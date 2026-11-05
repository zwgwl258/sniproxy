"""Runtime fallback-group circuit breaker; never restarts the production proxy."""
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import threading
import time

from panel import CONFIG, atomic_write, domain_blocks, domain_name

spec = importlib.util.spec_from_file_location("benchmark", Path(__file__).with_name("dns-benchmark.py"))
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)
RUNTIME = Path("/run/sniproxy-dns-runtime")
STATE = Path("/etc/sniproxy-managed/dns-runtime.json")
SOCKET = Path("/run/sniproxy-dns-health/events.sock")


def read_json(path, report=False):
    try:
        text = path.read_text(encoding="utf-8")
        return json.loads(text.rsplit("\n", 1)[1] if report else text)
    except (OSError, ValueError, IndexError):
        return {}


def route_text(groups, now):
    routes = "".join(f"{d} {g['preferred']} !\n" for key, g in groups.items()
                     if g.get("preferred") for d in key.split(","))
    return (routes + "\n" + json.dumps(dict(groups=groups, time=now))).encode()


def suspicious(stats):
    completed = stats["connected"] + stats["failed"]
    return ((completed >= 30 and stats["failed"] / completed >= .5) or
            stats["pending"] >= 100 or
            (stats["connected"] >= 30 and stats["reset"] / stats["connected"] >= .5))


def metrics(events):
    counts = {k: sum(e[1] == k for e in events)
              for k in ("started", "connected", "failed", "cancelled", "reset")}
    counts["pending"] = max(0, counts["started"] - counts["connected"] -
                            counts["failed"] - counts["cancelled"])
    passed = [e[2] for e in events if e[1] == "connected"]
    counts["connect_ms"] = round(sum(passed) / len(passed)) if passed else None
    counts["upstreams"] = sorted({e[3] for e in events if e[1] in ("failed", "reset")})[:8]
    return counts


class Policy:
    def __init__(self, probe=benchmark.measure):
        self.probe = probe

    def check(self, key, group, stats, failing, servers, now, allow_probe=True):
        """Two consecutive 15-second windows, then verify before switching."""
        group["live"] = stats
        group["checks"] = group.get("checks", 0) + 1 if suspicious(stats) else 0
        group.setdefault("cooldown", {})
        if group["checks"] < 2:
            group["status"] = "疑似故障，等待复核" if group["checks"] else "稳定保持（无流量不代表已验证健康）"
            return False
        if not allow_probe:
            group["status"] = "真实连接异常，等待限量复测"
            return False
        current = group["preferred"]
        members = key.split(",")
        # Check the hostnames actually failing, not just the group's homepage.
        targets = list(dict.fromkeys([*failing, members[0]]))[:3]
        candidates = list(dict.fromkeys([*group.get("standby", []), *servers]))
        candidates = [ip for ip in candidates if ip in servers and ip != current and
                      group["cooldown"].get(ip, 0) <= now][:3]
        if not candidates:
            group["status"] = "故障告警：没有可复测的备用，保留当前 DNS"
            return False
        # Repeat twice: one failed synthetic request is insufficient evidence.
        def verify(server):
            return [self.probe(server, targets) for _ in range(2)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = dict(zip([current, *candidates], pool.map(verify, [current, *candidates])))
        def passed(server):
            return all(all(ms is not None for ms in r["proxy"]) for r in results[server])
        if passed(current):
            group["status"] = "真实连接异常，但原线路复测通过；保留并告警"
            group["checks"] = 0
            return False
        healthy = [ip for ip in candidates if passed(ip)]
        group["last_probe"] = now
        if not healthy:
            group["status"] = "故障告警：备用未连续通过，保留当前 DNS"
            return False
        chosen = healthy[0]  # Keep the scheduled backup ranking, not one-shot speed.
        group["cooldown"][current] = now + 600
        group.update(preferred=chosen, checks=0, switched=now,
                     previous=current, status="整组故障切换，新连接生效，旧连接保持",
                     reason=f"{current} 真实连接异常且复测失败，备用 {chosen} 连续通过")
        return True


def main():
    SOCKET.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    SOCKET.unlink(missing_ok=True)
    events = deque(maxlen=200000)
    lock = threading.Lock()
    main_pid = [0]
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    sock.bind(str(SOCKET))
    os.chmod(SOCKET, 0o666)
    sock.settimeout(1)

    def receive():
        while True:
            try:
                data, ancillary, flags, _ = sock.recvmsg(512, socket.CMSG_SPACE(12))
                credentials = [struct.unpack("3i", value[:12])[0] for level, kind, value in ancillary
                               if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS]
                if flags or not main_pid[0] or credentials != [main_pid[0]]:
                    continue
                event, dns, ip, host, elapsed = data.decode("ascii").split()
                if event not in ("started", "connected", "failed", "cancelled", "reset"):
                    continue
                ipaddress.ip_address(dns)
                if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,253}", host):
                    continue
                with lock:
                    events.append((time.monotonic(), event, float(elapsed), ip, host.lower().rstrip("."), dns))
            except socket.timeout:
                continue
            except (ValueError, UnicodeError):
                continue

    threading.Thread(target=receive, daemon=True).start()
    groups = read_json(STATE).get("groups", {})
    policy = Policy()
    verifier = ThreadPoolExecutor(max_workers=1)
    pending = None
    attempts = {}
    while True:
        started = time.monotonic()
        now = time.time()
        try:
            pid = int(subprocess.check_output(["systemctl", "show", "-p", "MainPID", "--value",
                                               "sniproxy-managed.service"], timeout=3).strip())
            if pid != main_pid[0]:
                with lock:
                    events.clear()
                main_pid[0] = pid
            config = CONFIG.read_text(encoding="utf-8")
            domains, servers = benchmark.targets(config)
            blocks = domain_blocks(config)
            report = read_json(benchmark.REPORT, True)
            changed = False
            if pending is not None and pending[0].done():
                future, key, incumbent, original = pending
                result, switched = future.result()
                if original == config and groups.get(key, {}).get("preferred") == incumbent:
                    groups[key] = result
                    changed = switched
                pending = None
            valid = {}
            with lock:
                while events and events[0][0] < started - 60:
                    events.popleft()
                window = list(events)
            # Classify each sample once; do not scan the full traffic window
            # separately for every domain in every group.
            owners = {}
            for block in blocks:
                names = list(dict.fromkeys(domain_name(r).lower() for r in block
                                           if domain_name(r).lower() in domains))
                for name in names:
                    owners[name] = ",".join(names)
            group_events = {}
            for event in window:
                host = event[4]
                while host:
                    if host in owners:
                        group_events.setdefault(owners[host], []).append(event)
                        break
                    host = host.partition(".")[2]
            for block in blocks:
                members = list(dict.fromkeys(domain_name(r).lower() for r in block
                                             if domain_name(r).lower() in domains))
                key = ",".join(members)
                measured = report.get("groups", {}).get(key, {})
                if not key or not servers or (not measured and key not in groups):
                    continue
                group = groups.get(key, {}).copy()
                if group.get("preferred") not in servers:
                    group = dict(preferred=measured.get("preferred"), reason="首次采用综合测速结果")
                if group.get("preferred") not in servers:
                    continue
                group["standby"] = measured.get("standby", group.get("standby", []))
                selected = [e for e in group_events.get(key, []) if e[5] == group["preferred"]]
                failing = list(dict.fromkeys(e[4] for e in selected if e[1] in ("failed", "reset")))
                stats = metrics(selected)
                policy.check(key, group, stats, failing, servers, now, allow_probe=False)
                if (group["checks"] >= 2 and pending is None and
                        now - attempts.get(key, 0) >= 120):
                    attempts[key] = now
                    candidate = json.loads(json.dumps(group))
                    def verify(key=key, candidate=candidate, stats=stats, failing=failing, servers=servers, now=now):
                        switched = policy.check(key, candidate, stats, failing, servers, now)
                        return candidate, switched
                    pending = (verifier.submit(verify), key, group["preferred"], config)
                valid[key] = group
            # Never publish a decision for configuration edited during probes.
            if CONFIG.read_text(encoding="utf-8") == config:
                changed |= (set(valid) != set(groups) or any(
                    g.get("preferred") != groups.get(k, {}).get("preferred") for k, g in valid.items()))
                groups = valid
                atomic_write(RUNTIME, route_text(groups, time.time()), mode=0o644)
                if changed:
                    atomic_write(STATE, json.dumps(dict(groups=groups)).encode(), mode=0o600)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            print(f"DNS health monitor: {error}", flush=True)
        time.sleep(max(1, 15 - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
