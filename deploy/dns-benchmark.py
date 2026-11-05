"""Measure fallback resolvers through a separate loopback-only SNIProxy."""
import ipaddress
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import socket
from statistics import median
import subprocess
import tempfile
import time

from panel import CONFIG, atomic_write, domain_blocks, domain_name, managed_rules

REPORT = Path("/run/sniproxy-dns-benchmark")
BINARY = "/usr/local/lib/sniproxy-managed/sniproxy"


def targets(config):
    rules = list(managed_rules(config))
    domains = []
    for kind, _, _, rule, _ in rules:
        if kind != "domain":
            continue
        domain = domain_name(rule).lower()
        if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", domain) and domain not in domains:
            domains.append(domain)
    fallback = next((servers for kind, _, _, source, servers in reversed(rules)
                     if kind == "dns" and source == "fallback"), "")
    return domains, list(dict.fromkeys(str(ipaddress.ip_address(ip))
                                      for ip in fallback.split(", ") if ip))


def command(*args, timeout=5):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def dns_ms(server, domain):
    started = time.monotonic()
    answer = command("dig", "-r", "@" + server, domain + ".", "A", "+short",
                     "+time=2", "+tries=1", timeout=3)
    for line in answer.splitlines():
        try:
            ipaddress.IPv4Address(line)
        except ValueError:
            continue
        return round((time.monotonic() - started) * 1000)
    return None


def proxy_probe(port, domain):
    result = command("curl", "-q", "--noproxy", "*", "--http1.1", "--head",
                     "--silent", "--output", "/dev/null", "--connect-timeout", "3",
                     "--max-time", "4", "--connect-to", f"{domain}:443:127.0.0.1:{port}",
                     "--write-out", "%{http_code} %{time_starttransfer}",
                     f"https://{domain}/")
    try:
        status, elapsed = result.split()
        if 200 <= int(status) < 400:
            return round(float(elapsed) * 1000), int(status)
        return None, int(status)
    except ValueError:
        pass
    return None, 0


def proxy_ms(port, domain):
    return proxy_probe(port, domain)[0]


def measure(server, domains):
    dns, proxy, status = [], [], []
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "probe.conf"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        table = "".join("    ^" + domain.replace(".", "[.]") + "$ *:443\n" for domain in domains)
        config.write_text(f"resolver {{\n    nameserver {server}\n    mode ipv4_only\n}}\n"
                          f"listener 127.0.0.1:{port} {{\n    proto tls\n}}\n"
                          f"table {{\n{table}}}\n", encoding="ascii")
        with subprocess.Popen([BINARY, "-f", "-c", str(config)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as proc:
            try:
                for _ in range(30):
                    if proc.poll() is not None:
                        break
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.05)
                def probe(domain):
                    latency = dns_ms(server, domain)
                    # An unanswered DNS lookup cannot produce a useful proxy test.
                    elapsed, code = proxy_probe(port, domain) if latency is not None and proc.poll() is None else (None, 0)
                    return latency, elapsed, code
                # One proxy process per DNS, with a bounded global request budget.
                with ThreadPoolExecutor(max_workers=4) as pool:
                    for latency, elapsed, code in pool.map(probe, domains):
                        dns.append(latency)
                        proxy.append(elapsed)
                        status.append(code)
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        proc.kill()
    return {"dns": dns, "proxy": proxy, "status": status}


def summarize(rounds, servers):
    def metric(samples):
        valid = [ms for ms in samples if ms is not None]
        return len(valid), len(samples), median(valid) if valid else None
    return {ip: {kind: metric([ms for run in rounds for ms in run[ip][kind]])
                 for kind in ("dns", "proxy")} for ip in servers}


def select(scores, current, pending, latest):
    # Scheduled ranking must not replace a configured incumbent. Runtime
    # failover is a separate decision, not evidence from one synthetic round.
    if current in scores:
        return current, ""
    eligible = [ip for ip in scores if any(ms is not None for ms in latest[ip]["proxy"])]
    if not eligible:
        return "", ""
    def rank(ip):
        p, _, elapsed = scores[ip]["proxy"]
        d, _, dns = scores[ip]["dns"]
        return -p, elapsed // 25, -d, dns if dns is not None else float("inf"), elapsed
    best = min(eligible, key=rank)
    return best, ""


def standby_order(scores, latest, preferred):
    remaining = {ip: value for ip, value in scores.items() if ip != preferred}
    ordered = []
    while remaining:
        best, _ = select(remaining, None, None, latest)
        if not best:
            break
        ordered.append(best)
        del remaining[best]
    return ordered


def main():
    started = time.monotonic()
    config = CONFIG.read_text(encoding="utf-8")
    domains, servers = targets(config)
    try:
        old = json.loads(REPORT.read_text(encoding="utf-8").rsplit("\n", 1)[1])
    except (OSError, ValueError, IndexError):
        old = {}
    if old.get("domains") != domains or old.get("servers") != servers or time.time() - old.get("time", 0) > 4500:
        # Expire measurements, not the incumbent: a slow/interrupted round must
        # not turn the next scheduled test into a fresh election.
        for section in ("by_domain", "groups"):
            for prior in old.get(section, {}).values():
                prior["rounds"] = []
    by_domain = {}
    groups = {}
    strict = set()
    if domains and servers:
        jobs = servers
        latest = {domain: {} for domain in domains}
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = pool.map(lambda ip: measure(ip, domains), jobs)
            for ip, result in zip(jobs, results):
                for i, domain in enumerate(domains):
                    latest[domain][ip] = {kind: [result[kind][i]] for kind in ("dns", "proxy", "status")}
        for domain, sample in latest.items():
            prior = old.get("by_domain", {}).get(domain, {})
            rounds = [*prior.get("rounds", [])[-2:], sample]
            scores = summarize(rounds, servers)
            preferred, pending = select(scores, prior.get("preferred"), prior.get("pending"), sample)
            by_domain[domain] = dict(rounds=rounds, scores=scores, preferred=preferred, pending=pending)
        blocks = domain_blocks(config)
        if len(blocks) > 1:
            for block in blocks:
                members = list(dict.fromkeys(domain_name(rule).lower() for rule in block
                                             if domain_name(rule).lower() in latest))
                if not members:
                    continue
                key = ",".join(members)
                sample = {ip: {kind: [latest[domain][ip][kind][0] for domain in members]
                               for kind in ("dns", "proxy")} for ip in servers}
                prior = old.get("groups", {}).get(key, {})
                rounds = [*prior.get("rounds", [])[-2:], sample]
                scores = summarize(rounds, servers)
                # The first testable member is the group's key hostname.
                key_passed = {ip for ip in servers if sample[ip]["proxy"][0] is not None}
                eligible = {ip: score for ip, score in scores.items()
                            if not key_passed or ip in key_passed}
                incumbent = prior.get("preferred")
                preferred, pending = ((incumbent, "") if incumbent in servers else
                                      select(eligible, None, None, sample))
                reason = ("关键域名通过，按覆盖率选优" if key_passed else "关键域名未通过，按覆盖率选优")
                if not preferred:
                    preferred = prior.get("preferred") or servers[0]
                    reason = "无 HTTPS 成功，保留原首选" if prior.get("preferred") else "无 HTTPS 成功，使用列表首台"
                elif incumbent == preferred:
                    reason = "稳定优先：定时测速保留当前 DNS，不自动追快切换"
                selected = sample[preferred]
                diagnostics = dict(
                    dns_failed=sum(ms is None for ms in selected["dns"]),
                    transport_failed=sum(latest[d][preferred]["status"][0] == 0 and
                                         latest[d][preferred]["dns"][0] is not None for d in members),
                    http_failed=sum(latest[d][preferred]["status"][0] >= 400 for d in members))
                groups[key] = dict(rounds=rounds, preferred=preferred, pending=pending, reason=reason,
                                   coverage=sum(ms is not None for ms in selected["proxy"]),
                                   diagnostics=diagnostics,
                                   standby=standby_order(scores, sample, preferred))
                for domain in members:
                    by_domain[domain]["preferred"] = preferred
                    by_domain[domain]["group"] = members[0]
                    strict.add(domain)
    if CONFIG.read_text(encoding="utf-8") != config:
        return
    # Runtime failover owns the active route. A long-running benchmark must
    # not undo a switch that happened while it was measuring candidates.
    try:
        runtime = json.loads(Path("/run/sniproxy-dns-runtime").read_text().rsplit("\n", 1)[1])
    except (OSError, ValueError, IndexError):
        runtime = {}
    if time.time() - runtime.get("time", 0) <= 45:
        for key, data in runtime.get("groups", {}).items():
            if key in groups and data.get("preferred") in servers:
                groups[key]["preferred"] = data["preferred"]
                groups[key]["reason"] = "稳定优先：沿用实时监测当前 DNS"
                for domain in key.split(","):
                    by_domain[domain]["preferred"] = data["preferred"]
    report = dict(domains=domains, servers=servers, by_domain=by_domain, groups=groups,
                  time=time.time(), duration_seconds=round(time.monotonic() - started, 1))
    routes = "".join(f"{domain} {data['preferred']}{' !' if domain in strict else ''}\n" for domain, data in by_domain.items()
                     if data["preferred"])
    atomic_write(REPORT, (routes + "\n" + json.dumps(report)).encode("utf-8"), mode=0o644)


if __name__ == "__main__":
    main()
