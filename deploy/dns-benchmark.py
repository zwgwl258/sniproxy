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


def proxy_ms(port, domain):
    result = command("curl", "-q", "--noproxy", "*", "--http1.1", "--head",
                     "--silent", "--output", "/dev/null", "--connect-timeout", "3",
                     "--max-time", "4", "--connect-to", f"{domain}:443:127.0.0.1:{port}",
                     "--write-out", "%{http_code} %{time_starttransfer}",
                     f"https://{domain}/")
    try:
        status, elapsed = result.split()
        if 200 <= int(status) < 400:
            return round(float(elapsed) * 1000)
    except ValueError:
        pass
    return None


def measure(server, domains):
    dns, proxy = [], []
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
                for domain in domains:
                    dns.append(dns_ms(server, domain))
                    proxy.append(proxy_ms(port, domain) if proc.poll() is None else None)
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        proc.kill()
    return {"dns": dns, "proxy": proxy}


def summarize(rounds, servers):
    def metric(samples):
        valid = [ms for ms in samples if ms is not None]
        return len(valid), len(samples), median(valid) if valid else None
    return {ip: {kind: metric([ms for run in rounds for ms in run[ip][kind]])
                 for kind in ("dns", "proxy")} for ip in servers}


def select(scores, current, pending, latest):
    eligible = [ip for ip in scores if any(ms is not None for ms in latest[ip]["proxy"])]
    if not eligible:
        return "", ""
    def rank(ip):
        p, _, elapsed = scores[ip]["proxy"]
        d, _, dns = scores[ip]["dns"]
        return -p, elapsed // 25, -d, dns if dns is not None else float("inf"), elapsed
    best = min(eligible, key=rank)
    if current not in eligible or best == current or best == pending:
        return best, ""
    return current, best


def main():
    config = CONFIG.read_text(encoding="utf-8")
    domains, servers = targets(config)
    try:
        old = json.loads(REPORT.read_text(encoding="utf-8").rsplit("\n", 1)[1])
    except (OSError, ValueError, IndexError):
        old = {}
    if old.get("domains") != domains or old.get("servers") != servers or time.time() - old.get("time", 0) > 4500:
        old = {}
    by_domain = {}
    groups = {}
    strict = set()
    if domains and servers:
        jobs = [(ip, offset) for ip in servers for offset in range(0, len(domains), 16)]
        latest = {domain: {} for domain in domains}
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = pool.map(lambda job: measure(job[0], domains[job[1]:job[1] + 16]), jobs)
            for (ip, offset), result in zip(jobs, results):
                for i, domain in enumerate(domains[offset:offset + 16]):
                    latest[domain][ip] = {kind: [result[kind][i]] for kind in ("dns", "proxy")}
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
                eligible = {ip: score for ip, score in scores.items()
                            if all(ms is not None for ms in sample[ip]["proxy"])}
                preferred, pending = select(eligible, prior.get("preferred"), prior.get("pending"), sample)
                preferred = preferred or prior.get("preferred") or servers[0]
                groups[key] = dict(rounds=rounds, preferred=preferred, pending=pending)
                for domain in members:
                    by_domain[domain]["preferred"] = preferred
                    by_domain[domain]["group"] = members[0]
                    strict.add(domain)
    if CONFIG.read_text(encoding="utf-8") != config:
        return
    report = dict(domains=domains, servers=servers, by_domain=by_domain, groups=groups, time=time.time())
    routes = "".join(f"{domain} {data['preferred']}{' !' if domain in strict else ''}\n" for domain, data in by_domain.items()
                     if data["preferred"])
    atomic_write(REPORT, (routes + "\n" + json.dumps(report)).encode("utf-8"), mode=0o644)


if __name__ == "__main__":
    main()
