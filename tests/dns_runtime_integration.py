"""Linux native telemetry, live route reload, and existing-connection survival."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

from client_dns_integration import serve_dns, request


class KeepAlive(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = self.server.server_address[0].encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main(binary):
    runtime = Path("/run/sniproxy-dns-runtime")
    assert not runtime.exists(), "Refusing to overwrite an existing runtime policy"
    first = ThreadingHTTPServer(("127.0.0.10", 0), KeepAlive)
    port = first.server_port
    second = ThreadingHTTPServer(("127.0.0.11", port), KeepAlive)
    for backend in (first, second):
        threading.Thread(target=backend.serve_forever, daemon=True).start()
    for dns_ip, answer in (("127.0.0.60", "127.0.0.10"),
                           ("127.0.0.61", "127.0.0.11"),
                           ("127.0.0.62", "127.0.0.12")):
        dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns.bind((dns_ip, 53))
        threading.Thread(target=serve_dns, args=(dns, answer), daemon=True).start()
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "proxy.conf"
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            listen = s.getsockname()[1]
        config.write_text(f"""user root
resolver {{
    mode ipv4_only
}}
resolver {{
    client fallback
    nameserver 127.0.0.60
    nameserver 127.0.0.61
    nameserver 127.0.0.62
    mode ipv4_only
}}
listener 127.0.0.1:{listen} {{
    proto http
}}
table {{
    .*route[.]test$ *:{port}
}}
""")
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as telemetry:
            path = str(Path(tmp) / "events.sock")
            telemetry.bind(path)
            telemetry.settimeout(3)
            env = dict(os.environ, SNIPROXY_HEALTH_SOCKET=path)
            with subprocess.Popen([str(Path(binary).resolve()), "-f", "-c", str(config)], env=env) as proc:
                try:
                    runtime.write_text("route.test 127.0.0.60 !\n\n{}")
                    for _ in range(40):
                        try:
                            keep = socket.create_connection(("127.0.0.1", listen), .2)
                            break
                        except OSError:
                            time.sleep(.05)
                    else:
                        raise AssertionError("Proxy did not listen")
                    keep.settimeout(3)
                    stream = keep.makefile("rb")
                    def persistent_request():
                        keep.sendall(b"GET / HTTP/1.1\r\nHost: route.test\r\n\r\n")
                        assert stream.readline().startswith(b"HTTP/1.1 200")
                        length = 0
                        while True:
                            line = stream.readline()
                            if line == b"\r\n":
                                break
                            if line.lower().startswith(b"content-length:"):
                                length = int(line.split(b":")[1])
                        return stream.read(length).decode()
                    assert persistent_request() == "127.0.0.10"
                    assert b"started 127.0.0.60" in telemetry.recv(512)
                    assert b"connected 127.0.0.60" in telemetry.recv(512)
                    runtime.write_text("route.test 127.0.0.62 !\n\n{}")
                    time.sleep(1.1)
                    request(listen, "127.0.0.1")
                    messages = [telemetry.recv(512), telemetry.recv(512)]
                    assert any(b"failed 127.0.0.62" in m for m in messages), messages
                    runtime.write_text("route.test 127.0.0.61 !\n\n{}")
                    time.sleep(1.1)
                    assert request(listen, "127.0.0.1") == "127.0.0.11"
                    assert persistent_request() == "127.0.0.10", "Existing connection was interrupted"
                    assert proc.poll() is None, "Production PID changed or exited"
                    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
                    from panel import client_connections
                    counts, listening = client_connections(subprocess.check_output(
                        ["ss", "-H", "-ntap"], text=True), proc.pid)
                    assert listening and counts.get("127.0.0.1", 0) >= 1, counts
                    assert "127.0.0.10" not in counts and "127.0.0.11" not in counts, counts
                    print("PASS: client monitor counts real incoming sockets, excluding upstreams")
                    # Exercise the authenticated receiver and automatic policy
                    # publisher. Synthetic active-probe results are controlled;
                    # real HTTPS probing is covered by dns_benchmark_integration.
                    telemetry.close()
                    policy_config = Path(tmp) / "policy.conf"
                    policy_config.write_text(config.read_text().replace(f"*:{port}", "*"))
                    measured = Path(tmp) / "report"
                    measured.write_text("\n" + json.dumps(dict(groups={"route.test": dict(
                        preferred="127.0.0.62", standby=["127.0.0.61", "127.0.0.60"])})))
                    state = Path(tmp) / "state.json"
                    health_path = Path(__file__).resolve().parents[1] / "deploy/dns-health.py"
                    harness = """
import importlib.util, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]).parent))
s = importlib.util.spec_from_file_location('health', sys.argv[1])
h = importlib.util.module_from_spec(s); s.loader.exec_module(h)
h.CONFIG = Path(sys.argv[2]); h.benchmark.REPORT = Path(sys.argv[3])
h.STATE = Path(sys.argv[4]); h.SOCKET = Path(sys.argv[5])
h.subprocess.check_output = lambda *a, **kw: sys.argv[6].encode()
h.Policy.__init__.__defaults__ = (lambda server, domains: {'proxy': [1 if server == '127.0.0.61' else None for d in domains]},)
h.main()
"""
                    with subprocess.Popen([sys.executable, "-c", harness, str(health_path),
                                           str(policy_config), str(measured), str(state), path, str(proc.pid)]) as monitor:
                        try:
                            deadline = time.monotonic() + 8
                            while time.monotonic() < deadline:
                                if runtime.exists() and "127.0.0.62 !" in runtime.read_text():
                                    break
                                time.sleep(.1)
                            else:
                                raise AssertionError("Monitor did not publish initial policy")
                            time.sleep(1.1)
                            for _ in range(40):
                                request(listen, "127.0.0.1")
                            deadline = time.monotonic() + 55
                            while time.monotonic() < deadline:
                                if state.exists() and '"preferred": "127.0.0.61"' in state.read_text():
                                    break
                                assert monitor.poll() is None, "Monitor exited"
                                time.sleep(.5)
                            else:
                                raise AssertionError("Runtime monitor did not automatically switch the failing group")
                            time.sleep(1.1)
                            assert request(listen, "127.0.0.1") == "127.0.0.11"
                            assert persistent_request() == "127.0.0.10"
                            assert proc.poll() is None
                            print("PASS: authenticated live events trigger automatic whole-group policy publication")
                        finally:
                            monitor.terminate()
                            monitor.wait(timeout=5)
                    stream.close()
                    keep.close()
                    print("PASS: native TCP failure telemetry; live DNS switch; same PID; existing connection survives")
                finally:
                    runtime.unlink(missing_ok=True)
                    proc.terminate()
                    proc.wait(timeout=5)


if __name__ == "__main__":
    main(sys.argv[1])
