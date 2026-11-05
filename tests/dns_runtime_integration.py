"""Linux native telemetry, live route reload, and existing-connection survival."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
                    stream.close()
                    keep.close()
                    print("PASS: native TCP failure telemetry; live DNS switch; same PID; existing connection survives")
                finally:
                    runtime.unlink(missing_ok=True)
                    proc.terminate()
                    proc.wait(timeout=5)


if __name__ == "__main__":
    main(sys.argv[1])
