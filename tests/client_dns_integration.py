"""End-to-end split DNS test (Linux; UDP/53 on two loopback IPs)."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def serve_dns(sock, answer):
    with sock:
        while True:
            try:
                packet, peer = sock.recvfrom(4096)
            except OSError:
                return
            # The test sends one ordinary A question for route.test.
            question = b"\x05route\x04test\x00\x00\x01\x00\x01"
            if packet[12:12 + len(question)].lower() != question:
                continue
            response = packet[:2] + struct.pack("!5H", 0x8180 if answer else 0x8183, 1, int(bool(answer)), 0, 0)
            response += packet[12:12 + len(question)]
            if answer is None:
                sock.sendto(response, peer)
                continue
            response += struct.pack("!3HIH", 0xC00C, 1, 1, 0, 4)
            sock.sendto(response + socket.inet_aton(answer), peer)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.server.server_address[0].encode())

    def log_message(self, *_):
        pass


def request(port, source):
    with socket.create_connection(("127.0.0.1", port), 4, (source, 0)) as sock:
        sock.sendall(b"GET / HTTP/1.0\r\nHost: route.test\r\n\r\n")
        with sock.makefile("rb") as response:
            return response.read().split(b"\r\n\r\n", 1)[-1].decode()


def main(binary):
    first = ThreadingHTTPServer(("127.0.0.10", 0), Handler)
    backend_port = first.server_port
    second = ThreadingHTTPServer(("127.0.0.11", backend_port), Handler)
    for backend, dns_ip in ((first, "127.0.0.60"), (second, "127.0.0.61")):
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns.bind((dns_ip, 53))
        threading.Thread(target=serve_dns, args=(dns, backend.server_address[0]),
                         daemon=True).start()

    failed_dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    failed_dns.bind(("127.0.0.62", 53))
    threading.Thread(target=serve_dns, args=(failed_dns, None), daemon=True).start()

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    country = ""
    cases = [("127.0.0.2", "127.0.0.11"),
             ("127.0.0.3", "127.0.0.10"),
             ("127.0.0.9", "127.0.0.11"), ("127.0.0.12", "127.0.0.11")]
    if os.environ.get("SNIPROXY_COUNTRY_DB"):
        country = """resolver {
    client GB
    nameserver 127.0.0.61
    mode ipv4_only
}
resolver {
    client 81.2.69.161
    nameserver 127.0.0.60
    mode ipv4_only
}
"""
        cases += [("81.2.69.160", "127.0.0.11"), ("81.2.69.161", "127.0.0.10")]
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "sniproxy.conf"
        config.write_text(f"""resolver {{
    nameserver 127.0.0.60
    mode ipv4_only
}}
resolver {{
    client 127.0.0.2
    nameserver 127.0.0.61
    mode ipv4_only
}}
resolver {{
    client 127.0.0.0/29
    nameserver 127.0.0.60
    mode ipv4_only
}}
resolver {{
    client 127.0.0.12
    nameserver 127.0.0.62
    mode ipv4_only
}}
resolver {{
    client fallback
    nameserver 127.0.0.61
    nameserver 127.0.0.60
    mode ipv4_only
}}
{country}listener 127.0.0.1:{port} {{
    proto http
}}
table {{
    ^route[.]test$ *:{backend_port}
}}
""", encoding="ascii")
        proxy = subprocess.Popen([binary, "-f", "-c", str(config)])
        try:
            for _ in range(100):
                if proxy.poll() is not None:
                    raise RuntimeError(f"SNIProxy exited: {proxy.returncode}")
                try:
                    with socket.create_connection(("127.0.0.1", port), 0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("SNIProxy did not start listening")

            cases *= 4
            with ThreadPoolExecutor(max_workers=6) as pool:
                actual = list(pool.map(lambda case: request(port, case[0]), cases))
            expected = [case[1] for case in cases]
            if actual != expected:
                raise AssertionError(f"Expected {expected}, got {actual}")
            print("Client DNS routing passed")
        finally:
            proxy.terminate()
            proxy.wait(timeout=5)


if __name__ == "__main__":
    main(sys.argv[1])
