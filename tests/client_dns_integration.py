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


def serve_dns(sock, answer, delay=0, requests=None):
    with sock:
        while True:
            try:
                packet, peer = sock.recvfrom(4096)
            except OSError:
                return
            route = b"\x05route\x04test\x00\x00\x01\x00\x01"
            health = b"\x07example\x03com\x00\x00\x01\x00\x01"
            question = next((q for q in (route, health) if packet[12:12 + len(q)].lower() == q), None)
            if question is None:
                continue
            if requests is not None and question == route:
                requests.append(question)
            if delay:
                time.sleep(delay)
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

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

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
        threading.Thread(target=serve_dns, args=(dns, backend.server_address[0], 0.03 if dns_ip.endswith(".60") else 0),
                         daemon=True).start()

    failed_dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    failed_dns.bind(("127.0.0.62", 53))
    failed_requests = []
    threading.Thread(target=serve_dns, args=(failed_dns, None, 0, failed_requests), daemon=True).start()

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
    nameserver 127.0.0.60
    nameserver 127.0.0.63
    nameserver 127.0.0.64
    nameserver 127.0.0.65
    nameserver 127.0.0.66
    nameserver 127.0.0.67
    nameserver 127.0.0.61
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

            time.sleep(0.5)  # Allow startup health probes to finish.
            cases *= 4
            with ThreadPoolExecutor(max_workers=6) as pool:
                actual = list(pool.map(lambda case: request(port, case[0]), cases))
            expected = [case[1] for case in cases]
            if actual != expected:
                raise AssertionError(f"Expected {expected}, got {actual}")
            assert not failed_requests, "Unhealthy client DNS received a live query"
            if os.environ.get("SNIPROXY_TEST_BENCHMARK_SWITCH"):
                status = Path("/run/sniproxy-dns-benchmark")
                with status.open("x", encoding="ascii") as out:
                    out.write("route.test 127.0.0.60 !\n\n{}")
                try:
                    time.sleep(1.1)
                    assert request(port, "127.0.0.9") == "127.0.0.10"
                    assert proxy.poll() is None
                finally:
                    status.unlink()
                time.sleep(1.1)
                assert request(port, "127.0.0.9") == "127.0.0.11"
            print("Client DNS routing passed")
        finally:
            proxy.terminate()
            proxy.wait(timeout=5)


if __name__ == "__main__":
    main(sys.argv[1])
