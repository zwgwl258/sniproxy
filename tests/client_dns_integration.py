"""End-to-end split DNS test (Linux; UDP/53 on two loopback IPs)."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
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
            response = packet[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0)
            response += packet[12:12 + len(question)]
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

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
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
listener 127.0.0.1:{port} {{
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

            cases = [("127.0.0.2", "127.0.0.11"),
                     ("127.0.0.3", "127.0.0.10"),
                     ("127.0.0.9", "127.0.0.10")] * 4
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
