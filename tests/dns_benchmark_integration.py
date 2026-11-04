"""Real TLS requests through a temporary proxy with two isolated DNS servers."""
import os
from http.server import ThreadingHTTPServer
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

from client_dns_integration import Handler, serve_dns
from test_dns_benchmark import benchmark


def main(binary):
    benchmark.BINARY = str(Path(binary).resolve())
    with tempfile.TemporaryDirectory() as tmp:
        cert, key = Path(tmp) / "cert.pem", Path(tmp) / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=route.test", "-addext", "subjectAltName=DNS:route.test",
                        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
        os.environ["CURL_CA_BUNDLE"] = str(cert)
        with ThreadingHTTPServer(("127.0.0.10", 443), Handler) as upstream:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            upstream.socket = context.wrap_socket(upstream.socket, server_side=True)
            threading.Thread(target=upstream.serve_forever, daemon=True).start()
            for server, answer in (("127.0.0.60", "127.0.0.10"), ("127.0.0.61", "127.0.0.11")):
                dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                dns.bind((server, 53))
                threading.Thread(target=serve_dns, args=(dns, answer), daemon=True).start()
            good = benchmark.measure("127.0.0.60", ["route.test"])
            bad = benchmark.measure("127.0.0.61", ["route.test"])
            assert good["dns"][0] is not None and good["proxy"][0] is not None, good
            assert bad["dns"][0] is not None and bad["proxy"][0] is None, bad
            print("Both DNS servers resolve, but only the reachable upstream passes proxy HTTPS")


if __name__ == "__main__":
    main(sys.argv[1])
