"""Exercise the live HTTPS handler and the configuration transaction."""
import base64
import http.client
from pathlib import Path
import ssl
import subprocess
import tempfile
from threading import Thread
from unittest.mock import patch
from urllib.parse import urlencode

import panel


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    config = root / "test.conf"
    backup = root / "previous"
    config.write_bytes(b"old")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "1", "-subj", "/CN=localhost", "-keyout", str(root / "key"),
                    "-out", str(root / "cert")], check=True, capture_output=True)
    with panel.Server(("127.0.0.1", 0), panel.Panel) as server:
        server.authorization = b"Basic " + base64.b64encode(b"admin:test")
        server.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.tls.load_cert_chain(root / "cert", root / "key")
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()

        def request(form=None, auth=True):
            # Trust only the ephemeral test certificate.
            tls = ssl.create_default_context(cafile=str(root / "cert"))
            conn = http.client.HTTPSConnection("localhost", server.server_port,
                                               context=tls, timeout=5)
            try:
                headers = {"Authorization": server.authorization.decode()} if auth else {}
                conn.request("GET" if form is None else "POST", "/",
                             urlencode(form) if form is not None else None, headers)
                response = conn.getresponse()
                return response.status, response.read().decode()
            finally:
                conn.close()

        try:
            ok = subprocess.CompletedProcess([], 0, "", "")
            bad = subprocess.CompletedProcess([], 1, "", "bad config")
            with patch.multiple(panel, ROOT=root, CONFIG=config, BACKUP=backup), \
                 patch.object(panel, "command", return_value=ok) as command, \
                 patch.object(panel, "restart", return_value=True) as restart:
                assert request(auth=False)[0] == 401
                assert "old" in request()[1]
                form = {"action": "apply", "nonce": "wrong", "config": "new"}
                assert request(form)[0] == 403 and config.read_bytes() == b"old"
                form["nonce"] = panel.NONCE
                command.return_value = bad
                assert "校验失败" in request(form)[1] and config.read_bytes() == b"old"
                command.return_value = ok
                assert "已保存并应用" in request(form)[1]
                assert config.read_bytes() == b"new" and backup.read_bytes() == b"old"
                restart.side_effect = [False, True]
                form["config"] = "fails-to-start"
                assert "已恢复原配置" in request(form)[1]
                assert config.read_bytes() == b"new"
                restart.side_effect = None
                assert "已回滚" in request({"action": "rollback", "nonce": panel.NONCE})[1]
                assert config.read_bytes() == b"old"

                assert 'name="domain"' in request()[1] and 'name="dns"' in request()[1]
                domain = {"action": "domain", "nonce": panel.NONCE, "domain": "Netflix.ca"}
                assert "已保存并应用" in request(domain)[1]
                assert b"^(.*[.])?netflix[.]ca$ *" in config.read_bytes()
                assert "已存在" in request(domain)[1]
                domain["domain"] = "www.example.com"
                assert "已保存并应用" in request(domain)[1]
                assert config.read_bytes().count(b"table {") == 1
                domain["domain"] = "new.example.com\ninvalid line"
                before = config.read_bytes()
                assert "第 2 行" in request(domain)[1] and config.read_bytes() == before
                domain["domain"] = "new.example.com\n\n.*nflximg\\.net$ *\n.*nflximg\\.net$ *"
                domain_response = request(domain)[1]
                assert "已保存并应用" in domain_response
                assert config.read_bytes().count(br".*nflximg\.net$ *") == 1
                assert b"new[.]example[.]com$ *" in config.read_bytes()
                dns = {"action": "client_dns", "nonce": panel.NONCE,
                       "client": "192.0.2.3/24", "dns": "1.1.1.1"}
                assert "请输入两字母国家/地区代码" in request(dns)[1]
                dns.update(client="192.0.2.0/24", dns="1.1.1.1, 9.9.9.9")
                assert "已保存并应用" in request(dns)[1]
                assert b"client 192.0.2.0/24" in config.read_bytes()
                assert b"nameserver 9.9.9.9" in config.read_bytes()
                page = domain_response
                assert '<select id="country-options"' in page
                assert 'id="country-search"' in page
                assert panel.COUNTRY_SCRIPT in page
                assert '<option value="JP">JP · 日本 · Japan</option>' in page
                dns.update(client="jp", dns="1.1.1.1")
                assert "请先安装国家数据库" in request(dns)[1]
                (root / "country.mmdb").touch()
                assert "已保存并应用" in request(dns)[1]
                assert b"client JP" in config.read_bytes()
        finally:
            server.shutdown()
            worker.join()
