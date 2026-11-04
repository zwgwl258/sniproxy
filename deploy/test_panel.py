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

        def request(form=None, auth=True, follow=True):
            # Trust only the ephemeral test certificate.
            tls = ssl.create_default_context(cafile=str(root / "cert"))
            conn = http.client.HTTPSConnection("localhost", server.server_port,
                                               context=tls, timeout=5)
            try:
                headers = {"Authorization": server.authorization.decode()} if auth else {}
                conn.request("GET" if form is None else "POST", "/",
                             urlencode(form) if form is not None else None, headers)
                response = conn.getresponse()
                body = response.read().decode()
                if form is not None and follow:
                    assert response.status == 303
                    location = response.getheader("Location")
                    conn.request("GET", location, headers=headers)
                    response = conn.getresponse()
                    body = response.read().decode()
                    conn.request("GET", location, headers=headers)
                    refreshed = conn.getresponse()
                    assert refreshed.status == 200
                    refreshed.read()
                return response.status, body
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
                assert "本次操作未执行" in request(form)[1] and config.read_bytes() == b"old"
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
                current = config.read_text()
                key = panel.rule_revision(current) + ":0"
                edit = {"action": "edit_rule", "nonce": panel.NONCE,
                        "rule": key, "value": "changed.example.com"}
                assert "已保存并应用" in request(edit)[1]
                assert b"changed[.]example[.]com$ *" in config.read_bytes()
                assert "配置已变化" in request(edit)[1]
                current = config.read_text()
                rules = list(panel.managed_rules(current))
                dns_index = next(i for i, rule in enumerate(rules) if rule[3] == "JP")
                edit.update(rule=f"{panel.rule_revision(current)}:{dns_index}",
                            value="JP", dns="8.8.8.8")
                assert "已保存并应用" in request(edit)[1]
                assert b"client JP\n    nameserver 8.8.8.8" in config.read_bytes()
                edit.update(action="delete_rule",
                            rule=f"{panel.rule_revision(config.read_text())}:{dns_index}")
                assert "已保存并应用" in request(edit)[1]
                assert b"client JP" not in config.read_bytes()
                original = config.read_text(encoding="utf-8")
                original = original.replace("table {\n", "table {\n    ^custom$ 127.0.0.1\n")
                config.write_text(original, encoding="utf-8")
                save = {"action": "save_domains", "nonce": panel.NONCE,
                        "revision": panel.rule_revision(original),
                        "domain": "nflximg.net\nadded.example.org"}
                response = request(save)[1]
                assert "已保存并应用" in response
                updated = config.read_text(encoding="utf-8")
                assert r".*nflximg\.net$ *" in updated
                assert "added[.]example[.]org$ *" in updated
                assert "changed[.]example[.]com$ *" not in updated
                assert "^custom$ 127.0.0.1" in updated and "client 192.0.2.0/24" in updated
                assert 'data-kind="domain"' not in response
                assert 'data-kind="dns"' in response
                assert "配置已变化" in request(save)[1]
                save.update(revision=panel.rule_revision(updated), domain="bad domain")
                assert "整批未保存" in request(save)[1] and config.read_text(encoding="utf-8") == updated
                special = r"^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$ *"
                bulk = [f"example{i}.com" for i in range(322)]
                bulk.insert(40, special)
                save.update(revision=panel.rule_revision(updated), domain="\n".join(bulk))
                response = request(save)[1]
                assert "已保存并应用" in response and special in response
                updated = config.read_text(encoding="utf-8")
                rules = [rule for kind, _, _, rule, _ in panel.managed_rules(updated) if kind == "domain"]
                assert len(rules) == 323 and rules[40] == special
                assert panel.replace_domains(updated, panel.rule_revision(updated),
                                             "\n".join(map(panel.domain_name, rules))) == updated
                assert "^custom$ 127.0.0.1" in updated and "client 192.0.2.0/24" in updated

                link = {"action": "adguard_url", "nonce": panel.NONCE,
                        "url": "https://dns.example.com:8443/"}
                page = request(link)[1]
                assert 'href="https://dns.example.com:8443/" target="_blank"' in page
                link["url"] = "javascript:alert(1)"
                assert "请填写有效" in request(link)[1]
                assert 'href="https://dns.example.com:8443/"' in request()[1]
                link["url"] = ""
                assert 'href="#adguard-url"' in request(link)[1]
                marker = root / "password-change-required"
                marker.touch()
                assert "首次登录：修改初始密码" in request()[1]
                assert "请先修改初始密码" in request(link)[1]
                password = {"action": "change_password", "nonce": panel.NONCE,
                            "current_password": "wrong", "new_password": "new-test-password",
                            "confirm_password": "new-test-password"}
                assert "当前密码不正确" in request(password)[1] and marker.exists()
                password["current_password"] = "test"
                assert request(password, follow=False)[0] == 303
                assert not marker.exists()
                assert (root / "panel-password").read_bytes() == b"new-test-password\n"
                assert "SNIProxy 管理" in request()[1]
        finally:
            server.shutdown()
            worker.join()
