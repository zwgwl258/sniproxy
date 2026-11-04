"""HTTPS administration for the packaged SNIProxy service."""
import base64
import hmac
import html
import ipaddress
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import time
from urllib.parse import parse_qs

ROOT = Path("/etc/sniproxy-managed")
CONFIG = ROOT / "sniproxy.conf"
BACKUP = ROOT / "sniproxy.conf.previous"
SERVICE = "sniproxy-managed.service"
CHECKER = "/usr/local/lib/sniproxy-managed/config-test"
MAX_BODY = 1024 * 1024
NONCE = secrets.token_urlsafe(32)


def command(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=20)


def atomic_write(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temp:
        tmp = Path(temp.name)
        try:
            temp.write(data)
            temp.flush()
            os.fsync(temp.fileno())
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)


def active():
    return command("systemctl", "is-active", SERVICE).returncode == 0


def restart():
    result = command("systemctl", "restart", SERVICE)
    if result.returncode:
        return False
    time.sleep(1)
    return active()


def apply(data, rollback=False):
    with tempfile.NamedTemporaryFile(dir=ROOT) as candidate:
        candidate.write(data)
        candidate.flush()
        result = command(CHECKER, candidate.name)
    if result.returncode:
        return "配置未保存：校验失败。\n" + result.stderr[-4000:]
    old = CONFIG.read_bytes()
    was_active = active()
    atomic_write(CONFIG, data)
    try:
        if restart():
            if not rollback:
                atomic_write(BACKUP, old)
            return "配置已回滚并启动。" if rollback else "配置已保存并应用。"
    except (OSError, subprocess.TimeoutExpired):
        pass
    atomic_write(CONFIG, old)
    try:
        if was_active:
            if not restart():
                return "新配置启动失败，已恢复文件，但旧服务也未能启动。请查看日志。"
        elif command("systemctl", "stop", SERVICE).returncode:
            return "已恢复配置文件，但无法确认代理已停止。请查看日志。"
    except (OSError, subprocess.TimeoutExpired):
        return "已恢复配置文件，但无法恢复服务状态。请查看日志。"
    return "新配置启动失败，已恢复原配置。请查看日志。"


def add_domain(config, value):
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    existing = {" ".join(line.split()) for line in config.splitlines()}
    rules = []
    for number, line in enumerate(value.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        legacy = re.fullmatch(r"\.\*([a-zA-Z0-9-]+(?:\\\.[a-zA-Z0-9-]+)+)\$[ \t]+\*", line)
        domain = (legacy[1].replace(r"\.", ".") if legacy else line.rstrip(".")).lower()
        if len(domain) > 253 or not re.fullmatch(rf"{label}(?:\.{label})+", domain):
            raise ValueError(f"第 {number} 行格式无效；请填域名或 .*netflix\\.ca$ * 形式的规则。整批未保存。")
        entry = (".*" + legacy[1] + "$ *" if legacy else
                 "^(.*[.])?" + domain.replace(".", "[.]") + "$ *")
        if entry not in existing:
            existing.add(entry)
            rules.append("    " + entry + "\n")
    if not rules:
        raise ValueError("没有可添加的规则：输入为空或规则已存在。")
    rule = "".join(rules)
    tables = list(re.finditer(r"(?m)^[ \t]*table[ \t]*\{[^\S\n]*(?:#[^\n]*)?$\n", config))
    declarations = re.findall(r"(?m)^[ \t]*table(?:[ \t]+|(?=\{))", config)
    if not declarations:
        return config.rstrip() + "\n\ntable {\n" + rule + "}\n"
    if len(tables) != 1:
        raise ValueError("此配置没有唯一的标准默认转发表，请使用高级配置。")
    end = re.search(r"(?m)^[ \t]*\}[ \t]*(?:#[^\n]*)?$", config[tables[0].end():])
    if end is None:
        raise ValueError("找不到默认转发表结尾，请使用高级配置。")
    pos = tables[0].end() + end.start()
    if re.search(r"(?m)^[ \t]*(?:table|listener|listen|resolver)\b",
                 config[tables[0].end():pos]):
        raise ValueError("无法安全定位默认转发表，请使用高级配置。")
    return config[:pos] + rule + config[pos:]


def add_client_dns(config, client, dns):
    try:
        source = client.strip()
        if re.fullmatch(r"[A-Za-z]{2}", source):
            source = source.upper()
            if not (ROOT / "country.mmdb").is_file():
                raise ValueError("missing-country-db")
        else:
            source = str(ipaddress.ip_network(source, strict=True))
        servers = [ipaddress.ip_address(item) for item in re.split(r"[\s,]+", dns.strip()) if item]
        if not 1 <= len(servers) <= 6 or any("%" in str(server) for server in servers):
            raise ValueError
    except ValueError as error:
        if str(error) == "missing-country-db":
            raise ValueError("请先安装国家数据库 /etc/sniproxy-managed/country.mmdb。") from None
        raise ValueError("请输入两字母国家/地区代码、有效 IP 或网段，以及 1 至 6 个 DNS IP。") from None
    nameservers = "".join(f"    nameserver {server}\n" for server in servers)
    return (config.rstrip() + f"\n\nresolver {{\n    client {source}\n" +
            nameservers + "    mode ipv4_only\n}\n")


class Panel(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body="", **headers):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        for key, value in headers.items():
            self.send_header(key.replace("_", "-"), value)
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        supplied = self.headers.get("Authorization", "").encode()
        if not hmac.compare_digest(supplied, self.server.authorization):
            self.reply(401, "需要管理员账号和密码。",
                       WWW_Authenticate='Basic realm="SNIProxy", charset="UTF-8"')
            return False
        if self.path != "/":
            self.reply(404)
            return False
        return True

    def page(self, message="", domain_input=""):
        domain_input = html.escape(domain_input)
        config = html.escape(CONFIG.read_text(encoding="utf-8", errors="replace"))
        message = html.escape(message)
        status = "运行中" if active() else "未运行"
        self.reply(200, f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SNIProxy 管理</title><style>
body{{max-width:960px;margin:2rem auto;padding:0 1rem;font:16px system-ui}}
textarea{{width:100%;min-height:25rem;box-sizing:border-box;font:14px monospace}}
section,details{{border:1px solid #ccd5df;border-radius:.6rem;padding:1rem;margin:1rem 0}}
label{{display:block;margin:.55rem 0 .2rem}}
input{{width:100%;max-width:34rem;padding:.5rem;box-sizing:border-box}}
#domain{{display:block;min-height:16rem;resize:vertical;padding:.65rem;line-height:1.5;white-space:pre;overflow:auto}}
small{{display:block;margin:.25rem 0;color:#435264}}
button{{margin:.5rem .5rem .5rem 0;padding:.6rem}}pre{{white-space:pre-wrap}}
</style><h1>SNIProxy 管理</h1><p>代理状态：{status}</p><pre>{message}</pre>
<section><h2>域名转发</h2>
<form method="post" action="/">
<input type="hidden" name="nonce" value="{NONCE}">
<label for="domain">域名</label>
<textarea id="domain" name="domain" rows="12" wrap="off" placeholder="netflix.ca&#10;netflix.com" spellcheck="false" required>{domain_input}</textarea>
<small>每行一个域名或一条现有的 .*netflix\\.ca$ * 格式规则，可混合粘贴。空行和重复规则会跳过；任何一行无效则整批不保存。命名转发表请用高级配置。</small>
<button name="action" value="domain">添加并应用</button></form></section>
<section><h2>客户端 DNS 分流</h2>
<form method="post" action="/">
<input type="hidden" name="nonce" value="{NONCE}">
<label for="client">客户端来源国家／地区、IP 或网段</label>
<input id="client" name="client" placeholder="JP、US、HK，或 203.0.113.0/24" required>
<label for="dns">DNS 服务器 IP</label>
<input id="dns" name="dns" placeholder="154.83.83.86, 149.28.158.78" required>
<small>填写两字母国家／地区代码（如 JP）。按代理看到的 TCP 来源 IP 查询本地国家库。优先级：IP／网段 → 国家／地区 → 默认 DNS。</small>
<button name="action" value="client_dns">添加并应用</button></form></section>
<details><summary>高级配置：查看、编辑或删除规则</summary>
<form method="post" action="/">
<input type="hidden" name="nonce" value="{NONCE}">
<label for="config">代理配置（DNS 分组、监听端口、域名转发表）</label>
<textarea id="config" name="config" spellcheck="false">{config}</textarea>
<button name="action" value="apply">校验、保存并应用</button>
</form></details>
<form method="post" action="/">
<input type="hidden" name="nonce" value="{NONCE}">
<button name="action" value="restart">重启代理</button>
<button name="action" value="rollback">恢复上一版</button>
<button name="action" value="logs">查看最近日志</button>
</form></html>""")

    def do_GET(self):
        if self.authorized():
            self.page()

    def do_POST(self):
        if not self.authorized():
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= MAX_BODY:
                raise ValueError
            form = parse_qs(self.rfile.read(size).decode(), keep_blank_values=True,
                            max_num_fields=4, errors="strict")
        except (UnicodeError, ValueError):
            return self.reply(400)
        if not hmac.compare_digest(form.get("nonce", [""])[0].encode(), NONCE.encode()):
            return self.reply(403)
        action = form.get("action", [""])[0]
        try:
            if action == "apply":
                data = form["config"][0].replace("\r\n", "\n").encode()
                message = apply(data) if data.strip() else "配置不能为空。"
            elif action in ("domain", "client_dns"):
                config = CONFIG.read_text(encoding="utf-8")
                if action == "domain":
                    updated = add_domain(config, form["domain"][0])
                else:
                    updated = add_client_dns(config, form["client"][0], form["dns"][0])
                message = apply(updated.encode())
            elif action == "rollback":
                message = apply(BACKUP.read_bytes(), rollback=True) if BACKUP.exists() else "没有可恢复的配置。"
            elif action == "restart":
                message = "代理已重启。" if restart() else "重启失败，请查看日志。"
            elif action == "logs":
                result = command("journalctl", "-u", SERVICE, "-n", "60", "--no-pager")
                message = (result.stdout or result.stderr)[-16000:]
            else:
                return self.reply(400)
        except KeyError:
            return self.reply(400)
        except ValueError as error:
            message = str(error)
        except (OSError, subprocess.TimeoutExpired):
            message = "操作失败或超时，请检查代理状态和日志。"
        self.page(message, form.get("domain", [""])[0] if action == "domain" else "")


class Server(HTTPServer):
    def get_request(self):
        sock, peer = super().get_request()
        sock.settimeout(5)
        try:
            return self.tls.wrap_socket(sock, server_side=True), peer
        except OSError:
            sock.close()
            raise


if __name__ == "__main__":
    bind = os.environ.get("PANEL_BIND", "0.0.0.0")
    port = int(os.environ.get("PANEL_PORT", "9443"))
    with Server((bind, port), Panel) as server:
        password = (ROOT / "panel-password").read_bytes().strip()
        server.authorization = b"Basic " + base64.b64encode(b"admin:" + password)
        server.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.tls.minimum_version = ssl.TLSVersion.TLSv1_2
        server.tls.load_cert_chain(ROOT / "panel.crt", ROOT / "panel.key")
        server.serve_forever()
