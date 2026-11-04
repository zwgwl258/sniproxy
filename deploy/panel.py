"""HTTPS administration for the packaged SNIProxy service."""
import base64
import hmac
import html
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

    def page(self, message=""):
        config = html.escape(CONFIG.read_text(encoding="utf-8", errors="replace"))
        message = html.escape(message)
        status = "运行中" if active() else "未运行"
        self.reply(200, f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SNIProxy 管理</title><style>
body{{max-width:960px;margin:2rem auto;padding:0 1rem;font:16px system-ui}}
textarea{{width:100%;min-height:25rem;box-sizing:border-box;font:14px monospace}}
button{{margin:.5rem .5rem .5rem 0;padding:.6rem}}pre{{white-space:pre-wrap}}
</style><h1>SNIProxy 管理</h1><p>代理状态：{status}</p><pre>{message}</pre>
<form method="post" action="/">
<input type="hidden" name="nonce" value="{NONCE}">
<label for="config">代理配置（DNS 分组、监听端口、域名转发表）</label>
<textarea id="config" name="config" spellcheck="false">{config}</textarea>
<button name="action" value="apply">校验、保存并应用</button>
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
        except (OSError, subprocess.TimeoutExpired):
            message = "操作失败或超时，请检查代理状态和日志。"
        self.page(message)


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
