"""HTTPS administration for the packaged SNIProxy service."""
import base64
import hmac
import html
import hashlib
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

# ISO 3166-1 alpha-2 codes with Chinese and English search labels.
COUNTRIES = """AD|安道尔|Andorra
AE|阿拉伯联合酋长国|United Arab Emirates
AF|阿富汗|Afghanistan
AG|安提瓜和巴布达|Antigua & Barbuda
AI|安圭拉|Anguilla
AL|阿尔巴尼亚|Albania
AM|亚美尼亚|Armenia
AO|安哥拉|Angola
AQ|南极洲|Antarctica
AR|阿根廷|Argentina
AS|美属萨摩亚|American Samoa
AT|奥地利|Austria
AU|澳大利亚|Australia
AW|阿鲁巴|Aruba
AX|奥兰群岛|Åland Islands
AZ|阿塞拜疆|Azerbaijan
BA|波斯尼亚和黑塞哥维那|Bosnia & Herzegovina
BB|巴巴多斯|Barbados
BD|孟加拉国|Bangladesh
BE|比利时|Belgium
BF|布基纳法索|Burkina Faso
BG|保加利亚|Bulgaria
BH|巴林|Bahrain
BI|布隆迪|Burundi
BJ|贝宁|Benin
BL|圣巴泰勒米|St. Barthélemy
BM|百慕大|Bermuda
BN|文莱|Brunei
BO|玻利维亚|Bolivia
BQ|荷属加勒比区|Caribbean Netherlands
BR|巴西|Brazil
BS|巴哈马|Bahamas
BT|不丹|Bhutan
BV|布韦岛|Bouvet Island
BW|博茨瓦纳|Botswana
BY|白俄罗斯|Belarus
BZ|伯利兹|Belize
CA|加拿大|Canada
CC|科科斯（基林）群岛|Cocos (Keeling) Islands
CD|刚果（金）|Congo - Kinshasa
CF|中非共和国|Central African Republic
CG|刚果（布）|Congo - Brazzaville
CH|瑞士|Switzerland
CI|科特迪瓦|Côte d’Ivoire
CK|库克群岛|Cook Islands
CL|智利|Chile
CM|喀麦隆|Cameroon
CN|中国|China
CO|哥伦比亚|Colombia
CR|哥斯达黎加|Costa Rica
CU|古巴|Cuba
CV|佛得角|Cape Verde
CW|库拉索|Curaçao
CX|圣诞岛|Christmas Island
CY|塞浦路斯|Cyprus
CZ|捷克|Czechia
DE|德国|Germany
DJ|吉布提|Djibouti
DK|丹麦|Denmark
DM|多米尼克|Dominica
DO|多米尼加共和国|Dominican Republic
DZ|阿尔及利亚|Algeria
EC|厄瓜多尔|Ecuador
EE|爱沙尼亚|Estonia
EG|埃及|Egypt
EH|西撒哈拉|Western Sahara
ER|厄立特里亚|Eritrea
ES|西班牙|Spain
ET|埃塞俄比亚|Ethiopia
FI|芬兰|Finland
FJ|斐济|Fiji
FK|福克兰群岛（马尔维纳斯群岛）|Falkland Islands (Islas Malvinas)
FM|密克罗尼西亚|Micronesia
FO|法罗群岛|Faroe Islands
FR|法国|France
GA|加蓬|Gabon
GB|英国|United Kingdom
GD|格林纳达|Grenada
GE|格鲁吉亚|Georgia
GF|法属圭亚那|French Guiana
GG|根西岛|Guernsey
GH|加纳|Ghana
GI|直布罗陀|Gibraltar
GL|格陵兰|Greenland
GM|冈比亚|Gambia
GN|几内亚|Guinea
GP|瓜德罗普|Guadeloupe
GQ|赤道几内亚|Equatorial Guinea
GR|希腊|Greece
GS|南乔治亚和南桑威奇群岛|South Georgia & South Sandwich Islands
GT|危地马拉|Guatemala
GU|关岛|Guam
GW|几内亚比绍|Guinea-Bissau
GY|圭亚那|Guyana
HK|香港|Hong Kong
HM|赫德岛和麦克唐纳群岛|Heard & McDonald Islands
HN|洪都拉斯|Honduras
HR|克罗地亚|Croatia
HT|海地|Haiti
HU|匈牙利|Hungary
ID|印度尼西亚|Indonesia
IE|爱尔兰|Ireland
IL|以色列|Israel
IM|马恩岛|Isle of Man
IN|印度|India
IO|英属印度洋领地|British Indian Ocean Territory
IQ|伊拉克|Iraq
IR|伊朗|Iran
IS|冰岛|Iceland
IT|意大利|Italy
JE|泽西岛|Jersey
JM|牙买加|Jamaica
JO|约旦|Jordan
JP|日本|Japan
KE|肯尼亚|Kenya
KG|吉尔吉斯斯坦|Kyrgyzstan
KH|柬埔寨|Cambodia
KI|基里巴斯|Kiribati
KM|科摩罗|Comoros
KN|圣基茨和尼维斯|St. Kitts & Nevis
KP|朝鲜|North Korea
KR|韩国|South Korea
KW|科威特|Kuwait
KY|开曼群岛|Cayman Islands
KZ|哈萨克斯坦|Kazakhstan
LA|老挝|Laos
LB|黎巴嫩|Lebanon
LC|圣卢西亚|St. Lucia
LI|列支敦士登|Liechtenstein
LK|斯里兰卡|Sri Lanka
LR|利比里亚|Liberia
LS|莱索托|Lesotho
LT|立陶宛|Lithuania
LU|卢森堡|Luxembourg
LV|拉脱维亚|Latvia
LY|利比亚|Libya
MA|摩洛哥|Morocco
MC|摩纳哥|Monaco
MD|摩尔多瓦|Moldova
ME|黑山|Montenegro
MF|法属圣马丁|St. Martin
MG|马达加斯加|Madagascar
MH|马绍尔群岛|Marshall Islands
MK|北马其顿|North Macedonia
ML|马里|Mali
MM|缅甸|Myanmar (Burma)
MN|蒙古|Mongolia
MO|澳门|Macao
MP|北马里亚纳群岛|Northern Mariana Islands
MQ|马提尼克|Martinique
MR|毛里塔尼亚|Mauritania
MS|蒙特塞拉特|Montserrat
MT|马耳他|Malta
MU|毛里求斯|Mauritius
MV|马尔代夫|Maldives
MW|马拉维|Malawi
MX|墨西哥|Mexico
MY|马来西亚|Malaysia
MZ|莫桑比克|Mozambique
NA|纳米比亚|Namibia
NC|新喀里多尼亚|New Caledonia
NE|尼日尔|Niger
NF|诺福克岛|Norfolk Island
NG|尼日利亚|Nigeria
NI|尼加拉瓜|Nicaragua
NL|荷兰|Netherlands
NO|挪威|Norway
NP|尼泊尔|Nepal
NR|瑙鲁|Nauru
NU|纽埃|Niue
NZ|新西兰|New Zealand
OM|阿曼|Oman
PA|巴拿马|Panama
PE|秘鲁|Peru
PF|法属波利尼西亚|French Polynesia
PG|巴布亚新几内亚|Papua New Guinea
PH|菲律宾|Philippines
PK|巴基斯坦|Pakistan
PL|波兰|Poland
PM|圣皮埃尔和密克隆群岛|St. Pierre & Miquelon
PN|皮特凯恩群岛|Pitcairn Islands
PR|波多黎各|Puerto Rico
PS|巴勒斯坦|Palestine
PT|葡萄牙|Portugal
PW|帕劳|Palau
PY|巴拉圭|Paraguay
QA|卡塔尔|Qatar
RE|留尼汪|Réunion
RO|罗马尼亚|Romania
RS|塞尔维亚|Serbia
RU|俄罗斯|Russia
RW|卢旺达|Rwanda
SA|沙特阿拉伯|Saudi Arabia
SB|所罗门群岛|Solomon Islands
SC|塞舌尔|Seychelles
SD|苏丹|Sudan
SE|瑞典|Sweden
SG|新加坡|Singapore
SH|圣赫勒拿|St. Helena
SI|斯洛文尼亚|Slovenia
SJ|斯瓦尔巴和扬马延|Svalbard & Jan Mayen
SK|斯洛伐克|Slovakia
SL|塞拉利昂|Sierra Leone
SM|圣马力诺|San Marino
SN|塞内加尔|Senegal
SO|索马里|Somalia
SR|苏里南|Suriname
SS|南苏丹|South Sudan
ST|圣多美和普林西比|São Tomé & Príncipe
SV|萨尔瓦多|El Salvador
SX|荷属圣马丁|Sint Maarten
SY|叙利亚|Syria
SZ|斯威士兰|Eswatini
TC|特克斯和凯科斯群岛|Turks & Caicos Islands
TD|乍得|Chad
TF|法属南部领地|French Southern Territories
TG|多哥|Togo
TH|泰国|Thailand
TJ|塔吉克斯坦|Tajikistan
TK|托克劳|Tokelau
TL|东帝汶|Timor-Leste
TM|土库曼斯坦|Turkmenistan
TN|突尼斯|Tunisia
TO|汤加|Tonga
TR|土耳其|Türkiye
TT|特立尼达和多巴哥|Trinidad & Tobago
TV|图瓦卢|Tuvalu
TW|台湾|Taiwan
TZ|坦桑尼亚|Tanzania
UA|乌克兰|Ukraine
UG|乌干达|Uganda
UM|美国本土外小岛屿|U.S. Outlying Islands
US|美国|United States
UY|乌拉圭|Uruguay
UZ|乌兹别克斯坦|Uzbekistan
VA|梵蒂冈|Vatican City
VC|圣文森特和格林纳丁斯|St. Vincent & Grenadines
VE|委内瑞拉|Venezuela
VG|英属维尔京群岛|British Virgin Islands
VI|美属维尔京群岛|U.S. Virgin Islands
VN|越南|Vietnam
VU|瓦努阿图|Vanuatu
WF|瓦利斯和富图纳|Wallis & Futuna
WS|萨摩亚|Samoa
YE|也门|Yemen
YT|马约特|Mayotte
ZA|南非|South Africa
ZM|赞比亚|Zambia
ZW|津巴布韦|Zimbabwe"""
COUNTRY_OPTIONS = "".join(
    f'<option value="{code}">{code} · {html.escape(name)}</option>'
    for code, name in ((line[:2], line[3:].replace("|", " · ")) for line in COUNTRIES.splitlines())
)


COUNTRY_SCRIPT = """const picker = document.getElementById("country-picker");
const search = document.getElementById("country-search");
const results = document.getElementById("country-options");
const source = document.getElementById("client");
const countries = Array.from(results.options);
search.addEventListener("input", () => {
    const query = search.value.trim().toLowerCase();
    results.replaceChildren(...countries.filter(option =>
        option.textContent.toLowerCase().includes(query)));
    results.selectedIndex = -1;
});
results.addEventListener("change", () => {
    if (!results.value) return;
    source.value = results.value;
    picker.open = false;
    document.getElementById("dns").focus();
});
picker.addEventListener("toggle", () => {
    if (!picker.open) return;
    search.value = "";
    results.replaceChildren(...countries);
    results.selectedIndex = -1;
    search.focus();
});
const ruleSearch = document.getElementById("rule-search");
const ruleRows = Array.from(document.querySelectorAll(".rule-row"));
const previous = document.getElementById("rule-previous");
const next = document.getElementById("rule-next");
const pageSize = 10;
let page = 0;

function renderRules() {
    const query = ruleSearch.value.trim().toLowerCase();
    const matches = ruleRows.filter(row =>
        Array.from(row.querySelectorAll("input:not([type=hidden])")).some(input => {
            const value = input.value.toLowerCase();
            return value.includes(query) ||
                value.replaceAll(String.fromCharCode(92) + ".", ".").replaceAll("[.]", ".").includes(query);
        }));
    const pages = Math.max(1, Math.ceil(matches.length / pageSize));
    page = Math.max(0, Math.min(page, pages - 1));
    const visible = new Set(matches.slice(page * pageSize, (page + 1) * pageSize));
    for (const row of ruleRows) row.hidden = !visible.has(row);
    previous.disabled = page === 0;
    next.disabled = page >= pages - 1;
    document.getElementById("rule-count").textContent = matches.length
        ? `第 ${page + 1} / ${pages} 页 · ${matches.length} 条匹配`
        : "没有匹配规则";
}

ruleSearch.addEventListener("input", () => { page = 0; renderRules(); });
previous.addEventListener("click", () => { page--; renderRules(); });
next.addEventListener("click", () => { page++; renderRules(); });
renderRules();
for (const row of ruleRows) {
    row.addEventListener("submit", event => {
        if (event.submitter?.value === "delete_rule" && !window.confirm("确定删除这条规则？")) {
            event.preventDefault();
        }
    });
}"""
COUNTRY_SCRIPT_HASH = base64.b64encode(hashlib.sha256(COUNTRY_SCRIPT.encode()).digest()).decode()


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
            raise ValueError("请先安装国家数据库：重新运行一键安装脚本，或手动放到 /etc/sniproxy-managed/country.mmdb。") from None
        raise ValueError("请输入两字母国家/地区代码、有效 IP 或网段，以及 1 至 6 个 DNS IP。") from None
    nameservers = "".join(f"    nameserver {server}\n" for server in servers)
    return (config.rstrip() + f"\n\nresolver {{\n    client {source}\n" +
            nameservers + "    mode ipv4_only\n}\n")



def managed_rules(config):
    for block in re.finditer(r"(?m)^([ \t]*)(table|resolver)[ \t]*\{[ \t]*(?:#[^\n]*)?\n([\s\S]*?)^[ \t]*\}[ \t]*(?:#[^\n]*)?$\n?", config):
        body = block[3]
        if block[2] == "table":
            pattern = r"(?m)^[ \t]*((?:\.\*|\^\(\.\*\[\.\]\)\?)[A-Za-z0-9-]+(?:(?:\\\.|\[\.\])[A-Za-z0-9-]+)+\$[ \t]+\*)[ \t]*$\n?"
            for rule in re.finditer(pattern, body):
                yield ("domain", block.start(3) + rule.start(), block.start(3) + rule.end(), rule[1], "")
        else:
            rule = re.fullmatch(r"[ \t]*client[ \t]+(\S+)[ \t]*\n((?:[ \t]*nameserver[ \t]+\S+[ \t]*\n)+)[ \t]*mode[ \t]+ipv4_only[ \t]*\n", body)
            if rule:
                servers = ", ".join(line.split()[1] for line in rule[2].splitlines())
                yield ("dns", block.start(), block.end(), rule[1], servers)


def domain_name(rule):
    return (rule.split()[0].removeprefix("^(.*[.])?").removeprefix(".*")
            .removesuffix("$").replace(r"\.", ".").replace("[.]", "."))


def replace_domains(config, revision, value):
    if revision != rule_revision(config):
        raise ValueError("配置已变化，请刷新页面再保存。")
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    # Validate the entire input before dropping any saved rules.
    if lines:
        add_domain("", value)
    names = {line.rstrip(".").lower() for line in lines if not line.startswith(".*")}
    explicit = {" ".join(line.split()) for line in lines if line.startswith(".*")}
    retained = set()
    for kind, start, end, rule, _ in reversed(list(managed_rules(config))):
        if kind != "domain":
            continue
        name = domain_name(rule).lower()
        if name in names or " ".join(rule.split()) in explicit:
            retained.add(name)
        else:
            config = config[:start] + config[end:]
    existing = {" ".join(line.split()) for line in config.splitlines()}
    added = [line for line in lines if (
        " ".join(line.split()) not in existing if line.startswith(".*")
        else line.rstrip(".").lower() not in retained)]
    return add_domain(config, "\n".join(added)) if added else config


def rule_revision(config):
    return hashlib.sha256(config.encode()).hexdigest()


def change_rule(config, key, action, value="", dns=""):
    revision, _, index = key.partition(":")
    rules = list(managed_rules(config))
    if revision != rule_revision(config) or not index.isascii() or not index.isdecimal() or len(index) > 10:
        raise ValueError("配置已变化，请刷新页面再操作。")
    index = int(index)
    if index >= len(rules):
        raise ValueError("规则已不存在，请刷新页面。")
    kind, start, end, old, _ = rules[index]
    replacement = ""
    if action == "edit_rule":
        if kind == "dns":
            replacement = add_client_dns("", value, dns).lstrip()
        else:
            if len(value.splitlines()) != 1:
                raise ValueError("修改时只能填一条域名规则。")
            normalized = value.strip().replace("^(.*[.])?", "").removesuffix("$ *").replace("[.]", ".") if value.startswith("^(.*[.])?") else value
            replacement = add_domain("", normalized).split("table {\n", 1)[1].rsplit("}\n", 1)[0]
            if replacement.strip() != old.strip() and replacement.strip() in {
                    line.strip() for line in config.splitlines()}:
                raise ValueError("该域名规则已存在。")
    return config[:start] + replacement + config[end:]


def rule_forms(config):
    forms = []
    revision = rule_revision(config)
    for index, (kind, _, _, value, dns) in enumerate(managed_rules(config)):
        if kind != "dns":
            continue
        value = html.escape(value, quote=True)
        label = "域名" if kind == "domain" else "客户端 DNS"
        dns_field = (f'<input name="dns" aria-label="DNS 服务器 IP" value="{html.escape(dns, quote=True)}" required>'
                     if kind == "dns" else "")
        forms.append(f"""<form class="rule-row" data-kind="{kind}" method="post" action="/">
<input type="hidden" name="nonce" value="{NONCE}">
<input type="hidden" name="rule" value="{revision}:{index}">
<span class="rule-type">{label}</span>
<div class="rule-fields"><input name="value" aria-label="{label}规则" value="{value}" required>{dns_field}</div>
<div class="rule-actions"><button name="action" value="edit_rule">保存修改</button>
<button name="action" value="delete_rule" formnovalidate>删除</button></div>
</form>""")
    return "".join(forms) or "<p>没有可直接编辑的规则。</p>"


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
                         "frame-ancestors 'none'; form-action 'self'; base-uri 'none'; "
                         f"script-src 'sha256-{COUNTRY_SCRIPT_HASH}'")
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

    def page(self, message="", domain_input=None, rules_open=False):
        current = CONFIG.read_text(encoding="utf-8", errors="replace")
        rules = rule_forms(current)
        domains = html.escape(domain_input if domain_input is not None else "\n".join(
            domain_name(value) for kind, _, _, value, _ in managed_rules(current) if kind == "domain"
        ))
        config = html.escape(current)
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
#saved-domains{{display:block;min-height:16rem;resize:vertical;padding:.65rem;line-height:1.5;white-space:pre;overflow:auto}}
small{{display:block;margin:.25rem 0;color:#435264}}
button{{margin:.5rem .5rem .5rem 0;padding:.6rem}}pre{{white-space:pre-wrap}}
.rule-row{{display:grid;grid-template-columns:5.5rem minmax(0,1fr) auto;align-items:center;gap:.65rem;padding:.5rem 0;border-bottom:1px solid #e4eaf0}}
.rule-row[hidden]{{display:none}}
.rule-fields{{display:flex;gap:.45rem;min-width:0}}
.rule-fields input{{min-width:0;max-width:none}}
.rule-actions{{display:flex;gap:.35rem}}
.rule-actions button{{margin:0;white-space:nowrap;padding:.4rem .55rem}}
.rule-actions button[value=delete_rule]{{color:#a12626}}
.rule-type{{color:#435264;font-size:.875rem}}
.rule-toolbar{{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}}
#rule-count{{color:#435264}}
@media(max-width:640px){{.rule-row{{grid-template-columns:minmax(0,1fr) auto}}.rule-type{{grid-column:1/-1}}.rule-fields{{flex-wrap:wrap}}}}
</style><h1>SNIProxy 管理</h1><p>代理状态：{status}</p><pre>{message}</pre>
<section><h2>域名转发</h2>
<form method="post" action="/">
<input type="hidden" name="nonce" value="{NONCE}">
<input type="hidden" name="revision" value="{rule_revision(current)}">
<label for="saved-domains">域名列表（每行一条）</label>
<textarea id="saved-domains" name="domain" rows="12" spellcheck="false" placeholder="netflix.ca&#10;netflix.com">{domains}</textarea>
<small>新增一行添加域名，改一行修改域名，删一行删除域名。保存会应用整个列表；自定义规则不受影响。</small>
<button name="action" value="save_domains">保存域名列表</button></form></section>
<section><h2>客户端 DNS 分流</h2>
<form method="post" action="/">
<input type="hidden" name="nonce" value="{NONCE}">
<label for="client">客户端来源国家／地区、IP 或网段</label>
<input id="client" name="client" autocomplete="off" placeholder="JP，或输入 IP / 网段" required>
<details id="country-picker"><summary>选择国家／地区</summary>
<label for="country-search">搜索国家／地区</label>
<input id="country-search" type="search" autocomplete="off" placeholder="日本 / Japan / JP">
<select id="country-options" size="6" aria-label="国家／地区搜索结果"
        style="display:block;width:100%;max-width:34rem;margin-top:.5rem">{COUNTRY_OPTIONS}</select>
</details>
<label for="dns">DNS 服务器 IP</label>
<input id="dns" name="dns" placeholder="154.83.83.86, 149.28.158.78" required>
<small>点击「选择国家／地区」，按中文名、英文名或两字母代码搜索后选择；也可直接输入 IP 或网段。按代理看到的 TCP 来源 IP 查询本地国家库。优先级：IP／网段 → 国家／地区 → 默认 DNS。 <a href="https://db-ip.com/" rel="noreferrer">IP Geolocation by DB-IP</a></small>
<button name="action" value="client_dns">添加并应用</button></form></section>
<details id="saved-rules" {"open" if rules_open else ""}><summary>已添加客户端 DNS：修改或删除</summary>
<label for="rule-search">搜索已添加的客户端 DNS</label>
<div class="rule-toolbar">
<input id="rule-search" type="search" placeholder="搜索客户端来源或 DNS 地址" autocomplete="off">
</div>
<nav class="rule-toolbar" aria-label="规则分页">
<button id="rule-previous" type="button">上一页</button>
<button id="rule-next" type="button">下一页</button>
<span id="rule-count" aria-live="polite"></span>
</nav>{rules}</details>
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
</form><script>{COUNTRY_SCRIPT}</script></html>""")

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
                            max_num_fields=5, errors="strict")
        except (UnicodeError, ValueError):
            return self.reply(400)
        if not hmac.compare_digest(form.get("nonce", [""])[0].encode(), NONCE.encode()):
            return self.reply(403)
        action = form.get("action", [""])[0]
        try:
            if action == "apply":
                data = form["config"][0].replace("\r\n", "\n").encode()
                message = apply(data) if data.strip() else "配置不能为空。"
            elif action == "save_domains":
                config = CONFIG.read_text(encoding="utf-8")
                updated = replace_domains(config, form["revision"][0], form["domain"][0])
                message = apply(updated.encode()) if updated != config else "域名列表没有变化。"
            elif action in ("domain", "client_dns"):
                config = CONFIG.read_text(encoding="utf-8")
                if action == "domain":
                    updated = add_domain(config, form["domain"][0])
                else:
                    updated = add_client_dns(config, form["client"][0], form["dns"][0])
                message = apply(updated.encode())
            elif action in ("edit_rule", "delete_rule"):
                config = CONFIG.read_text(encoding="utf-8")
                updated = change_rule(config, form["rule"][0], action,
                                      form.get("value", [""])[0], form.get("dns", [""])[0])
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
        draft = (form.get("domain", [""])[0] if action == "save_domains" and
                 message not in ("配置已保存并应用。", "域名列表没有变化。") else None)
        self.page(message, draft,
                  rules_open=action in ("edit_rule", "delete_rule"))


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
