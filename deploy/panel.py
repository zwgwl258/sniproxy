"""HTTPS administration for the packaged SNIProxy service."""
import base64
import hmac
import html
import hashlib
import ipaddress
import re
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

ROOT = Path("/etc/sniproxy-managed")
CONFIG = ROOT / "sniproxy.conf"
BACKUP = ROOT / "sniproxy.conf.previous"
SERVICE = "sniproxy-managed.service"
CHECKER = "/usr/local/lib/sniproxy-managed/config-test"
MAX_BODY = 1024 * 1024
NONCE = secrets.token_urlsafe(32)
FORM_RESULTS = {}

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


def dns_health_status():
    try:
        invocation = command("systemctl", "show", "-p", "InvocationID", "--value", SERVICE)
        invocation_id = invocation.stdout.strip()
        if invocation.returncode or not re.fullmatch(r"[0-9a-f]{32}", invocation_id) or not int(invocation_id, 16):
            return "<p>DNS 探测状态：服务未运行或暂不可读。</p>"
        result = command("journalctl", f"_SYSTEMD_INVOCATION_ID={invocation_id}",
                         "--grep=^SNIPROXY_DNS_(HEALTH|PREFERRED) ", "-o", "cat", "-n", "2048", "--no-pager")
    except (OSError, subprocess.TimeoutExpired):
        return "<p>DNS 探测状态暂不可读。</p>"

    readings = {}
    preferred = ""
    for line in result.stdout.splitlines():
        health = re.fullmatch(r"SNIPROXY_DNS_HEALTH (\S+) (\S+) (-?\d{1,9})", line)
        if health:
            readings[health[1], health[2]] = int(health[3])
        else:
            selected = re.fullmatch(r"SNIPROXY_DNS_PREFERRED (\S+)", line)
            if selected:
                preferred = selected[1]
    if not readings:
        return "<p>DNS 探测状态：暂无结果（等待探测或日志不可读）。</p>"
    delay = readings.get(("fallback", preferred))
    if delay is not None and delay >= 0:
        primary = f"{html.escape(preferred)}（{delay} ms）"
    elif preferred == "-":
        primary = "暂无通过探测的兜底 DNS（查询仍会尝试原兜底组）"
    else:
        primary = "暂无选中节点"
    failed = [f"{html.escape(server)}（{html.escape(source if source != 'fallback' else '兜底')}）"
              for (source, server), latency in readings.items() if latency < 0]
    return (f"<p><strong>当前首选兜底 DNS：</strong>{primary}</p>"
            f"<p><strong>不可用 DNS：</strong>{'、'.join(failed) or '已探测节点中无故障'}</p>"
            "<small>每 5 分钟复测，刷新页面查看最近结果。</small>")



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


DOMAIN_RULE = r'(?:\\[^\r\n]|"(?:\\[^\r\n]|[^"\\\r\n])*"|[^ \t\r\n#;{}"\\\x00])+[ \t]+\*'


def domain_entries(value):
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    for number, line in enumerate(value.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        if re.fullmatch(DOMAIN_RULE, line):
            yield line, None
            continue
        domain = line.rstrip(".").lower()
        if len(domain) > 253 or not re.fullmatch(rf"{label}(?:\.{label})+", domain):
            raise ValueError(f"第 {number} 行格式无效；请填域名或正则表达式加 *。整批未保存。")
        yield "^(.*[.])?" + domain.replace(".", "[.]") + "$ *", domain


def add_domain(config, value):
    existing = {line.strip() for line in config.splitlines()}
    rules = []
    for entry, _ in domain_entries(value):
        if entry not in existing:
            existing.add(entry)
            rules.append("    " + entry + "\n")
    if not rules:
        raise ValueError("没有可添加的规则：输入为空或规则已存在。")
    return insert_domains(config, "".join(rules))


def insert_domains(config, rule):
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


def add_client_dns(config, client, dns, *, fallback=False):
    try:
        source = client.strip()
        if fallback:
            source = "fallback"
        elif re.fullmatch(r"[A-Za-z]{2}", source):
            source = source.upper()
            if not (ROOT / "country.mmdb").is_file():
                raise ValueError("missing-country-db")
        else:
            source = str(ipaddress.ip_network(source, strict=True))
        servers = [ipaddress.ip_address(item) for item in re.split(r"[\s,]+", dns.strip()) if item]
        if not servers or (not fallback and len(servers) > 6) or any("%" in str(server) for server in servers):
            raise ValueError
    except ValueError as error:
        if str(error) == "missing-country-db":
            raise ValueError("请先安装国家数据库：重新运行一键安装脚本，或手动放到 /etc/sniproxy-managed/country.mmdb。") from None
        if fallback:
            raise ValueError("请输入有效的 DNS IP，每行一个。") from None
        raise ValueError("请输入两字母国家/地区代码、有效 IP 或网段，以及 1 至 6 个 DNS IP。") from None
    nameservers = "".join(f"    nameserver {server}\n" for server in servers)
    return (config.rstrip() + f"\n\nresolver {{\n    client {source}\n" +
            nameservers + "    mode ipv4_only\n}\n")



def managed_rules(config):
    for block in re.finditer(r"(?m)^([ \t]*)(table|resolver)[ \t]*\{[ \t]*(?:#[^\n]*)?\n([\s\S]*?)^[ \t]*\}[ \t]*(?:#[^\n]*)?$\n?", config):
        body = block[3]
        if block[2] == "table":
            pattern = rf"(?m)^[ \t]*({DOMAIN_RULE})[ \t]*$\n?"
            for rule in re.finditer(pattern, body):
                yield ("domain", block.start(3) + rule.start(), block.start(3) + rule.end(), rule[1], "")
        else:
            rule = re.fullmatch(r"[ \t]*client[ \t]+(\S+)[ \t]*\n((?:[ \t]*nameserver[ \t]+\S+[ \t]*\n)+)[ \t]*mode[ \t]+ipv4_only[ \t]*\n", body)
            if rule:
                servers = ", ".join(line.split()[1] for line in rule[2].splitlines())
                yield ("dns", block.start(), block.end(), rule[1], servers)


def domain_name(rule):
    if not re.fullmatch(r"(?:\.\*|\^\(\.\*\[\.\]\)\?)[A-Za-z0-9-]+(?:(?:\\\.|\[\.\])[A-Za-z0-9-]+)+\$[ \t]+\*", rule):
        return rule
    return (rule.split()[0].removeprefix("^(.*[.])?").removeprefix(".*")
            .removesuffix("$").replace(r"\.", ".").replace("[.]", "."))


def replace_domains(config, revision, value):
    if revision != rule_revision(config):
        raise ValueError("配置已变化，请刷新页面再保存。")
    old = [(start, end, rule) for kind, start, end, rule, _ in managed_rules(config)
           if kind == "domain"]
    aliases = {}
    for _, _, rule in old:
        name = domain_name(rule)
        if name != rule:
            aliases.setdefault(name.lower(), []).append(rule)
    entries = list(dict.fromkeys(
        rule for entry, name in domain_entries(value) for rule in aliases.get(name, [entry])))
    rows = ["    " + entry + "\n" for entry in entries]
    if not old:
        return insert_domains(config, "".join(rows)) if rows else config
    for i in reversed(range(len(old))):
        start, end, rule = old[i]
        if i == len(old) - 1:
            replacement = "".join(rows[i:])
        elif i < len(rows) and entries[i] == rule:
            replacement = config[start:end]
        else:
            replacement = "".join(rows[i:i + 1])
        config = config[:start] + replacement + config[end:]
    return config


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
        if kind != "dns" or value == "fallback":
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
        if self.path.startswith("/adguard/"):
            if (ROOT / "password-change-required").is_file():
                self.reply(303, Location="/")
                return False
            return True
        if self.path != "/" and not (self.command == "GET" and
                re.fullmatch(r"/\?result=[A-Za-z0-9_-]{22}", self.path)):
            self.reply(404)
            return False
        return True

    def page(self, message="", domain_input=None):
        password_form = f"""
<form method="post" action="/">
<input type="hidden" name="nonce" value="{NONCE}">
<label for="current-password">当前密码</label>
<input id="current-password" name="current_password" type="password" autocomplete="current-password" required>
<label for="new-password">新密码</label>
<input id="new-password" name="new_password" type="password" autocomplete="new-password" minlength="12" maxlength="128" required>
<label for="confirm-password">确认新密码</label>
<input id="confirm-password" name="confirm_password" type="password" autocomplete="new-password" minlength="12" maxlength="128" required>
<button name="action" value="change_password">修改密码</button>
<small>新密码至少 12 个字符。保存后请用新密码重新登录。</small>
</form>"""
        if (ROOT / "password-change-required").is_file():
            return self.reply(200, f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<title>修改初始密码</title><h1>首次登录：修改初始密码</h1>
<p>{html.escape(message or "请先修改初始密码，再进入管理面板。")}</p>
<style>label,input,button{{display:block;margin:.5rem 0}}body{{font:16px system-ui;margin:2rem}}</style>
{password_form}</html>""")
        address_file = ROOT / "adguard-url"
        adguard_url = html.escape(address_file.read_text(encoding="utf-8").strip(), quote=True) if address_file.is_file() else ""
        integrated = (ROOT / "adguard-integrated").is_file()
        adguard_link = "/adguard/" if integrated else adguard_url or "#adguard-url"
        current = CONFIG.read_text(encoding="utf-8", errors="replace")
        rules = rule_forms(current)
        fallback_dns = html.escape(next((dns for kind, _, _, source, dns in
            reversed(list(managed_rules(current))) if kind == "dns" and source == "fallback"), "").replace(", ", "\n"), quote=True)
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
#fallback-dns{{display:block;width:min(100%,34rem);min-height:0;resize:vertical}}
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
#saved-rules{{margin:1rem 0;padding:.8rem 0;border-block:1px solid #e4eaf0}}
#saved-rules h3{{margin:0 0 .5rem}}
#rule-count{{color:#435264}}
@media(max-width:640px){{.rule-row{{grid-template-columns:minmax(0,1fr) auto}}.rule-type{{grid-column:1/-1}}.rule-fields{{flex-wrap:wrap}}}}
.panel-header{{display:flex;align-items:center;gap:1.25rem;flex-wrap:wrap}}
.panel-header a{{padding:.55rem .8rem;border:1px solid #a5b8cc;border-radius:.45rem;color:#194b79;text-decoration:none}}
.panel-header a:hover{{background:#edf5ff}}
</style><header class="panel-header"><h1>SNIProxy 管理</h1>
<a href="{adguard_link}" {'target="_blank" rel="noopener noreferrer"' if integrated or adguard_url else ""}>AdGuard Home 管理</a></header><p>代理状态：{status}</p><pre>{message}</pre>
<section><h2>域名转发</h2>
<form method="post" action="/">
<input type="hidden" name="nonce" value="{NONCE}">
<input type="hidden" name="revision" value="{rule_revision(current)}">
<label for="saved-domains">域名列表（每行一条）</label>
<textarea id="saved-domains" name="domain" rows="12" spellcheck="false" placeholder="netflix.ca&#10;netflix.com">{domains}</textarea>
<small>每行填写一个域名或一条以 * 为转发目标的原版 SNIProxy 正则规则。支持批量粘贴、修改、删除；其他转发目标不受影响。</small>
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
<button name="action" value="client_dns">添加并应用</button></form>
<div id="saved-rules"><h3>已添加客户端 DNS：修改或删除</h3>
<label for="rule-search">搜索已添加的客户端 DNS</label>
<div class="rule-toolbar">
<input id="rule-search" type="search" placeholder="搜索客户端来源或 DNS 地址" autocomplete="off">
</div>
<nav class="rule-toolbar" aria-label="规则分页">
<button id="rule-previous" type="button">上一页</button>
<button id="rule-next" type="button">下一页</button>
<span id="rule-count" aria-live="polite"></span>
</nav>{rules}</div>
<form method="post" action="/">
<input type="hidden" name="nonce" value="{NONCE}">
<div id="dns-health">{dns_health_status()}</div>
<label for="fallback-dns">全局兜底 DNS</label>
<textarea id="fallback-dns" name="dns" rows="6" spellcheck="false" placeholder="1.1.1.1&#10;8.8.8.8">{fallback_dns}</textarea>
<small>未命中 IP／网段或国家规则时直接使用；客户端专用 DNS 未返回可用地址时也会尝试。每行一个 IP；清空后保存可关闭。</small>
<button name="action" value="fallback_dns">保存兜底 DNS</button></form></section>
<details><summary>修改面板密码</summary>{password_form}</details>
<details><summary>AdGuard Home 后台地址设置</summary>
<form method="post" action="/">
<input type="hidden" name="nonce" value="{NONCE}">
<label for="adguard-url">AdGuard Home 管理地址</label>
<input id="adguard-url" name="url" type="url" value="{adguard_url}" placeholder="https://dns.example.com/">
<button name="action" value="adguard_url">保存后台地址</button>
<small>填写浏览器能访问的完整后台地址。留空保存会清除入口地址。</small>
</form></details>
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

    def form_result(self, message, draft=None):
        token = secrets.token_urlsafe(16)
        if len(FORM_RESULTS) >= 16:
            FORM_RESULTS.pop(next(iter(FORM_RESULTS)))
        FORM_RESULTS[token] = (message, draft)
        self.reply(303, Location=f"/?result={token}")

    def proxy_adguard(self):
        if not (ROOT / "adguard-integrated").is_file():
            return self.reply(404)
        if self.command != "GET":
            origin = self.headers.get("Origin")
            if origin != "https://" + self.headers.get("Host", ""):
                return self.reply(403, "请从已登录的管理页面提交请求。")
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if self.headers.get("Transfer-Encoding") or not 0 <= size <= MAX_BODY:
                return self.reply(400)
        except ValueError:
            return self.reply(400)
        target = "/" + self.path.removeprefix("/adguard/")
        if target.startswith("//") or "\\" in target:
            return self.reply(400)
        if urlsplit(target).path == "/control/tls/configure":
            return self.reply(403, "请使用 SNIProxy 的 HTTPS 管理入口。")
        headers = {}
        for key in ("Content-Type", "Accept"):
            if key in self.headers:
                headers[key] = self.headers[key]
        conn = HTTPConnection("127.0.0.1", 3000, timeout=15)
        try:
            conn.request(self.command, target, body=self.rfile.read(size) if size else None,
                         headers=headers)
            response = conn.getresponse()
            body = response.read(32 * 1024 * 1024 + 1)
            if len(body) > 32 * 1024 * 1024:
                return self.reply(502)
            self.send_response(response.status)
            for key in ("Content-Type", "Content-Encoding", "Content-Disposition"):
                if response.getheader(key):
                    self.send_header(key, response.getheader(key))
            location = response.getheader("Location")
            if location and location.startswith("/") and not location.startswith("//"):
                self.send_header("Location", "/adguard" + location)
            elif location and not urlsplit(location).netloc and not urlsplit(location).scheme:
                self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (OSError, HTTPException):
            self.reply(502, "AdGuard Home 后台暂不可用。")
        finally:
            conn.close()

    def do_PUT(self):
        if self.path.startswith("/adguard/") and self.authorized():
            self.proxy_adguard()
        elif not self.path.startswith("/adguard/"):
            self.reply(404)

    do_DELETE = do_PATCH = do_PUT

    def do_GET(self):
        if self.authorized():
            if self.path.startswith("/adguard/"):
                return self.proxy_adguard()
            token = self.path.partition("?result=")[2]
            self.page(*FORM_RESULTS.pop(token, ("", None)))

    def do_POST(self):
        if not self.authorized():
            return
        if self.path.startswith("/adguard/"):
            return self.proxy_adguard()
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= MAX_BODY:
                raise ValueError
            form = parse_qs(self.rfile.read(size).decode(), keep_blank_values=True,
                            max_num_fields=5, errors="strict")
        except (UnicodeError, ValueError):
            return self.reply(400)
        if not hmac.compare_digest(form.get("nonce", [""])[0].encode(), NONCE.encode()):
            return self.form_result("页面已过期，本次操作未执行。请重新操作。")
        action = form.get("action", [""])[0]
        if action != "change_password" and (ROOT / "password-change-required").is_file():
            return self.form_result("请先修改初始密码。")
        try:
            if action == "apply":
                data = form["config"][0].replace("\r\n", "\n").encode()
                message = apply(data) if data.strip() else "配置不能为空。"
            elif action == "fallback_dns":
                config = CONFIG.read_text(encoding="utf-8")
                dns = form["dns"][0].strip()
                for kind, start, end, source, _ in reversed(list(managed_rules(config))):
                    if kind == "dns" and source == "fallback":
                        config = config[:start] + config[end:]
                if re.search(r"(?m)^[ \t]*client[ \t]+fallback\b", config):
                    raise ValueError("已有自定义兜底配置，请在高级配置中修改。")
                if dns:
                    config = add_client_dns(config, "", dns, fallback=True)
                message = apply(config.encode())
            elif action == "change_password":
                current = form["current_password"][0]
                new = form["new_password"][0]
                confirmation = form["confirm_password"][0]
                supplied = b"Basic " + base64.b64encode(b"admin:" + current.encode())
                if not hmac.compare_digest(supplied, self.server.authorization):
                    raise ValueError("当前密码不正确。")
                if new != confirmation:
                    raise ValueError("两次输入的新密码不一致。")
                if (not 12 <= len(new) <= 128 or new != new.strip() or
                        not new.isprintable() or new == current):
                    raise ValueError("新密码须为不同的 12–128 个可打印字符，首尾不能有空白。")
                atomic_write(ROOT / "panel-password", (new + "\n").encode())
                self.server.authorization = b"Basic " + base64.b64encode(b"admin:" + new.encode())
                (ROOT / "password-change-required").unlink(missing_ok=True)
                message = "密码已修改，请用新密码重新登录。"
            elif action == "adguard_url":
                url = form["url"][0].strip()
                if url:
                    parsed = urlsplit(url)
                    if (len(url) > 2048 or parsed.scheme not in ("http", "https") or
                            not parsed.hostname or parsed.username is not None or
                            parsed.password is not None or parsed.port == 0 or
                            any(char.isspace() or ord(char) < 32 or char == chr(92) for char in url)):
                        raise ValueError("请填写有效的 HTTP 或 HTTPS 后台地址，不要包含账号或密码。")
                atomic_write(ROOT / "adguard-url", (url + "\n").encode())
                message = "AdGuard Home 后台地址已保存。" if url else "已清除 AdGuard Home 后台地址。"
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
        self.form_result(message, draft)


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
