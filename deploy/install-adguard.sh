#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "$0")"

dir=/opt/sniproxy-adguard
unit=sniproxy-adguard.service
if systemctl cat AdGuardHome.service >/dev/null 2>&1 ||
   [[ -e /opt/AdGuardHome/AdGuardHome || -e /usr/local/bin/AdGuardHome ]]; then
    echo "Existing AdGuard Home detected; leaving it unchanged. Set its URL in the SNIProxy panel."
    exit 0
fi

if [[ ! -x $dir/AdGuardHome ]]; then
    version=v0.107.80
    case "$(dpkg --print-architecture)" in
        amd64) arch=amd64; sha=28593bc761d71469abdbc6f39ca42cbed763ec92b63082c729177b037ed51d18 ;;
        arm64) arch=arm64; sha=d5e17d0d724418ddef8b7723ed8ade7eef4e621ec5b0e43a341859cca71a3d8f ;;
        *) echo "Bundled AdGuard Home installation supports amd64 and arm64." >&2; exit 1 ;;
    esac
    tmp=$(mktemp -d)
    trap 'rm -rf -- "$tmp"' EXIT
    curl -fLsS --proto '=https' --retry 2 --connect-timeout 10 --max-time 120 \
        "https://github.com/AdguardTeam/AdGuardHome/releases/download/$version/AdGuardHome_linux_$arch.tar.gz" \
        -o "$tmp/adguard.tar.gz"
    printf '%s  %s\n' "$sha" "$tmp/adguard.tar.gz" | sha256sum -c -
    tar -xzf "$tmp/adguard.tar.gz" -C "$tmp"
    install -d -m 0700 "$dir"
    install -m 0644 "$tmp/AdGuardHome/LICENSE.txt" "$dir/LICENSE.txt"
    install -m 0755 "$tmp/AdGuardHome/AdGuardHome" "$dir/AdGuardHome"
fi

config=$dir/AdGuardHome.yaml
marker=/etc/sniproxy-managed/adguard-integrated
if [[ ! -e $config ]]; then
    bind_ip=${ADGUARD_BIND_IP:-}
    if [[ -z $bind_ip ]]; then
        bind_ip=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<NF;i++) if($i=="src") {print $(i+1); exit}}')
    fi
    python3 - "$bind_ip" <<'PYTHON'
import ipaddress
import sys

try:
    addr = ipaddress.IPv4Address(sys.argv[1])
    if addr.is_unspecified or addr.is_multicast:
        raise ValueError
except ValueError:
    sys.exit("Set ADGUARD_BIND_IP to a local interface IPv4 address.")
PYTHON
    if ! ip -o -4 addr show | awk '{split($4,a,"/"); print a[1]}' | grep -Fx -- "$bind_ip" >/dev/null; then
        echo "ADGUARD_BIND_IP is not assigned to a local interface: $bind_ip" >&2
        exit 1
    fi
    if ! python3 - "$bind_ip" <<'PYTHON'
import socket
import sys

for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind((sys.argv[1], 53))
PYTHON
    then
        echo "Cannot bind DNS to $bind_ip:53; check TCP/UDP port conflicts." >&2
        exit 1
    fi
    echo "AdGuard Home DNS: $bind_ip:53. Restrict TCP/UDP 53 to trusted clients in your firewall."
    cat > "$config.tmp" <<YAML
schema_version: 34
users: []
filters:
  - id: 1
    enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
  - id: 2
    enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt
    name: AdAway Default Blocklist
http:
  address: 127.0.0.1:3000
dns:
  bind_hosts:
    - $bind_ip
  port: 53
YAML
    mv -- "$config.tmp" "$config"
    touch "$marker"
fi

install -m 0644 sniproxy-adguard.service "/etc/systemd/system/$unit"
systemctl daemon-reload
systemctl enable --now "$unit"
if ! curl -fsS --noproxy '*' --retry 5 --retry-connrefused --max-time 3 \
        -o /dev/null http://127.0.0.1:3000/; then
    echo "AdGuard Home UI did not start; check journalctl -u $unit and TCP port 3000." >&2
    exit 1
fi

systemctl is-active --quiet "$unit"

if [[ -f $marker ]]; then
    public_ip=${ADGUARD_PUBLIC_IP:-}
    if [[ -z $public_ip ]]; then
        public_ip=$(curl -4 -fLsS --noproxy '*' --proto '=https' --connect-timeout 5 \
            --max-time 10 https://checkip.amazonaws.com/)
    fi
    python3 - "$public_ip" <<'PYTHON'
import ipaddress
import json
import sys
from http.client import HTTPConnection

try:
    address = ipaddress.IPv4Address(sys.argv[1].strip())
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise ValueError
except ValueError:
    sys.exit("No valid public IPv4. Re-run with ADGUARD_PUBLIC_IP set to the server public IPv4.")

prefix = "|*^$dnsrewrite=NOERROR;A;"
rule = prefix + str(address)

def request(method, path, payload=None):
    conn = HTTPConnection("127.0.0.1", 3000, timeout=10)
    try:
        conn.request(method, "/control/filtering/" + path,
                     body=json.dumps(payload) if payload is not None else None,
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        if response.status != 200:
            sys.exit(f"AdGuard Home filtering API returned HTTP {response.status}.")
        return response.read()
    finally:
        conn.close()

rules = json.loads(request("GET", "status"))["user_rules"] or []
if any(item.strip().startswith(prefix) and item.strip() != rule for item in rules):
    sys.exit("An existing wildcard A rewrite uses a different IP; not overwritten.")
if not any(item.strip() == rule for item in rules):
    request("POST", "set_rules", {"rules": [*rules, rule]})
print(f"AdGuard Home wildcard A rewrite: {address}")
PYTHON
fi

url=/etc/sniproxy-managed/adguard-url
if [[ ! -e $url && ! -e $marker ]]; then
    printf 'http://127.0.0.1:3000/\n' > "$url"
fi
echo "AdGuard Home installed: $unit (web UI on 127.0.0.1:3000)"
