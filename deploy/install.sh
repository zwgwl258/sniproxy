#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
[[ $EUID == 0 ]] || { echo "Run with sudo." >&2; exit 1; }
[[ -d /run/systemd/system ]] && command -v apt-get >/dev/null || {
    echo "Requires Debian/Ubuntu with systemd." >&2; exit 1;
}
state=/etc/sniproxy-managed
lib=/usr/local/lib/sniproxy-managed
port=${PANEL_PORT:-9443}
bind=${PANEL_BIND:-0.0.0.0}
host=${PANEL_HOST:-$(hostname -I | awk '{print $1}')}
host=${host:-127.0.0.1}
[[ $host =~ ^[a-zA-Z0-9][a-zA-Z0-9.:-]*$ ]] || { echo "Invalid PANEL_HOST" >&2; exit 1; }
[[ $port =~ ^[1-9][0-9]{0,4}$ && $port -le 65535 ]] || { echo "Invalid PANEL_PORT" >&2; exit 1; }
[[ $bind =~ ^[0-9.]+$ ]] || { echo "PANEL_BIND must be an IPv4 address" >&2; exit 1; }
if [[ -n ${PANEL_CERT:-} || -n ${PANEL_KEY:-} ]]; then
    [[ -f ${PANEL_CERT:-} && -f ${PANEL_KEY:-} ]] || { echo "Supply both PANEL_CERT and PANEL_KEY" >&2; exit 1; }
fi

apt-get update
apt-get install -y build-essential autoconf automake libev-dev libpcre2-dev libudns-dev python3 openssl
autoreconf -fi
./configure --enable-dns
make -j"$(nproc)"
make -C tests config_test

install -d -m 0700 "$state"
install -d -m 0755 "$lib"
install -m 0755 src/sniproxy "$lib/sniproxy"
install -m 0755 tests/config_test "$lib/config-test"
install -m 0644 deploy/panel.py "$lib/panel.py"
if [[ ! -f $state/sniproxy.conf ]]; then
    install -m 0600 "${SNIPROXY_CONFIG:-deploy/default.conf}" "$state/sniproxy.conf"
fi
if [[ ! -s $state/panel-password ]]; then
    openssl rand -hex 24 > "$state/panel-password"
fi
if [[ -n ${PANEL_CERT:-} ]]; then
    install -m 0600 "$PANEL_CERT" "$state/panel.crt"
    install -m 0600 "$PANEL_KEY" "$state/panel.key"
elif [[ ! -s $state/panel.crt || ! -s $state/panel.key ]]; then
    if [[ $host =~ ^[0-9.]+$ || $host == *:* ]]; then
        san="IP:$host"
    else
        san="DNS:$host"
    fi
    openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj /CN=sniproxy-panel -addext "subjectAltName=$san" \
        -keyout "$state/panel.key" -out "$state/panel.crt"
fi
if [[ ! -f $state/panel.env || -v PANEL_BIND || -v PANEL_PORT ]]; then
    printf 'PANEL_BIND=%s\nPANEL_PORT=%s\n' "$bind" "$port" > "$state/panel.env"
fi
install -m 0644 deploy/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable sniproxy-panel.service
systemctl restart sniproxy-panel.service
sleep 1
systemctl is-active --quiet sniproxy-panel.service
if systemctl is-active --quiet sniproxy.service; then
    echo "Existing sniproxy.service left running; cut over before starting managed proxy."
else
    systemctl enable sniproxy-managed.service
    if ! systemctl restart sniproxy-managed.service || ! (sleep 1; systemctl is-active --quiet sniproxy-managed.service); then
        echo "Proxy did not start; review its configuration in the panel." >&2
    fi
fi
# This file is generated above and readable only by root.
. "$state/panel.env"
url_host=$host
[[ $host != *:* ]] || url_host="[$host]"
printf '\nPanel: https://%s:%s/ (bind: %s)\nUser: admin\nPassword: sudo cat %s/panel-password\n' "$url_host" "$PANEL_PORT" "$PANEL_BIND" "$state"
openssl x509 -in "$state/panel.crt" -noout -fingerprint -sha256
