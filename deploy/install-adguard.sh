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
    cat > "$config.tmp" <<'YAML'
schema_version: 34
users: []
http:
  address: 127.0.0.1:3000
dns:
  bind_hosts:
    - 127.0.0.1
  port: 5353
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

url=/etc/sniproxy-managed/adguard-url
if [[ ! -e $url && ! -e $marker ]]; then
    printf 'http://127.0.0.1:3000/\n' > "$url"
fi
echo "AdGuard Home installed: $unit (web UI on 127.0.0.1:3000)"
