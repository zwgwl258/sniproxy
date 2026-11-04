#!/usr/bin/env bash
set -euo pipefail
umask 077

archive_url='https://codeload.github.com/zwgwl258/sniproxy/tar.gz/a75393f8577cf49fb2c3984f663d9bea75105817'
archive_sha256='bbc75948944fdacbfb6fd96cdda9b46d690b4ae7f1d60729898746d0a9dd23e7'

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
curl -fLsS --retry 3 --proto '=https' "$archive_url" -o "$work/source.tar.gz"
printf '%s  %s\n' "$archive_sha256" "$work/source.tar.gz" | sha256sum -c -
tar -xzf "$work/source.tar.gz" --strip-components=1 -C "$work"
if (( EUID == 0 )); then
    bash "$work/deploy/install.sh"
else
    sudo bash "$work/deploy/install.sh"
fi
