#!/usr/bin/env bash
set -euo pipefail
umask 077

archive_url='https://codeload.github.com/zwgwl258/sniproxy/tar.gz/3d3fcfae6931e2fac56c2b7c871aaeff1670d7cd'
archive_sha256='3585233577c7c2e9de09f49bc6f47837009310fe24281456c92ddf747705d207'

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
