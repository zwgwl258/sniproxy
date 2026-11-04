#!/usr/bin/env bash
set -euo pipefail
umask 077

archive_url='https://codeload.github.com/zwgwl258/sniproxy/tar.gz/4224e66b61d46cd1ca2b8d54ba4f2c11bd83bc08'
archive_sha256='2d4eadf7f5d9ab38ad661750b256320acb57fbb06a2d9602834dc0fe9a4fbcc6'

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
