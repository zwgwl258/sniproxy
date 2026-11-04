#!/usr/bin/env bash
set -euo pipefail
umask 077

archive_url='https://codeload.github.com/zwgwl258/sniproxy/tar.gz/b689d6d30bff8d2a7fa603df6a86a8f8571154a4'
archive_sha256='bd8b8257ceac0f0265e85d4caf478ea34f6aab83f1b12a623d9c4f97a039f7d7'

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
