#!/usr/bin/env bash
set -euo pipefail
umask 077

archive_url='https://codeload.github.com/zwgwl258/sniproxy/tar.gz/9716d04fbf84f992d2fc3bd5d3313c54cc280c1e'
archive_sha256='a9c60ae297fed3f05a343f487921d8b70ccc81b5de875134be4fa2a58c9f6bb8'

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
