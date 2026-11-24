#!/bin/sh
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -gt 1 ]; then
    echo 'Использование: install-astra-fly.sh [путь/к/libaldcrypto.so]' >&2
    exit 2
fi
plugin=${1:-"$project/lib/libaldcrypto.so"}
root=${DESTDIR:-}
install_dir=$root/usr/local/libexec/vault-lab
actions=$root/usr/share/flyfm/actions
mime=$root/usr/share/mime
if [ ! -x "$project/target/release/vault-lab" ]; then
    echo 'Сначала выполните cargo build --release --locked из корня проекта.' >&2
    exit 1
fi
if [ -z "$root" ]; then
    for tool in /usr/bin/x-terminal-emulator /usr/bin/fly-fm /usr/bin/python3 /usr/bin/sudo /bin/umount; do
        [ -x "$tool" ] || { echo "Отсутствует $tool" >&2; exit 1; }
    done
fi
# Compare ELF requirements without executing either input as root.
host_glibc=$(getconf GNU_LIBC_VERSION)
for elf in "$plugin" "$project/target/release/vault-lab"; do
    versions=$(LC_ALL=C readelf -WV "$elf")
    required=$(echo "$versions" | sed -n 's/.*Name: GLIBC_\([0-9.]*\) .*/\1/p' | sort -V | tail -1)
    host=${host_glibc#glibc }
    if [ -n "$required" ] && [ "$(printf '%s\n' "$required" "$host" | sort -V | tail -1)" != "$host" ]; then
        echo "$elf требует GLIBC $required. Здесь установлена $host_glibc." >&2
        exit 1
    fi
done
install -D -m 0755 "$project/target/release/vault-lab" "$install_dir/vault-lab"
install -m 0644 "$plugin" "$install_dir/libaldcrypto.so"
install -m 0755 "$project/desktop/astra/fly-action" "$install_dir/fly-action"
install -D -m 0644 "$project/desktop/astra/vault-lab-sbox.xml" "$mime/packages/vault-lab-sbox.xml"
update-mime-database "$mime"
install -D -m 0644 "$project/desktop/astra/vault-lab-fly.desktop" "$actions/vault-lab-fly.desktop"
