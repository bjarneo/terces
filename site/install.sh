#!/bin/sh
# Installs the latest terces release for macOS or Linux.
#
#   curl -sSfL https://bjarneo.github.io/terces/install.sh | sh
#
# The script checks the archive against SHA256SUMS before it installs.
# It installs to /usr/local/bin, which is on the PATH by default, and asks
# for sudo only when that directory is not writable. Without
# /usr/local/bin, or without sudo, it installs to ~/.local/bin.
# Set TERCES_INSTALL_DIR to install to another directory.
set -eu

repo="bjarneo/terces"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
linux | darwin) ;;
*) echo "terces: no release for $os. Build from source: https://github.com/$repo" >&2; exit 1 ;;
esac
arch=$(uname -m)
case "$arch" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) echo "terces: no release for $arch. Build from source: https://github.com/$repo" >&2; exit 1 ;;
esac

name="terces_${os}_${arch}.tar.gz"
base="https://github.com/$repo/releases/latest/download"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -sSfL -o "$tmp/$name" "$base/$name"
curl -sSfL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"

expected=$(grep " $name\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
if command -v sha256sum > /dev/null 2>&1; then
	actual=$(sha256sum "$tmp/$name" | cut -d' ' -f1)
else
	actual=$(shasum -a 256 "$tmp/$name" | cut -d' ' -f1)
fi
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
	echo "terces: the checksum of $name does not match SHA256SUMS. Nothing was installed." >&2
	exit 1
fi

tar -xzf "$tmp/$name" -C "$tmp" terces
chmod 0755 "$tmp/terces"

# install_to moves the binary into a directory. It uses sudo only when
# the directory is not writable.
install_to() {
	if [ -w "$1" ]; then
		mv "$tmp/terces" "$1/terces"
	elif command -v sudo > /dev/null 2>&1; then
		echo "Installing to $1 needs sudo."
		sudo mv "$tmp/terces" "$1/terces"
	else
		return 1
	fi
}

if [ -n "${TERCES_INSTALL_DIR:-}" ]; then
	dir=$TERCES_INSTALL_DIR
	mkdir -p "$dir"
	install_to "$dir"
elif [ -d /usr/local/bin ] && install_to /usr/local/bin; then
	dir=/usr/local/bin
else
	dir="$HOME/.local/bin"
	[ -d /usr/local/bin ] && echo "Could not install to /usr/local/bin. Installing to $dir."
	mkdir -p "$dir"
	mv "$tmp/terces" "$dir/terces"
fi
echo "Installed $("$dir/terces" --version) to $dir/terces"
case ":$PATH:" in
*":$dir:"*) ;;
*) echo "Add $dir to your PATH, or run $dir/terces." ;;
esac
