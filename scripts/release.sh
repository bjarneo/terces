#!/usr/bin/env bash
# release.sh builds the release archives into dist/: one terces binary for
# each of macOS and Linux on amd64 and arm64, plus SHA256SUMS.
#
# Usage: scripts/release.sh v0.1.0
set -euo pipefail

version=${1:?usage: scripts/release.sh <version>}
root=$(cd "$(dirname "$0")/.." && pwd)
dist="$root/dist"
rm -rf "$dist"
mkdir -p "$dist"
cd "$root"

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
	os=${target%/*}
	arch=${target#*/}
	name="terces_${os}_${arch}"
	stage="$dist/$name"
	mkdir -p "$stage"
	CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
		-ldflags "-s -w -X main.version=$version" -o "$stage/terces" ./cmd/terces
	cp LICENSE README.md "$stage/"
	tar -C "$stage" --owner=0 --group=0 --numeric-owner -czf "$dist/$name.tar.gz" terces LICENSE README.md
	rm -rf "$stage"
	echo "built $name.tar.gz"
done

(cd "$dist" && sha256sum ./*.tar.gz | sed 's| \./| |' > SHA256SUMS)
cat "$dist/SHA256SUMS"
