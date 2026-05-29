#!/bin/sh
# Regenerate debian/brightdate-rust-VERSION.tar.xz from the git submodule.
# Run after bumping debian/brightdate-rust-version or updating the submodule.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
VERSION=$(tr -d '[:space:]' < "$ROOT/debian/brightdate-rust-version")
SRC="$ROOT/brightdate-rust"
OUT="$ROOT/debian/brightdate-rust-${VERSION}.tar.xz"

if [ ! -f "$SRC/crates/btime/src/color.rs" ]; then
	echo "brightdate-rust submodule missing; run: git submodule update --init brightdate-rust" >&2
	exit 1
fi

if [ ! -d "$SRC/vendor" ]; then
	echo "brightdate-rust/vendor missing; run: (cd brightdate-rust && cargo vendor vendor)" >&2
	exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

mkdir "$tmp/brightdate-rust"
tar -C "$SRC" \
	--exclude=target \
	--exclude=.git \
	--exclude=homebrew-tap \
	-cf - \
	Cargo.toml Cargo.lock crates vendor .cargo 2>/dev/null \
	| tar -C "$tmp/brightdate-rust" -xf -

XZ_OPT=-9 tar -C "$tmp" -cJf "$OUT" brightdate-rust
echo "Wrote $OUT ($(du -h "$OUT" | awk '{print $1}'))"
