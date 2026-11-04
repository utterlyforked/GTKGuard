#!/bin/sh
# Install GTKGuard for the current user (no root needed).
# Build first (in the toolbox):  cargo build --release
set -eu
cd "$(dirname "$0")"

id=io.github.utterlyforked.GtkGuard
bin=target/release/gtkguard
[ -x "$bin" ] || { echo "Build first: cargo build --release" >&2; exit 1; }

install -Dm755 "$bin" "$HOME/.local/bin/gtkguard"
install -Dm644 "data/$id.desktop" "$HOME/.local/share/applications/$id.desktop"
install -Dm644 "data/icons/hicolor/scalable/apps/$id.svg" \
    "$HOME/.local/share/icons/hicolor/scalable/apps/$id.svg"

echo "Installed. Binary: ~/.local/bin/gtkguard (make sure ~/.local/bin is in PATH)."
