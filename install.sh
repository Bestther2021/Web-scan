#!/usr/bin/env bash
# install.sh - install ws to /usr/local/bin
set -e
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="/usr/local/bin/ws"
if [ ! -f "$SRC_DIR/ws" ]; then
  echo "Error: ws file not found in $SRC_DIR"
  exit 1
fi
sudo cp "$SRC_DIR/ws" "$TARGET"
sudo chmod +x "$TARGET"
 echo "Installed ws -> $TARGET"
