#!/usr/bin/env bash
set -e
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="/usr/local/bin/ws"

if [ ! -f "$SRC_DIR/ws" ]; then
  echo "Error: ws not found in $SRC_DIR"
  exit 1
fi

echo "Installing ws to $TARGET"
if [ ! -w "$(dirname "$TARGET")" ]; then
  echo "Need sudo to copy to $TARGET"
  sudo cp "$SRC_DIR/ws" "$TARGET"
  sudo chmod +x "$TARGET"
else
  cp "$SRC_DIR/ws" "$TARGET"
  chmod +x "$TARGET"
fi

echo "Done. You can now run: ws http://example.com"
