#!/bin/bash
set -euo pipefail
OCMOCK_VERSION="3.8.1"
DEST_DIR="$(cd "$(dirname "$0")" && pwd)/OCMock.xcframework"

if [ -d "$DEST_DIR" ]; then
  echo "OCMock already present at $DEST_DIR"
  exit 0
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

ARCHIVE="OCMock-$OCMOCK_VERSION.tar.gz"
URL="https://github.com/erikdoe/ocmock/releases/download/v$OCMOCK_VERSION/$ARCHIVE"

echo "Downloading OCMock $OCMOCK_VERSION..."
curl -L "$URL" -o "$tmpdir/$ARCHIVE"

echo "Extracting..."
tar -xzf "$tmpdir/$ARCHIVE" -C "$tmpdir"

SRC_PATH=$(find "$tmpdir" -name 'OCMock.xcframework' -type d | head -n 1)
if [ -z "$SRC_PATH" ]; then
  echo "OCMock.xcframework not found in archive" >&2
  exit 1
fi

mkdir -p "$(dirname "$DEST_DIR")"
cp -R "$SRC_PATH" "$DEST_DIR"

echo "Installed OCMock to $DEST_DIR"
