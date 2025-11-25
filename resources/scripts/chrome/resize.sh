#!/bin/bash
# resize - Generate icons for the chrome extension
# Usage: ./resize path/to/image.png

# Exit if no argument provided
if [ -z "$1" ]; then
    echo "Usage: $0 path/to/image.{png,jpg,svg,...}"
    exit 1
fi

SRC_FILE="$1"

# Ensure ImageMagick is installed
if ! command -v convert &> /dev/null; then
    echo "ImageMagick not found. Please install it:"
    echo "  brew install imagemagick"
    exit 1
fi

# Ensure the source file exists
if [ ! -f "$SRC_FILE" ]; then
    echo "Error: file '$SRC_FILE' not found."
    exit 1
fi

# Output directory (optional)
OUT_DIR="./icons"
mkdir -p "$OUT_DIR"

# Generate PNG icons with standardized filenames
convert -background transparent "$SRC_FILE" -resize 16x16  "$OUT_DIR/icon-16.png"
convert -background transparent "$SRC_FILE" -resize 48x48  "$OUT_DIR/icon-48.png"
convert -background transparent "$SRC_FILE" -resize 128x128 "$OUT_DIR/icon-128.png"

echo "Icons generated successfully in: $OUT_DIR"