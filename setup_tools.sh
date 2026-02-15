#!/usr/bin/env bash
set -euo pipefail
# DroidSec Tools Downloader
# This script downloads the necessary analysis tools (apktool, jadx).

TOOLS_DIR="$(cd "$(dirname "$0")" && pwd)/tools"
mkdir -p "$TOOLS_DIR"

echo "📥 Setting up DroidSec analysis tools..."

# 1. Download apktool.jar
if [ ! -f "$TOOLS_DIR/apktool.jar" ]; then
    echo "Downloading apktool v2.9.3..."
    curl -fL --retry 3 --retry-delay 2 \
      https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar \
      -o "$TOOLS_DIR/apktool.jar"
fi

# 2. Setup apktool wrapper
if [ ! -f "$TOOLS_DIR/apktool" ]; then
    echo "Creating apktool wrapper..."
    cat > "$TOOLS_DIR/apktool" <<EOF
#!/bin/bash
java -jar "\$(dirname "\$0")/apktool.jar" "\$@"
EOF
    chmod +x "$TOOLS_DIR/apktool"
fi

# 3. Download JADX
if [ ! -d "$TOOLS_DIR/jadx" ]; then
    echo "Downloading JADX v1.5.1..."
    curl -fL --retry 3 --retry-delay 2 \
      https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip \
      -o "$TOOLS_DIR/jadx.zip"
    unzip -q "$TOOLS_DIR/jadx.zip" -d "$TOOLS_DIR/jadx"
    rm "$TOOLS_DIR/jadx.zip"
    chmod +x "$TOOLS_DIR/jadx/bin/jadx"
fi

if [ ! -f "$TOOLS_DIR/apktool.jar" ] || [ ! -x "$TOOLS_DIR/apktool" ]; then
    echo "❌ apktool setup failed"
    exit 1
fi

if [ ! -x "$TOOLS_DIR/jadx/bin/jadx" ]; then
    echo "❌ JADX setup failed"
    exit 1
fi

# Validate executables so deployment fails fast if tooling is broken.
java -jar "$TOOLS_DIR/apktool.jar" --version >/dev/null
"$TOOLS_DIR/jadx/bin/jadx" --version >/dev/null

echo "✅ All tools ready in $TOOLS_DIR"
