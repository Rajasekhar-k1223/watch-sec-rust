#!/bin/bash
# Rust Cross-Platform Build Pipeline

set -e

APP_NAME="agent-rust"
OUTPUT_DIR="./dist"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

echo "=== Starting Cross-Platform Builds (Rust) ==="

# Define targets
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "x86_64-pc-windows-gnu"
    "i686-pc-windows-gnu"
)

for target in "${TARGETS[@]}"; do
    EXT=""
    if [[ "$target" == *"windows"* ]]; then
        EXT=".exe"
    fi
    
    echo "[BUILD] Building for $target -> ${OUTPUT_DIR}/${APP_NAME}-${target}${EXT}"
    cargo build --release --target "$target"
    
    # Copy to dist
    cp "target/${target}/release/${APP_NAME}${EXT}" "${OUTPUT_DIR}/${APP_NAME}-${target}${EXT}"
done

echo "=== Build Complete ==="
