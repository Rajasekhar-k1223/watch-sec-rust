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
    
    if [[ "$target" == *"windows"* ]]; then
        echo "[SIGN] Signing ${APP_NAME}-${target}${EXT} with Monitorix Publisher Certificate..."
        rm -f "${OUTPUT_DIR}/${APP_NAME}-${target}${EXT}"
        osslsigncode sign \
            -certs /opt/apps/monitorix/certs/codesign/codesign.crt \
            -key /opt/apps/monitorix/certs/codesign/codesign.key \
            -n "Monitorix Agent" \
            -i "https://monitorix.local" \
            -in "target/${target}/release/${APP_NAME}${EXT}" \
            -out "${OUTPUT_DIR}/${APP_NAME}-${target}${EXT}"
    else
        # Copy to dist for non-windows
        cp "target/${target}/release/${APP_NAME}${EXT}" "${OUTPUT_DIR}/${APP_NAME}-${target}${EXT}"
    fi
done

echo "=== Build Complete ==="
