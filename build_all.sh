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
        echo "[SIGN] Signing ${APP_NAME}-${target}${EXT} with publisher certificates..."
        WIN_DIR="/opt/projects/monitorix/watch-sec-python/backend/storage/AgentTemplate/win-x64"
        mkdir -p "$WIN_DIR"
        rm -f "${WIN_DIR}/monitorix-agent.exe"
        osslsigncode sign -certs /opt/projects/monitorix/certs/monitorix-publisher.crt -key /opt/projects/monitorix/certs/monitorix-publisher.key -n "Monitorix Agent" -i "https://monitorix.elsea.co.in" -in "target/${target}/release/monitorix-agent${EXT}" -out "${WIN_DIR}/monitorix-agent.exe"
        
        # Generate RSA .sig file for agent verification
        openssl dgst -sha256 -sign /opt/projects/monitorix/certs/monitorix-publisher.key "${WIN_DIR}/monitorix-agent.exe" > "${WIN_DIR}/monitorix-agent.exe.sig.raw"
        xxd -p -c 999 "${WIN_DIR}/monitorix-agent.exe.sig.raw" > "${WIN_DIR}/monitorix-agent.exe.sig"
        rm -f "${WIN_DIR}/monitorix-agent.exe.sig.raw"
    else
        # Copy to dist for non-windows
        LINUX_DIR="/opt/projects/monitorix/watch-sec-python/backend/storage/AgentTemplate/linux-x64"
        mkdir -p "$LINUX_DIR"
        cp "target/${target}/release/monitorix-agent${EXT}" "${LINUX_DIR}/monitorix-agent-linux"
        
        # Generate RSA .sig file for agent verification
        openssl dgst -sha256 -sign /opt/projects/monitorix/certs/monitorix-publisher.key "${LINUX_DIR}/monitorix-agent-linux" > "${LINUX_DIR}/monitorix-agent-linux.sig.raw"
        xxd -p -c 999 "${LINUX_DIR}/monitorix-agent-linux.sig.raw" > "${LINUX_DIR}/monitorix-agent-linux.sig"
        rm -f "${LINUX_DIR}/monitorix-agent-linux.sig.raw"
    fi
done

echo "=== Build Complete ==="
