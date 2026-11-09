#!/bin/bash
# Monitorix Rust Sovereign Cross-Platform Build & Packaging Pipeline
set -e

APP_NAME="agent-rust"
OUTPUT_DIR="./dist"
CERT_DIR="/opt/projects/monitorix/certs"
BACKEND_STORAGE="/opt/projects/monitorix/watch-sec-python/backend/storage/AgentTemplate"
PYTHON_STORAGE="/opt/projects/monitorix/watch-sec-python/storage/AgentTemplate"
ROOT_AGENT_BIN="/opt/projects/monitorix/monitorix-agent/bin"

mkdir -p "$OUTPUT_DIR"
mkdir -p "${BACKEND_STORAGE}/win-x64" "${BACKEND_STORAGE}/win-x86" "${BACKEND_STORAGE}/linux-x64"
mkdir -p "${PYTHON_STORAGE}/win-x64" "${PYTHON_STORAGE}/linux-x64"
mkdir -p "$ROOT_AGENT_BIN"

echo "=== Starting Sovereign Cross-Platform Builds (Monitorix Agent) ==="

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
    
    echo "[BUILD] Building release for $target..."
    cargo build --release --target "$target"
    
    SRC_BIN="target/${target}/release/monitorix-agent${EXT}"
    DIST_BIN="${OUTPUT_DIR}/${APP_NAME}-${target}${EXT}"
    
    echo "[COPY] Staging to $DIST_BIN"
    cp "$SRC_BIN" "$DIST_BIN"
    
    if [[ "$target" == "x86_64-pc-windows-gnu" ]]; then
        SIGNED_EXE="target/${target}/release/monitorix-agent-signed.exe"
        echo "[SIGN] Signing $SIGNED_EXE with Monitorix Sovereign Publisher Certificate..."
        rm -f "$SIGNED_EXE"
        osslsigncode sign \
            -certs "${CERT_DIR}/monitorix-publisher.crt" \
            -key "${CERT_DIR}/monitorix-publisher.key" \
            -n "Monitorix Agent" \
            -i "https://monitorix.co.in" \
            -in "$SRC_BIN" \
            -out "$SIGNED_EXE"
            
        openssl dgst -sha256 -sign "${CERT_DIR}/monitorix-publisher.key" "$SIGNED_EXE" > "${SIGNED_EXE}.sig.raw"
        xxd -p -c 999 "${SIGNED_EXE}.sig.raw" > "${SIGNED_EXE}.sig"
        rm -f "${SIGNED_EXE}.sig.raw"
        
        # Stage signed binary to templates
        cp "$SIGNED_EXE" "${BACKEND_STORAGE}/win-x64/monitorix-agent.exe"
        cp "${SIGNED_EXE}.sig" "${BACKEND_STORAGE}/win-x64/monitorix-agent.exe.sig"
        cp "$SIGNED_EXE" "${PYTHON_STORAGE}/win-x64/monitorix-agent.exe"
        cp "$SIGNED_EXE" "/opt/projects/monitorix/watch-sec-python/backend/monitorix-agent.exe"
        
    elif [[ "$target" == "i686-pc-windows-gnu" ]]; then
        SIGNED_EXE="target/${target}/release/monitorix-agent-signed.exe"
        echo "[SIGN] Signing $SIGNED_EXE (32-bit)..."
        rm -f "$SIGNED_EXE"
        osslsigncode sign \
            -certs "${CERT_DIR}/monitorix-publisher.crt" \
            -key "${CERT_DIR}/monitorix-publisher.key" \
            -n "Monitorix Agent (x86)" \
            -i "https://monitorix.co.in" \
            -in "$SRC_BIN" \
            -out "$SIGNED_EXE"
            
        openssl dgst -sha256 -sign "${CERT_DIR}/monitorix-publisher.key" "$SIGNED_EXE" > "${SIGNED_EXE}.sig.raw"
        xxd -p -c 999 "${SIGNED_EXE}.sig.raw" > "${SIGNED_EXE}.sig"
        rm -f "${SIGNED_EXE}.sig.raw"
        
        cp "$SIGNED_EXE" "${BACKEND_STORAGE}/win-x86/monitorix-agent.exe"
        cp "${SIGNED_EXE}.sig" "${BACKEND_STORAGE}/win-x86/monitorix-agent.exe.sig"
        
    else
        # Linux x86_64
        SIG_FILE="target/${target}/release/monitorix-agent.sig"
        echo "[SIGN] Generating SHA-256 signature for Linux agent: $SIG_FILE"
        openssl dgst -sha256 -sign "${CERT_DIR}/monitorix-publisher.key" "$SRC_BIN" > "${SIG_FILE}.raw"
        xxd -p -c 999 "${SIG_FILE}.raw" > "$SIG_FILE"
        rm -f "${SIG_FILE}.raw"
        
        cp "$SRC_BIN" "${BACKEND_STORAGE}/linux-x64/monitorix-agent-rust-linux"
        cp "$SIG_FILE" "${BACKEND_STORAGE}/linux-x64/monitorix-agent-rust-linux.sig"
        cp "$SRC_BIN" "${PYTHON_STORAGE}/linux-x64/monitorix-agent-rust-linux"
        cp "$SRC_BIN" "${ROOT_AGENT_BIN}/monitorix-agent-rust-linux"
    fi
done

echo "=== Build & Staging Complete ==="

