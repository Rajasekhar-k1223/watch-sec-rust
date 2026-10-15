#!/bin/bash
set -e

# ============================================================
# Monitorix Agent Build & Sign Script
# Builds for: Windows (x64), Linux (x64), macOS (arm64/x64)
# Signs all binaries with RSA-SHA256 using the publisher cert
# ============================================================

export PATH="$HOME/.cargo/bin:$PATH"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="/opt/projects/monitorix/certs"
STORAGE_DIR="/opt/projects/monitorix/watch-sec-python/backend/storage/AgentTemplate"
KEY_FILE="$CERTS_DIR/monitorix-publisher.key"
CERT_FILE="$CERTS_DIR/monitorix-publisher.crt"
PFX_FILE="$CERTS_DIR/monitorix-publisher.pfx"

cd "$SCRIPT_DIR"

# ────────────────────────────────────────────────────────────
# 1. Ensure Publisher Certificate Exists
# ────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "[1/5] Checking Publisher Certificate"
echo "══════════════════════════════════════════════════════"
mkdir -p "$CERTS_DIR"

if [ ! -f "$PFX_FILE" ]; then
    echo "[*] Generating new RSA-4096 self-signed publisher certificate..."
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -days 3650 -nodes \
        -subj "/CN=Elsea Monitorix Security/O=Elsea/OU=AgentPublisher/C=IN"
    openssl pkcs12 -export \
        -out "$PFX_FILE" \
        -inkey "$KEY_FILE" \
        -in "$CERT_FILE" \
        -passout pass:monitorix123
    echo "[+] Certificate generated: $CERT_FILE"
else
    echo "[+] Using existing certificate: $CERT_FILE"
    openssl x509 -in "$CERT_FILE" -noout -subject -enddate
fi

# ────────────────────────────────────────────────────────────
# Helper: Sign a binary with RSA-SHA256 and save the .sig file
# ────────────────────────────────────────────────────────────
sign_binary() {
    local bin="$1"
    local sig_file="${bin}.sig"
    echo "[*] Signing: $bin"
    openssl dgst -sha256 -sign "$KEY_FILE" -out "$sig_file.bin" "$bin"
    # Convert binary signature to hex string for embedding in server responses
    xxd -p -c 999 "$sig_file.bin" | tr -d '\n' > "$sig_file"
    rm -f "$sig_file.bin"
    echo "[+] Signature saved: $sig_file ($(wc -c < "$sig_file") bytes)"
}

# ────────────────────────────────────────────────────────────
# 2. Build Windows (x86_64)
# ────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "[2/5] Building Windows Agent (x86_64)"
echo "══════════════════════════════════════════════════════"
cargo build --release --target x86_64-pc-windows-gnu
WIN_RAW="target/x86_64-pc-windows-gnu/release/monitorix-agent.exe"
WIN_SIGNED="target/x86_64-pc-windows-gnu/release/monitorix-agent-signed.exe"

# Sign with osslsigncode (Authenticode — for Windows SmartScreen compatibility)
if command -v osslsigncode &>/dev/null; then
    echo "[*] Applying Authenticode signature with osslsigncode..."
    rm -f "$WIN_SIGNED"
    osslsigncode sign \
        -pkcs12 "$PFX_FILE" \
        -pass monitorix123 \
        -n "Monitorix Enterprise Agent" \
        -i "https://monitorix.elsea.co.in" \
        -in "$WIN_RAW" \
        -out "$WIN_SIGNED"
    echo "[+] Authenticode signed: $WIN_SIGNED"
else
    echo "[!] osslsigncode not found — skipping Authenticode signing"
    cp "$WIN_RAW" "$WIN_SIGNED"
fi

# Also create RSA-SHA256 detached signature for agent OTA verification
sign_binary "$WIN_SIGNED"

mkdir -p "$STORAGE_DIR/win-x64"
cp "$WIN_SIGNED" "$STORAGE_DIR/win-x64/monitorix-agent.exe"
cp "${WIN_SIGNED}.sig" "$STORAGE_DIR/win-x64/monitorix-agent.exe.sig"
echo "[+] Windows binary deployed to storage."

# ────────────────────────────────────────────────────────────
# 3. Build Linux x86_64
# ────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "[3/5] Building Linux Agent (x86_64)"
echo "══════════════════════════════════════════════════════"
cargo build --release --target x86_64-unknown-linux-gnu
LINUX_BIN="target/x86_64-unknown-linux-gnu/release/monitorix-agent"
sign_binary "$LINUX_BIN"

mkdir -p "$STORAGE_DIR/linux-x64"
cp "$LINUX_BIN" "$STORAGE_DIR/linux-x64/monitorix-agent-rust-linux"
cp "${LINUX_BIN}.sig" "$STORAGE_DIR/linux-x64/monitorix-agent-rust-linux.sig"
echo "[+] Linux x64 binary deployed to storage."

# ────────────────────────────────────────────────────────────
# 4. Build macOS arm64 (aarch64-apple-darwin)
# ────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "[4/5] Building macOS Agent (arm64)"
echo "══════════════════════════════════════════════════════"
if rustup target list --installed | grep -q "aarch64-apple-darwin"; then
    if cargo build --release --target aarch64-apple-darwin 2>&1 | tail -3; then
        MAC_BIN="target/aarch64-apple-darwin/release/monitorix-agent"
        if [ -f "$MAC_BIN" ]; then
            sign_binary "$MAC_BIN"
            mkdir -p "$STORAGE_DIR/osx-arm64"
            cp "$MAC_BIN" "$STORAGE_DIR/osx-arm64/monitorix-agent-mac"
            cp "${MAC_BIN}.sig" "$STORAGE_DIR/osx-arm64/monitorix-agent-mac.sig"
            echo "[+] macOS arm64 binary deployed to storage."
        else
            echo "[!] macOS arm64 build output not found — skipping deploy."
        fi
    else
        echo "[!] macOS arm64 build failed — skipping."
    fi
else
    echo "[!] aarch64-apple-darwin target not installed. Run: rustup target add aarch64-apple-darwin"
fi

# ────────────────────────────────────────────────────────────
# 5. Summary
# ────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "[5/5] Build Complete — Deployed Binaries:"
echo "══════════════════════════════════════════════════════"
for dir in "$STORAGE_DIR"/*/; do
    echo ""
    echo "  📁 $dir"
    ls -lh "$dir" 2>/dev/null | grep -v "^total" | awk '{print "     " $5 "  " $9}'
done

echo ""
echo "════════════════════════════════════════════════════════"
echo " Publisher Cert: CN=Elsea Monitorix Security, O=Elsea"
echo " Algorithm     : RSA-4096 + SHA-256"
echo " Valid Until   : $(openssl x509 -in "$CERT_FILE" -noout -enddate 2>/dev/null | cut -d= -f2)"
echo "════════════════════════════════════════════════════════"
echo " All .sig files contain the hex RSA-SHA256 signature"
echo " that each agent's verify.rs will validate on OTA update."
echo "════════════════════════════════════════════════════════"
