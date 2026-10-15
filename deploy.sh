#!/bin/bash
set -e

echo "[*] Building Monitorix Rust Agent (Linux)..."
cargo build --release

echo "[*] 1. Deploying to LOCAL agent (Dev Environment)..."
systemctl stop monitorix-agent 2>/dev/null || true
killall -9 monitorix-agent-rust-linux 2>/dev/null || true
cp target/release/monitorix-agent /opt/monitorix-agent/monitorix-agent-rust-linux
systemctl start monitorix-agent
echo "    -> Local agent updated and restarted successfully."

echo "[*] 2. Deploying to BACKEND Payload Directory (for new Linux installs)..."
DIST_DIR="/opt/projects/monitorix/monitorix-agent/bin"
mkdir -p "$DIST_DIR"
cp target/release/monitorix-agent "$DIST_DIR/monitorix-agent-rust-linux"
echo "    -> Distribution payload updated successfully."

echo "[+] Deployment complete! Any new Linux server running the installer will now get this version."
