#!/bin/bash
# Simple Mininet Installation for Ubuntu 24.04
# Chapter 3: Mininet Setup

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC} $1"; }

echo "=========================================="
echo "Chapter 3: Mininet Installation"
echo "=========================================="
echo ""

# Do not run as root
if [ "${EUID}" -eq 0 ]; then
  err "Do not run as root. Run as ubuntu user."
  exit 1
fi

# Ubuntu check
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
  err "Ubuntu required. Detected: ${ID:-unknown}"
  exit 1
fi

ok "Detected Ubuntu ${VERSION_ID:-unknown}"

# Update packages
ok "Updating package lists..."
sudo apt update -y

# Install Mininet and Open vSwitch
ok "Installing Mininet and Open vSwitch..."
sudo apt install -y mininet openvswitch-switch openvswitch-common iproute2 iputils-ping

# Enable and start Open vSwitch
ok "Enabling and starting Open vSwitch service..."
sudo systemctl enable --now openvswitch-switch

# Clean any previous Mininet state
ok "Cleaning any previous Mininet state..."
sudo mn -c >/dev/null 2>&1 || true

# Verify installation
ok "Verifying installation..."
if ! command -v mn >/dev/null 2>&1; then
  err "mn command not found. Installation failed."
  exit 1
fi

echo ""
ok "Mininet version:"
mn --version || true

echo ""
ok "Open vSwitch version:"
ovs-vsctl --version | head -n 1 || true

echo ""
echo "=========================================="
ok "Mininet Installation Complete!"
echo "=========================================="