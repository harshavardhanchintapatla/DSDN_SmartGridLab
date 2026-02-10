#!/bin/bash
# Tshark Installation for Traffic Capture
# Part of Chapter 4: DNP3 Setup

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
echo "Tshark Installation for Traffic Capture"
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

# Install tshark and related tools
ok "Installing tshark, tcpdump, and jq..."
sudo apt install -y tshark tcpdump jq

# Configure wireshark-common for non-root capture
ok "Configuring Wireshark for non-root packet capture..."
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive dpkg-reconfigure wireshark-common

# Add current user to wireshark group
CURRENT_USER="${USER}"
ok "Adding user '${CURRENT_USER}' to wireshark group..."
sudo usermod -a -G wireshark "${CURRENT_USER}"

# Verify installation
echo ""
ok "Verifying installation..."
if ! command -v tshark >/dev/null 2>&1; then
  err "tshark command not found. Installation failed."
  exit 1
fi

echo ""
ok "Tshark version:"
tshark -v | head -n 1

echo ""
ok "Available capture interfaces:"
tshark -D || warn "Could not list interfaces (group change requires logout/login)"

# Check if user is in wireshark group
if groups "${CURRENT_USER}" | grep -q wireshark; then
  ok "User '${CURRENT_USER}' is in wireshark group"
else
  warn "User '${CURRENT_USER}' not yet in wireshark group (requires new session)"
fi

echo ""
echo "=========================================="
ok "Tshark Installation Complete!"
echo "=========================================="
echo ""
echo "=========================================="
echo "Capture DNP3 Traffic (after DNP3 setup):"
echo "=========================================="
echo ""
echo "Run this command to capture and display DNP3 traffic:"
echo ""
echo "${GREEN}sudo tshark -l -i any -f 'tcp portrange 20002-20024' \\
  -d tcp.port==20002,dnp3 -d tcp.port==20003,dnp3 -d tcp.port==20004,dnp3 \\
  -d tcp.port==20005,dnp3 -d tcp.port==20006,dnp3 -d tcp.port==20007,dnp3 \\
  -d tcp.port==20008,dnp3 -d tcp.port==20009,dnp3 -d tcp.port==20010,dnp3 \\
  -d tcp.port==20011,dnp3 -d tcp.port==20012,dnp3 -d tcp.port==20013,dnp3 \\
  -d tcp.port==20014,dnp3 -d tcp.port==20015,dnp3 -d tcp.port==20016,dnp3 \\
  -d tcp.port==20017,dnp3 -d tcp.port==20018,dnp3 -d tcp.port==20019,dnp3 \\
  -d tcp.port==20020,dnp3 -d tcp.port==20021,dnp3 -d tcp.port==20022,dnp3 \\
  -d tcp.port==20023,dnp3 -d tcp.port==20024,dnp3 \\
  -Y 'dnp3' \\
  -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \\
  -e dnp3.al.func -e dnp3.al.seq -e dnp3.al.iin -e dnp3.al.uns${NC}"
echo ""
echo "This captures DNP3 traffic on ports 20002-20024 and displays:"
echo "  - Timestamp, Source IP, Destination IP"
echo "  - Source/Destination ports"
echo "  - DNP3 function code, sequence number, flags"
echo ""
echo "Press Ctrl+C to stop capturing"
echo ""
echo "Next: Continue with DNP3 installation"
echo "=========================================="