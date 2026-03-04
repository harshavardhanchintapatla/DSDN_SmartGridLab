#!/bin/bash
# Ollama LLM Installation for GridLLM Project
# Chapter 4: LLM Setup (Part 2)

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
echo "Chapter 4: Ollama LLM Setup"
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

# Check disk space (need at least 6GB for llama3.1)
AVAILABLE_GB=$(df -BG "$HOME" | awk 'NR==2 {print $4}' | sed 's/G//')
ok "Available disk space: ${AVAILABLE_GB}GB"

if [ "$AVAILABLE_GB" -lt 6 ]; then
  warn "Low disk space detected. Need at least 6GB for llama3.1 model."
  warn "Consider expanding EBS volume or using a smaller model."
  echo ""
fi

# Install Python dependencies for SYSTEM Python (critical for sudo usage)
echo ""
ok "Installing Python dependencies for system Python..."
warn "Using --ignore-installed to bypass typing-extensions conflict"

if sudo pip3 install --ignore-installed ollama requests --break-system-packages; then
  ok "Python packages installed successfully (system-wide)"
else
  err "Python package installation failed"
  exit 1
fi

# Verify system Python can import packages
echo ""
ok "Verifying system Python package installation..."
if sudo python3 -c "import ollama; import requests" 2>/dev/null; then
  ok "System Python packages verified"
else
  err "System Python package verification failed"
  warn "Trying alternative installation method..."
  
  # Alternative: Install without dependencies first
  sudo pip3 install --no-deps ollama --break-system-packages
  sudo pip3 install httpx pydantic httpcore h11 anyio --break-system-packages
  
  # Verify again
  if sudo python3 -c "import ollama; import requests" 2>/dev/null; then
    ok "Alternative installation successful"
  else
    err "Installation failed. Please check errors above."
    exit 1
  fi
fi

# Also install for user Python (optional, for non-sudo usage)
echo ""
ok "Installing for user Python (optional)..."
pip3 install ollama requests --break-system-packages || warn "User installation failed (not critical)"

# Install Ollama server
echo ""
ok "Installing Ollama server..."
curl -fsSL https://ollama.com/install.sh | sh

# Verify Ollama installation
if ! command -v ollama >/dev/null 2>&1; then
  err "ollama command not found. Installation failed."
  exit 1
fi

echo ""
ok "Ollama version:"
ollama --version || true

# Pull llama3.1 model
echo ""
ok "Pulling llama3.1 model (~4.9GB, this may take several minutes)..."
warn "This will download approximately 4.9GB of data"

if ollama pull llama3.1; then
  ok "llama3.1 model downloaded successfully"
else
  err "Failed to pull llama3.1 model"
  warn "If disk space is limited, try a smaller model:"
  echo "  ollama pull llama3.2:1b  # ~900MB"
  echo "  ollama pull tinyllama     # ~600MB"
  exit 1
fi

# Verify model is available
echo ""
ok "Installed models:"
ollama list

# Test Ollama connection
echo ""
ok "Testing Ollama connection..."
if echo "Say 'CONNECTION_OK' only" | ollama run llama3.1 >/dev/null 2>&1; then
  ok "Ollama service is working correctly"
else
  warn "Ollama test had issues, but model is installed"
fi

# Final comprehensive verification
echo ""
ok "Running final verification tests..."

# Test 1: User Python
if python3 -c "import ollama; import requests" 2>/dev/null; then
  ok "✓ User Python: ollama and requests available"
else
  warn "⚠ User Python: packages not available (non-critical)"
fi

# Test 2: System Python (CRITICAL)
if sudo python3 -c "import ollama; import requests; print('System packages OK')" 2>/dev/null; then
  ok "✓ System Python (sudo): ollama and requests available (CRITICAL)"
else
  err "✗ System Python (sudo): packages FAILED"
  err "Your detection scripts will NOT work with sudo"
  exit 1
fi

# Test 3: Ollama server
if ollama list | grep -q llama3.1; then
  ok "✓ Ollama server: llama3.1 model ready"
else
  err "✗ Ollama server: model not found"
  exit 1
fi

echo ""
echo "=========================================="
ok "Ollama LLM Setup Complete!"
echo "=========================================="
echo ""
ok "Installed components:"
echo "  - Python packages: ollama, requests (system-wide)"
echo "  - Ollama server"
echo "  - llama3.1 model (4.9GB)"
echo ""
echo "Verification Summary:"
echo "  ${GREEN}✓${NC} System Python (sudo) has ollama package"
echo "  ${GREEN}✓${NC} Ollama server running"
echo "  ${GREEN}✓${NC} llama3.1 model downloaded"
echo ""
echo "Quick test commands:"
echo "  ${GREEN}ollama list${NC}                              # List installed models"
echo "  ${GREEN}ollama run llama3.1 'test'${NC}               # Test the model"
echo "  ${GREEN}sudo python3 -c 'import ollama'${NC}         # Verify system package"
echo "  ${GREEN}python3 -c 'import ollama'${NC}              # Verify user package"
echo ""
echo "Test your detection script:"
echo "  ${GREEN}cd /home/ubuntu/DSDN_SmartGridLab${NC}"
echo "  ${GREEN}sudo python3 attack_detection.py --enable-llm --onos-ip 172.20.0.5 --debug${NC}"
echo ""
echo "Model Information:"
echo "  - Model: llama3.1"
echo "  - Size: ~4.9GB"
echo "  - URL: http://localhost:11434"
echo "  - Purpose: DNP3 threat analysis"
echo ""
echo "Next: Your GridLLM detection scripts can now use LLM"
echo "=========================================="