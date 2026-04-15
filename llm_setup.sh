#!/bin/bash
# Ollama LLM + RAG Setup

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC} $1"; }

echo "=========================================="
echo "Ollama + RAG Setup"
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

# Disk check
AVAILABLE_GB=$(df -BG "$HOME" | awk 'NR==2 {print $4}' | sed 's/G//')
ok "Available disk space: ${AVAILABLE_GB}GB"

if [ "$AVAILABLE_GB" -lt 6 ]; then
  err "Need at least 6GB free. Only ${AVAILABLE_GB}GB available."
  exit 1
fi

# ==========================================
# System Python Dependencies
# ==========================================
echo ""
echo "Installing system dependencies..."

sudo apt update -y
sudo apt install -y python3-venv python3-full python3-pip curl

if sudo pip3 install --ignore-installed ollama requests --break-system-packages; then
  ok "System Python packages installed"
else
  err "System Python package installation failed"
  exit 1
fi

if ! sudo python3 -c "import ollama; import requests" 2>/dev/null; then
  sudo pip3 install --no-deps ollama --break-system-packages
  sudo pip3 install httpx pydantic httpcore h11 anyio requests --break-system-packages
fi

# ==========================================
# RAG Environment
# ==========================================
echo ""
echo "Setting up RAG environment..."

rm -rf "$HOME/gridcad_env"

python3 -m venv ~/gridcad_env
source ~/gridcad_env/bin/activate

pip install --upgrade pip

# Install CPU torch first
pip install torch --index-url https://download.pytorch.org/whl/cpu

AFTER_TORCH_GB=$(df -BG "$HOME" | awk 'NR==2 {print $4}' | sed 's/G//')
if [ "$AFTER_TORCH_GB" -lt 4 ]; then
  err "Not enough space after torch install"
  deactivate
  exit 1
fi

pip install chromadb sentence-transformers ollama requests pydantic

if ! python3 -c "import chromadb; import sentence_transformers; import pydantic" 2>/dev/null; then
  err "RAG packages verification failed"
  deactivate
  exit 1
fi

deactivate

# ==========================================
# Ollama Installation
# ==========================================
echo ""
echo "Installing Ollama..."

PRE_OLLAMA_GB=$(df -BG "$HOME" | awk 'NR==2 {print $4}' | sed 's/G//')
if [ "$PRE_OLLAMA_GB" -lt 4 ]; then
  err "Not enough space for Ollama model"
  exit 1
fi

curl -fsSL https://ollama.com/install.sh | sh

if ! command -v ollama >/dev/null 2>&1; then
  err "Ollama installation failed"
  exit 1
fi

ollama --version || true

# ==========================================
# Model Download
# ==========================================
echo ""
echo "Downloading model..."

sudo rm -rf /usr/share/ollama/.ollama/models/blobs/*partial* 2>/dev/null || true

if ! ollama pull phi4-mini; then
  err "Model download failed"
  exit 1
fi

ollama list

echo "Testing model..."
echo "test" | ollama run phi4-mini >/dev/null 2>&1 || warn "Model test failed"

# ==========================================
# Final Checks
# ==========================================
echo ""
echo "Running verification..."

if ! sudo python3 -c "import ollama; import requests" 2>/dev/null; then
  err "System Python packages missing"
  exit 1
fi

if ! ollama list | grep -q phi4-mini; then
  err "Model not found"
  exit 1
fi

source ~/gridcad_env/bin/activate
if ! python3 -c "import chromadb; import sentence_transformers; import ollama; import torch" 2>/dev/null; then
  warn "RAG env incomplete"
fi
deactivate

echo ""
echo "=========================================="
ok "Setup complete"
echo "=========================================="

echo ""
echo "Commands:"
echo "  ollama list"
echo "  ollama run phi4-mini 'test'"
echo "  source ~/gridcad_env/bin/activate"
echo ""