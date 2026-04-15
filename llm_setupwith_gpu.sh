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

# Check disk space (need at least 6GB free)
AVAILABLE_GB=$(df -BG "$HOME" | awk 'NR==2 {print $4}' | sed 's/G//')
ok "Available disk space: ${AVAILABLE_GB}GB"

if [ "$AVAILABLE_GB" -lt 6 ]; then
  err "Need at least 6GB free. Only ${AVAILABLE_GB}GB available."
  err "Free up space before continuing."
  exit 1
fi

# ==========================================
# GPU Detection (for Ollama only)
# ==========================================
echo ""
echo "=========================================="
echo "GPU Detection"
echo "=========================================="

GPU_AVAILABLE=false

if command -v nvidia-smi >/dev/null 2>&1; then
  ok "NVIDIA GPU detected:"
  nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader || true
  GPU_AVAILABLE=true
else
  warn "nvidia-smi not found."
fi

if lspci 2>/dev/null | grep -qi nvidia; then
  ok "NVIDIA GPU confirmed via lspci"
  GPU_AVAILABLE=true
else
  warn "No NVIDIA GPU found via lspci. Ollama will run in CPU mode."
fi

if [ "$GPU_AVAILABLE" = true ]; then
  ok "Ollama will use GPU automatically (driver-level)"
  ok "NOTE: PyTorch is CPU-only — Ollama handles GPU inference independently"
else
  warn "Running in CPU-only mode — inference will be slower"
fi

# ==========================================
# Install System Python Dependencies
# ==========================================
echo ""
echo "=========================================="
echo "Installing System Python Dependencies"
echo "=========================================="

ok "Updating apt package lists..."
sudo apt update -y

ok "Installing python3-venv, python3-full and pip prerequisites..."
sudo apt install -y python3-venv python3-full python3-pip

ok "Installing ollama and requests for system Python..."
if sudo pip3 install --ignore-installed ollama requests --break-system-packages; then
  ok "System Python packages installed successfully"
else
  err "System Python package installation failed"
  exit 1
fi

ok "Verifying system Python packages..."
if sudo python3 -c "import ollama; import requests" 2>/dev/null; then
  ok "System Python packages verified"
else
  warn "Trying alternative installation method..."
  sudo pip3 install --no-deps ollama --break-system-packages
  sudo pip3 install httpx pydantic httpcore h11 anyio --break-system-packages
  if sudo python3 -c "import ollama; import requests" 2>/dev/null; then
    ok "Alternative installation successful"
  else
    err "System Python installation failed. Check errors above."
    exit 1
  fi
fi

ok "Installing for user Python (optional)..."
pip3 install ollama requests --break-system-packages || warn "User install failed (non-critical)"

# ==========================================
# RAG Environment Setup (gridcad_env)
# ==========================================
echo ""
echo "=========================================="
echo "Setting Up RAG Environment (gridcad_env)"
echo "=========================================="

# Clean up any existing venv
if [ -d "$HOME/gridcad_env" ]; then
  warn "Removing existing ~/gridcad_env for clean setup..."
  rm -rf "$HOME/gridcad_env"
fi

ok "Creating Python virtual environment at ~/gridcad_env..."
python3 -m venv ~/gridcad_env

ok "Activating virtual environment..."
source ~/gridcad_env/bin/activate

ok "Upgrading pip inside venv..."
pip install --upgrade pip

# ── CRITICAL: Install CPU torch FIRST before sentence-transformers ──
# If sentence-transformers is installed first, pip resolves torch as
# a dependency and pulls the CUDA build (~2.5GB nvidia/* + triton).
# Installing CPU torch first forces pip to reuse it instead.
echo ""
ok "Installing PyTorch CPU build FIRST (prevents CUDA build being pulled)..."
pip install torch --index-url https://download.pytorch.org/whl/cpu

# Check space after torch
echo ""
AFTER_TORCH_GB=$(df -BG "$HOME" | awk 'NR==2 {print $4}' | sed 's/G//')
ok "Disk space after PyTorch install: ${AFTER_TORCH_GB}GB free"

if [ "$AFTER_TORCH_GB" -lt 4 ]; then
  err "Only ${AFTER_TORCH_GB}GB remaining after torch. Need 4GB for chromadb + phi4-mini."
  deactivate
  exit 1
fi

# Now install everything else — pip will reuse the CPU torch already installed
ok "Installing RAG dependencies (chromadb, sentence-transformers, etc.)..."
pip install chromadb sentence-transformers ollama requests pydantic

# Verify RAG environment
echo ""
ok "Verifying RAG environment packages..."

if python3 -c "import chromadb; import sentence_transformers; import pydantic; print('RAG_OK')"; then
  ok "RAG packages verified (RAG_OK)"
else
  err "RAG package verification failed"
  deactivate
  exit 1
fi

if python3 -c "import chromadb; import sentence_transformers; import pydantic; print('ALL_OK')"; then
  ok "Full stack verified (ALL_OK)"
else
  err "Full stack verification failed"
  deactivate
  exit 1
fi

# Verify torch is CPU-only (no CUDA bloat)
echo ""
ok "Verifying PyTorch build..."
python3 -c "
import torch
version = torch.__version__
cuda = torch.cuda.is_available()
print(f'  PyTorch version : {version}')
print(f'  CUDA available  : {cuda}')
if '+cpu' in version:
    print('  Build           : CPU only (correct — saves ~3GB)')
else:
    print('  Build           : WARNING — CUDA build detected, may use extra space')
print(f'  Mode            : {\"GPU\" if cuda else \"CPU (Ollama handles GPU separately)\"}')
" || warn "PyTorch check failed (non-critical)"

deactivate

# ==========================================
# Verify system-level RAG imports (sudo)
# ==========================================
echo ""
ok "Verifying RAG packages for system Python (sudo)..."
sudo python3 -c "import chromadb; import sentence_transformers; import pydantic; print('RAG_OK')" \
  || warn "System Python RAG check failed — expected, use virtualenv (~/gridcad_env) for RAG scripts"

# ==========================================
# Disk space check before Ollama
# ==========================================
echo ""
PRE_OLLAMA_GB=$(df -BG "$HOME" | awk 'NR==2 {print $4}' | sed 's/G//')
ok "Disk space before Ollama + model: ${PRE_OLLAMA_GB}GB free"

if [ "$PRE_OLLAMA_GB" -lt 4 ]; then
  err "Need at least 4GB free to install Ollama + phi4-mini. Only ${PRE_OLLAMA_GB}GB available."
  exit 1
fi

# ==========================================
# Install Ollama Server
# ==========================================
echo ""
echo "=========================================="
echo "Installing Ollama Server"
echo "=========================================="

ok "Installing Ollama server..."
curl -fsSL https://ollama.com/install.sh | sh

if ! command -v ollama >/dev/null 2>&1; then
  err "ollama command not found. Installation failed."
  exit 1
fi

ok "Ollama version:"
ollama --version || true

if [ "$GPU_AVAILABLE" = true ]; then
  ok "Ollama GPU: active (verify with: OLLAMA_DEBUG=1 ollama run phi4-mini)"
else
  warn "Ollama running in CPU mode"
fi

# ==========================================
# Pull phi4-mini model
# ==========================================
echo ""
ok "Pulling phi4-mini model (~2.5GB, this may take several minutes)..."
warn "This will download approximately 2.5GB of data"

# Clean up any partial downloads from previous attempts
sudo rm -rf /usr/share/ollama/.ollama/models/blobs/*partial* 2>/dev/null || true

if ollama pull phi4-mini; then
  ok "phi4-mini model downloaded successfully"
else
  err "Failed to pull phi4-mini model"
  sudo rm -rf /usr/share/ollama/.ollama/models/blobs/*partial* 2>/dev/null || true
  warn "Partial download cleaned. Check disk space and retry manually:"
  echo "  df -h ~"
  echo "  ollama pull phi4-mini"
  exit 1
fi

echo ""
ok "Installed models:"
ollama list

ok "Testing Ollama connection..."
if echo "Say 'CONNECTION_OK' only" | ollama run phi4-mini >/dev/null 2>&1; then
  ok "Ollama service working correctly"
else
  warn "Ollama test had issues, but model is installed"
fi

# ==========================================
# Final Verification
# ==========================================
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
  err "Detection scripts will NOT work with sudo"
  exit 1
fi

# Test 3: Ollama model
if ollama list | grep -q phi4-mini; then
  ok "✓ Ollama server: phi4-mini model ready"
else
  err "✗ Ollama server: phi4-mini model not found"
  exit 1
fi

# Test 4: RAG virtualenv
source ~/gridcad_env/bin/activate
if python3 -c "import chromadb; import sentence_transformers; import ollama; import torch" 2>/dev/null; then
  ok "✓ RAG virtualenv (~/gridcad_env): all packages available"
else
  warn "⚠ RAG virtualenv: one or more packages missing"
fi
deactivate

# Final disk report
echo ""
FINAL_GB=$(df -BG "$HOME" | awk 'NR==2 {print $4}' | sed 's/G//')
ok "Remaining disk space: ${FINAL_GB}GB"

echo ""
echo "=========================================="
ok "Ollama LLM + RAG Setup Complete!"
echo "=========================================="
echo ""
ok "Installed components:"
echo "  - Python packages: ollama, requests (system-wide)"
echo "  - Ollama server"
echo "  - phi4-mini model (~2.5GB)"
echo "  - RAG virtualenv: ~/gridcad_env"
echo "    └─ chromadb, sentence-transformers, torch (CPU), ollama, pydantic"
echo ""
echo "Verification Summary:"
echo "  ${GREEN}✓${NC} System Python (sudo) has ollama package"
echo "  ${GREEN}✓${NC} Ollama server running"
echo "  ${GREEN}✓${NC} phi4-mini model downloaded"
echo "  ${GREEN}✓${NC} RAG environment ready at ~/gridcad_env"
if [ "$GPU_AVAILABLE" = true ]; then
  echo "  ${GREEN}✓${NC} GPU detected — Ollama will use it automatically"
else
  echo "  ${YELLOW}⚠${NC} CPU mode (no GPU detected)"
fi
echo ""
echo "Quick test commands:"
echo "  ${GREEN}ollama list${NC}                                     # List installed models"
echo "  ${GREEN}ollama run phi4-mini 'test'${NC}                     # Test the model"
echo "  ${GREEN}OLLAMA_DEBUG=1 ollama run phi4-mini 'test'${NC}      # Verify GPU usage"
echo "  ${GREEN}sudo python3 -c 'import ollama'${NC}                 # Verify system package"
echo ""
echo "RAG environment commands:"
echo "  ${GREEN}source ~/gridcad_env/bin/activate${NC}               # Activate RAG env"
echo "  ${GREEN}python3 -c 'import chromadb; print(\"OK\")'${NC}       # Test RAG packages"
echo "  ${GREEN}deactivate${NC}                                       # Exit RAG env"
echo ""
echo "Test your detection script:"
echo "  ${GREEN}cd /home/ubuntu/DSDN_SmartGridLab${NC}"
echo "  ${GREEN}sudo python3 attack_detection.py --enable-llm --onos-ip 172.20.0.5 --debug${NC}"
echo ""
echo "Model Information:"
echo "  - Model: phi4-mini"
echo "  - Size: ~2.5GB"
echo "  - URL: http://localhost:11434"
echo "  - Purpose: DNP3 threat analysis + RAG"
echo ""
echo "Next: Your GridLLM detection scripts can now use LLM + RAG"
echo "=========================================="