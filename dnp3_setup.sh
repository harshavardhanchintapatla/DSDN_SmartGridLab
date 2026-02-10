#!/bin/bash
# DNP3 Installation Setup Script
# Based on successful installation from December 2025
# This script installs Python 3.10 and dnp3-python on Ubuntu 24.04

set -e  # Exit on error

echo "=========================================="
echo "DNP3-Python Installation Script"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check if running on Ubuntu
if [ ! -f /etc/os-release ]; then
    print_error "Cannot determine OS. This script is designed for Ubuntu."
    exit 1
fi

source /etc/os-release
if [[ "$ID" != "ubuntu" ]]; then
    print_error "This script is designed for Ubuntu. Detected: $ID"
    exit 1
fi

print_status "Detected Ubuntu $VERSION_ID"

# Step 1: Install Python 3.10 (required for dnp3-python)
echo ""
echo "Step 1: Installing Python 3.10..."
echo "=========================================="

print_warning "DNP3-Python requires Python 3.8-3.10 (NOT Python 3.12+)"

# Add deadsnakes PPA for Python 3.10
print_status "Adding deadsnakes PPA repository..."
sudo add-apt-repository -y ppa:deadsnakes/ppa

print_status "Updating package lists..."
sudo apt update

print_status "Installing Python 3.10 and dependencies..."
sudo apt install -y \
    python3.10 \
    python3.10-venv \
    python3.10-dev \
    build-essential \
    python3-pip

# Verify Python 3.10 installation
if command -v python3.10 &> /dev/null; then
    PYTHON_VERSION=$(python3.10 --version)
    print_status "Python 3.10 installed successfully: $PYTHON_VERSION"
else
    print_error "Python 3.10 installation failed"
    exit 1
fi

# Step 2: Create virtual environment with Python 3.10
echo ""
echo "Step 2: Creating virtual environment..."
echo "=========================================="

VENV_PATH="$HOME/dnp3_310"

if [ -d "$VENV_PATH" ]; then
    print_warning "Virtual environment already exists at $VENV_PATH"
    read -p "Do you want to remove it and create a new one? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Removing existing virtual environment..."
        rm -rf "$VENV_PATH"
    else
        print_warning "Keeping existing virtual environment. Skipping creation."
        SKIP_VENV_CREATE=true
    fi
fi

if [ "$SKIP_VENV_CREATE" != "true" ]; then
    print_status "Creating virtual environment at $VENV_PATH..."
    python3.10 -m venv "$VENV_PATH"
    print_status "Virtual environment created successfully"
fi

# Step 3: Activate virtual environment and install dnp3-python
echo ""
echo "Step 3: Installing dnp3-python..."
echo "=========================================="

print_status "Activating virtual environment..."
source "$VENV_PATH/bin/activate"

print_status "Upgrading pip..."
pip install --upgrade pip

print_status "Installing dnp3-python..."
# Use --break-system-packages flag as required
pip install dnp3-python --break-system-packages

# Verify installation
if python -c "import dnp3_python" 2>/dev/null; then
    print_status "dnp3-python installed successfully!"
    
    # Show installed version
    DNP3_VERSION=$(pip show dnp3-python | grep Version | awk '{print $2}')
    print_status "Installed version: dnp3-python $DNP3_VERSION"
else
    print_error "dnp3-python installation verification failed"
    exit 1
fi

# Step 4: Create DNP3 scripts directory
echo ""
echo "Step 4: Setting up DNP3 scripts directory..."
echo "=========================================="

SCRIPTS_DIR="$HOME/dnp3_scripts"

if [ ! -d "$SCRIPTS_DIR" ]; then
    print_status "Creating DNP3 scripts directory at $SCRIPTS_DIR..."
    mkdir -p "$SCRIPTS_DIR"
else
    print_status "DNP3 scripts directory already exists at $SCRIPTS_DIR"
fi

# Step 5: Check disk space
echo ""
echo "Step 5: Checking disk space..."
echo "=========================================="

AVAILABLE_SPACE=$(df -h "$HOME" | awk 'NR==2 {print $4}')
print_status "Available disk space: $AVAILABLE_SPACE"

AVAILABLE_SPACE_GB=$(df -BG "$HOME" | awk 'NR==2 {print $4}' | sed 's/G//')
if [ "$AVAILABLE_SPACE_GB" -lt 5 ]; then
    print_warning "Low disk space detected. You may need to expand your storage."
    print_warning "Recommended: At least 10-15GB free for full ONOS + Mininet + DNP3 setup"
fi

# Step 6: Display activation instructions
echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
print_status "DNP3-Python installation successful!"
echo ""
echo "To activate the DNP3 environment:"
echo "  ${GREEN}source $VENV_PATH/bin/activate${NC}"
echo ""
echo "To deactivate:"
echo "  ${GREEN}deactivate${NC}"
echo ""
echo "Your DNP3 scripts directory:"
echo "  ${GREEN}$SCRIPTS_DIR${NC}"
echo ""
echo "Python version in virtual environment:"
python --version
echo ""

# Step 7: Create activation helper script
ACTIVATE_SCRIPT="$HOME/activate_dnp3.sh"
cat > "$ACTIVATE_SCRIPT" << 'EOF'
#!/bin/bash
# Quick activation script for DNP3 environment
source ~/dnp3_310/bin/activate
echo "DNP3 environment activated!"
echo "Python version: $(python --version)"
echo "DNP3-Python version: $(pip show dnp3-python | grep Version | awk '{print $2}')"
EOF

chmod +x "$ACTIVATE_SCRIPT"
print_status "Created activation helper script: $ACTIVATE_SCRIPT"

# Step 8: Test installation
echo ""
echo "Step 8: Testing installation..."
echo "=========================================="

print_status "Running import test..."
if python -c "from dnp3_python.dnp3station.master import MyMaster; from dnp3_python.dnp3station.outstation import MyOutStation; print('✓ All imports successful')" 2>/dev/null; then
    print_status "Import test passed!"
else
    print_error "Import test failed. There may be issues with the installation."
fi

# Step 9: Summary and next steps
echo ""
echo "=========================================="
echo "Next Steps:"
echo "=========================================="
echo ""
echo "1. Copy your DNP3 scripts to: ${GREEN}$SCRIPTS_DIR${NC}"
echo ""
echo "2. Activate the environment:"
echo "   ${GREEN}source ~/activate_dnp3.sh${NC}"
echo "   or"
echo "   ${GREEN}source ~/dnp3_310/bin/activate${NC}"
echo ""
echo "3. Update your scripts to use the correct Python path:"
echo "   ${GREEN}#!/home/ubuntu/dnp3_310/bin/python3${NC}"
echo ""
echo "4. For Mininet topology, use commands like:"
echo "   ${GREEN}h2 /home/ubuntu/dnp3_310/bin/python3 /home/ubuntu/dnp3_scripts/simple_outstation.py --station-id 2 &${NC}"
echo ""
echo "5. Your scripts should support stations 2-24 for the updated topology"
echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="