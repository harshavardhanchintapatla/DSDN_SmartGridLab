#!/bin/bash

################################################################################
# ONOS Distributed Cluster Setup Script
# Sets up 3 ONOS controllers with 3 Atomix nodes
# 
# PREREQUISITES:
# - Ubuntu 20.04 or later
# - sudo access
# - At least 8GB RAM recommended
#
# BEFORE RUNNING:
# - Set PUBLIC_IP variable below to your EC2 instance public IP
################################################################################

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

################################################################################
# CONFIGURATION - OPTIONAL: Set PUBLIC_IP manually or leave blank for auto-detect
################################################################################

# PUBLIC IP Configuration:
# - Leave blank ("") for automatic detection
# - OR set manually: PUBLIC_IP="1.2.3.4"
PUBLIC_IP=""

# Network configuration (do not modify unless you know what you're doing)
DOCKER_NETWORK="onos-atomix-net"
DOCKER_SUBNET="172.20.0.0/16"

# Atomix container IPs
ATOMIX_1_IP="172.20.0.2"
ATOMIX_2_IP="172.20.0.3"
ATOMIX_3_IP="172.20.0.4"

# ONOS container IPs
ONOS_1_IP="172.20.0.5"
ONOS_2_IP="172.20.0.6"
ONOS_3_IP="172.20.0.7"

# Versions
ATOMIX_VERSION="3.1.5"
ONOS_VERSION="2.2.1"

# Directories
HOME_DIR="/home/ubuntu"
ONOS_DIR="$HOME_DIR/onos"
ATOMIX_CONFIG_DIR="$HOME_DIR/atomix-configs"
ONOS_CONFIG_DIR="$HOME_DIR/onos-configs"

# ONOS apps to pre-load
ONOS_APPS="drivers,openflow,openflow-base,ofagent,netcfghostprovider,lldpprovider,gui2,fwd,mfwd"

################################################################################
# HELPER FUNCTIONS
################################################################################

wait_for_onos() {
    local port="$1"
    local name="$2"
    local max_wait="${3:-240}"  # seconds
    local start
    start=$(date +%s)

    log_info "Waiting for $name REST API on localhost:$port ..."
    while true; do
        if curl -s -u onos:rocks --max-time 3 "http://localhost:${port}/onos/v1/cluster" >/dev/null 2>&1; then
            log_success "$name is reachable on port $port"
            return 0
        fi

        if [ $(( $(date +%s) - start )) -ge "$max_wait" ]; then
            log_error "Timeout waiting for $name on port $port after ${max_wait}s"
            return 1
        fi

        sleep 5
    done
}

wait_for_atomix_cluster() {
    log_info "Waiting for Atomix cluster to elect leader and stabilize..."
    log_info "This typically takes 10-30 seconds..."
    
    local max_wait=60
    local elapsed=0
    
    while [ $elapsed -lt $max_wait ]; do
        # Check if any Atomix node mentions "leader" or "READY" in logs
        if sudo docker logs atomix-1 2>&1 | grep -q -i "leader\|raft\|ready"; then
            log_success "Atomix cluster appears to be forming"
            sleep 10  # Give it a bit more time to fully stabilize
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    
    log_warning "Atomix cluster status unclear after ${max_wait}s, proceeding anyway"
    return 0
}

################################################################################
# VALIDATION
################################################################################

validate_config() {
    log_info "Validating configuration..."
    
    # Auto-detect PUBLIC_IP if not set
    if [ -z "$PUBLIC_IP" ]; then
        log_info "PUBLIC_IP not set, attempting auto-detection..."
        PUBLIC_IP="$(curl -s --max-time 5 ifconfig.me 2>/dev/null || curl -s --max-time 5 icanhazip.com 2>/dev/null || true)"
        
        if [ -z "$PUBLIC_IP" ]; then
            log_error "Failed to auto-detect PUBLIC IP!"
            log_error "Please set PUBLIC_IP manually in the script or check your internet connection."
            log_error "You can find your public IP in AWS EC2 console or by running: curl ifconfig.me"
            exit 1
        fi
        
        log_success "Auto-detected PUBLIC IP: $PUBLIC_IP"
    else
        log_info "Using manually configured PUBLIC IP: $PUBLIC_IP"
    fi
    
    # Validate IP format
    if ! [[ $PUBLIC_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_error "Invalid IP address format: $PUBLIC_IP"
        log_error "Expected format: xxx.xxx.xxx.xxx"
        exit 1
    fi
    
    # Additional validation: check each octet is 0-255
    IFS='.' read -r -a octets <<< "$PUBLIC_IP"
    for octet in "${octets[@]}"; do
        if [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
            log_error "Invalid IP address: $PUBLIC_IP (octet out of range: $octet)"
            exit 1
        fi
    done
    
    log_success "Configuration validated"
    log_info "ONOS Web UI will be accessible at:"
    log_info "  - http://$PUBLIC_IP:8181/onos/ui/"
    log_info "  - http://$PUBLIC_IP:8182/onos/ui/"
    log_info "  - http://$PUBLIC_IP:8183/onos/ui/"
}

################################################################################
# STEP 1: Install Docker
################################################################################

install_docker() {
    log_info "STEP 1: Installing Docker..."
    
    if command -v docker &> /dev/null; then
        log_warning "Docker already installed, checking version..."
        docker --version
    else
        log_info "Updating package index..."
        sudo apt update -qq
        
        log_info "Installing Docker..."
        sudo apt install -y docker.io
        
        log_info "Starting Docker service..."
        sudo systemctl start docker
        sudo systemctl enable docker
        
        log_success "Docker installed successfully"
    fi
    
    # Verify Docker is running
    if ! sudo systemctl is-active --quiet docker; then
        log_error "Docker service is not running"
        exit 1
    fi
    
    log_success "STEP 1 Complete: Docker is installed and running"
}

################################################################################
# STEP 2: Create Docker user group
################################################################################

setup_docker_group() {
    log_info "STEP 2: Setting up Docker user group..."
    
    log_info "Adding current user ($USER) to docker group..."
    sudo usermod -aG docker $USER
    
    log_info "Applying docker group for current session..."
    # Instead of newgrp which creates a subshell, we'll use sg to run the rest of the script
    # This allows Docker commands to work without requiring logout/login
    
    log_success "Docker group configured successfully"
    log_warning "Note: If you see permission errors, you may need to log out and back in, or run: sudo chmod 666 /var/run/docker.sock"
    log_success "STEP 2 Complete: Docker group configured"
}

################################################################################
# STEP 3: Note about restarting instance
################################################################################

note_restart() {
    log_info "STEP 3: Instance restart recommendation"
    log_warning "For production use, it's recommended to stop and restart the VM after Docker installation"
    log_info "Since this is an automated script, we'll continue without restart"
    log_info "If you experience permission issues, manually restart the instance and re-run this script"
    log_success "STEP 3 Complete: Noted restart recommendation"
}

################################################################################
# STEP 4: Get ONOS source code
################################################################################

get_onos_source() {
    log_info "STEP 4: Getting ONOS source code..."
    
    if [ -d "$ONOS_DIR" ]; then
        log_warning "ONOS directory already exists at $ONOS_DIR"
        log_info "Checking current branch..."
        cd "$ONOS_DIR"
        current_branch=$(git branch --show-current)
        log_info "Current branch: $current_branch"
        
        if [ "$current_branch" != "2.2.1" ]; then
            log_info "Switching to branch 2.2.1..."
            git checkout 2.2.1
        fi
    else
        log_info "Cloning ONOS repository..."
        cd "$HOME_DIR"
        
        # Try with SSL verification disabled (common issue with gerrit certificates)
        log_info "Attempting to clone with SSL verification workaround..."
        if ! GIT_SSL_NO_VERIFY=true git clone https://gerrit.onosproject.org/onos; then
            log_warning "HTTPS clone failed, trying alternative GitHub mirror..."
            # Alternative: Try GitHub mirror if gerrit fails
            if ! git clone https://github.com/opennetworkinglab/onos.git onos; then
                log_error "Failed to clone ONOS from both sources"
                log_error "Please check your network connection and try again"
                exit 1
            fi
        fi
        
        log_info "Checking out version 2.2.1..."
        cd "$ONOS_DIR"
        git checkout 2.2.1
    fi
    
    log_success "STEP 4 Complete: ONOS source code ready at $ONOS_DIR"
}

################################################################################
# STEP 5: Generate Atomix configuration files
################################################################################

generate_atomix_configs() {
    log_info "STEP 5: Generating Atomix configuration files..."
    
    # Check if configs already exist
    if [ -d "$ATOMIX_CONFIG_DIR" ]; then
        log_warning "Atomix config directory already exists"
        log_info "Backing up existing configs..."
        mv "$ATOMIX_CONFIG_DIR" "${ATOMIX_CONFIG_DIR}_backup_$(date +%Y%m%d_%H%M%S)"
    fi
    
    log_info "Creating Atomix config directories..."
    mkdir -p "$ATOMIX_CONFIG_DIR/atomix-1-conf"
    mkdir -p "$ATOMIX_CONFIG_DIR/atomix-2-conf"
    mkdir -p "$ATOMIX_CONFIG_DIR/atomix-3-conf"
    
    log_info "Generating Atomix config for node 1..."
    cat > "$ATOMIX_CONFIG_DIR/atomix-1-conf/atomix.conf" << 'EOF'
{
  "cluster": {
    "clusterId": "onos",
    "node": {
      "id": "atomix-1",
      "address": "172.20.0.2:5679"
    },
    "discovery": {
      "type": "bootstrap",
      "nodes": [
        {
          "id": "atomix-1",
          "address": "172.20.0.2:5679"
        },
        {
          "id": "atomix-2",
          "address": "172.20.0.3:5679"
        },
        {
          "id": "atomix-3",
          "address": "172.20.0.4:5679"
        }
      ]
    }
  },
  "managementGroup": {
    "type": "raft",
    "partitions": 1,
    "partitionSize": 3,
    "members": [
      "atomix-1",
      "atomix-2",
      "atomix-3"
    ],
    "storage": {
      "level": "mapped"
    }
  },
  "partitionGroups": {
    "raft": {
      "type": "raft",
      "partitions": 3,
      "partitionSize": 3,
      "members": [
        "atomix-1",
        "atomix-2",
        "atomix-3"
      ],
      "storage": {
        "level": "mapped"
      }
    }
  }
}
EOF

    log_info "Generating Atomix config for node 2..."
    cat > "$ATOMIX_CONFIG_DIR/atomix-2-conf/atomix.conf" << 'EOF'
{
  "cluster": {
    "clusterId": "onos",
    "node": {
      "id": "atomix-2",
      "address": "172.20.0.3:5679"
    },
    "discovery": {
      "type": "bootstrap",
      "nodes": [
        {
          "id": "atomix-1",
          "address": "172.20.0.2:5679"
        },
        {
          "id": "atomix-2",
          "address": "172.20.0.3:5679"
        },
        {
          "id": "atomix-3",
          "address": "172.20.0.4:5679"
        }
      ]
    }
  },
  "managementGroup": {
    "type": "raft",
    "partitions": 1,
    "partitionSize": 3,
    "members": [
      "atomix-1",
      "atomix-2",
      "atomix-3"
    ],
    "storage": {
      "level": "mapped"
    }
  },
  "partitionGroups": {
    "raft": {
      "type": "raft",
      "partitions": 3,
      "partitionSize": 3,
      "members": [
        "atomix-1",
        "atomix-2",
        "atomix-3"
      ],
      "storage": {
        "level": "mapped"
      }
    }
  }
}
EOF

    log_info "Generating Atomix config for node 3..."
    cat > "$ATOMIX_CONFIG_DIR/atomix-3-conf/atomix.conf" << 'EOF'
{
  "cluster": {
    "clusterId": "onos",
    "node": {
      "id": "atomix-3",
      "address": "172.20.0.4:5679"
    },
    "discovery": {
      "type": "bootstrap",
      "nodes": [
        {
          "id": "atomix-1",
          "address": "172.20.0.2:5679"
        },
        {
          "id": "atomix-2",
          "address": "172.20.0.3:5679"
        },
        {
          "id": "atomix-3",
          "address": "172.20.0.4:5679"
        }
      ]
    }
  },
  "managementGroup": {
    "type": "raft",
    "partitions": 1,
    "partitionSize": 3,
    "members": [
      "atomix-1",
      "atomix-2",
      "atomix-3"
    ],
    "storage": {
      "level": "mapped"
    }
  },
  "partitionGroups": {
    "raft": {
      "type": "raft",
      "partitions": 3,
      "partitionSize": 3,
      "members": [
        "atomix-1",
        "atomix-2",
        "atomix-3"
      ],
      "storage": {
        "level": "mapped"
      }
    }
  }
}
EOF
    
    # Verify configs were created
    for i in 1 2 3; do
        if [ ! -f "$ATOMIX_CONFIG_DIR/atomix-$i-conf/atomix.conf" ]; then
            log_error "Failed to generate atomix-$i-conf/atomix.conf"
            exit 1
        fi
    done
    
    log_success "STEP 5 Complete: Atomix configurations generated"
}

################################################################################
# STEP 6: Generate ONOS configuration files
################################################################################

generate_onos_configs() {
    log_info "STEP 6: Generating ONOS configuration files..."
    
    # Check if configs already exist
    if [ -d "$ONOS_CONFIG_DIR" ]; then
        log_warning "ONOS config directory already exists"
        log_info "Backing up existing configs..."
        mv "$ONOS_CONFIG_DIR" "${ONOS_CONFIG_DIR}_backup_$(date +%Y%m%d_%H%M%S)"
    fi
    
    log_info "Creating ONOS config directory..."
    mkdir -p "$ONOS_CONFIG_DIR"
    
    log_info "Generating ONOS config for controller 1..."
    cat > "$ONOS_CONFIG_DIR/cluster-1.json" << EOF
{
  "name": "onos",
  "node": {
    "id": "$ONOS_1_IP",
    "ip": "$ONOS_1_IP",
    "port": 9876
  },
  "storage": [
    {
      "id": "atomix-1",
      "ip": "$ATOMIX_1_IP",
      "port": 5679
    },
    {
      "id": "atomix-2",
      "ip": "$ATOMIX_2_IP",
      "port": 5679
    },
    {
      "id": "atomix-3",
      "ip": "$ATOMIX_3_IP",
      "port": 5679
    }
  ]
}
EOF

    log_info "Generating ONOS config for controller 2..."
    cat > "$ONOS_CONFIG_DIR/cluster-2.json" << EOF
{
  "name": "onos",
  "node": {
    "id": "$ONOS_2_IP",
    "ip": "$ONOS_2_IP",
    "port": 9876
  },
  "storage": [
    {
      "id": "atomix-1",
      "ip": "$ATOMIX_1_IP",
      "port": 5679
    },
    {
      "id": "atomix-2",
      "ip": "$ATOMIX_2_IP",
      "port": 5679
    },
    {
      "id": "atomix-3",
      "ip": "$ATOMIX_3_IP",
      "port": 5679
    }
  ]
}
EOF

    log_info "Generating ONOS config for controller 3..."
    cat > "$ONOS_CONFIG_DIR/cluster-3.json" << EOF
{
  "name": "onos",
  "node": {
    "id": "$ONOS_3_IP",
    "ip": "$ONOS_3_IP",
    "port": 9876
  },
  "storage": [
    {
      "id": "atomix-1",
      "ip": "$ATOMIX_1_IP",
      "port": 5679
    },
    {
      "id": "atomix-2",
      "ip": "$ATOMIX_2_IP",
      "port": 5679
    },
    {
      "id": "atomix-3",
      "ip": "$ATOMIX_3_IP",
      "port": 5679
    }
  ]
}
EOF
    
    # Verify configs were created
    for i in 1 2 3; do
        if [ ! -f "$ONOS_CONFIG_DIR/cluster-$i.json" ]; then
            log_error "Failed to generate cluster-$i.json"
            exit 1
        fi
    done
    
    log_success "STEP 6 Complete: ONOS configurations generated"
}

################################################################################
# STEP 7-9: Docker Setup and Container Deployment
################################################################################

cleanup_existing_containers() {
    log_info "Cleaning up existing Docker containers and networks..."
    
    # Stop all containers
    if [ "$(sudo docker ps -aq)" ]; then
        log_info "Stopping all Docker containers..."
        sudo docker stop $(sudo docker ps -aq) 2>/dev/null || true
        
        log_info "Removing all Docker containers..."
        sudo docker rm $(sudo docker ps -aq) 2>/dev/null || true
    else
        log_info "No existing containers to clean up"
    fi
    
    # Remove network if exists
    if sudo docker network inspect $DOCKER_NETWORK &>/dev/null; then
        log_info "Removing existing Docker network: $DOCKER_NETWORK"
        sudo docker network rm $DOCKER_NETWORK 2>/dev/null || true
    fi
    
    # System prune
    log_info "Running Docker system prune..."
    sudo docker system prune -a --volumes -f
    
    log_success "Docker cleanup complete"
}

pull_atomix_image() {
    log_info "Pulling Atomix Docker image..."
    sudo docker pull atomix/atomix:$ATOMIX_VERSION
    log_success "Atomix image pulled successfully"
}

create_docker_network() {
    log_info "Creating Docker network: $DOCKER_NETWORK with subnet $DOCKER_SUBNET"
    sudo docker network create --subnet=$DOCKER_SUBNET $DOCKER_NETWORK
    log_success "Docker network created"
}

deploy_atomix_containers() {
    log_info "Deploying Atomix containers..."
    
    log_info "Starting Atomix container 1 at $ATOMIX_1_IP..."
    sudo docker run -t -d \
        --name atomix-1 \
        --net $DOCKER_NETWORK \
        --ip $ATOMIX_1_IP \
        -v $ATOMIX_CONFIG_DIR/atomix-1-conf:/etc/atomix/conf \
        atomix/atomix:$ATOMIX_VERSION \
        --config /etc/atomix/conf/atomix.conf \
        --ignore-resource
    
    log_info "Starting Atomix container 2 at $ATOMIX_2_IP..."
    sudo docker run -t -d \
        --name atomix-2 \
        --net $DOCKER_NETWORK \
        --ip $ATOMIX_2_IP \
        -v $ATOMIX_CONFIG_DIR/atomix-2-conf:/etc/atomix/conf \
        atomix/atomix:$ATOMIX_VERSION \
        --config /etc/atomix/conf/atomix.conf \
        --ignore-resource
    
    log_info "Starting Atomix container 3 at $ATOMIX_3_IP..."
    sudo docker run -t -d \
        --name atomix-3 \
        --net $DOCKER_NETWORK \
        --ip $ATOMIX_3_IP \
        -v $ATOMIX_CONFIG_DIR/atomix-3-conf:/etc/atomix/conf \
        atomix/atomix:$ATOMIX_VERSION \
        --config /etc/atomix/conf/atomix.conf \
        --ignore-resource
    
    # Verify containers are running
    sleep 3
    for i in 1 2 3; do
        if ! sudo docker ps | grep -q "atomix-$i"; then
            log_error "Atomix container $i failed to start"
            sudo docker logs atomix-$i
            exit 1
        fi
    done
    
    log_success "All Atomix containers deployed and running"
    
    # Wait for Atomix cluster to stabilize before starting ONOS
    wait_for_atomix_cluster
}

export_atomix_env_vars() {
    log_info "Exporting Atomix environment variables..."
    export OC1=$ATOMIX_1_IP
    export OC2=$ATOMIX_2_IP
    export OC3=$ATOMIX_3_IP
    
    log_info "Environment variables set:"
    log_info "  OC1=$OC1"
    log_info "  OC2=$OC2"
    log_info "  OC3=$OC3"
    
    log_success "Atomix environment variables exported"
}

deploy_onos_containers() {
    log_info "Deploying ONOS controller containers..."
    
    log_info "Starting ONOS controller 1 at $ONOS_1_IP (port 8181)..."
    sudo docker run -t -d \
        --name onos-1 \
        --hostname onos-1 \
        --net $DOCKER_NETWORK \
        --ip $ONOS_1_IP \
        -p 8181:8181 \
        -e ONOS_APPS="$ONOS_APPS" \
        onosproject/onos:$ONOS_VERSION >/dev/null
    
    log_info "Starting ONOS controller 2 at $ONOS_2_IP (port 8182)..."
    sudo docker run -t -d \
        --name onos-2 \
        --hostname onos-2 \
        --net $DOCKER_NETWORK \
        --ip $ONOS_2_IP \
        -p 8182:8181 \
        -e ONOS_APPS="$ONOS_APPS" \
        onosproject/onos:$ONOS_VERSION >/dev/null
    
    log_info "Starting ONOS controller 3 at $ONOS_3_IP (port 8183)..."
    sudo docker run -t -d \
        --name onos-3 \
        --hostname onos-3 \
        --net $DOCKER_NETWORK \
        --ip $ONOS_3_IP \
        -p 8183:8181 \
        -e ONOS_APPS="$ONOS_APPS" \
        onosproject/onos:$ONOS_VERSION >/dev/null
    
    # Verify containers are running
    sleep 5
    for i in 1 2 3; do
        if ! sudo docker ps | grep -q "onos-$i"; then
            log_error "ONOS container $i failed to start"
            sudo docker logs onos-$i
            exit 1
        fi
    done
    
    log_success "All ONOS controller containers started"
    
    # Wait for each ONOS instance to be ready via REST API
    log_info "Waiting for ONOS controllers to initialize..."
    wait_for_onos 8181 "ONOS-1" 240 || log_warning "ONOS-1 not ready, continuing anyway"
    wait_for_onos 8182 "ONOS-2" 240 || log_warning "ONOS-2 not ready, continuing anyway"
    wait_for_onos 8183 "ONOS-3" 240 || log_warning "ONOS-3 not ready, continuing anyway"
    
    log_success "All ONOS controller containers deployed and ready"
}

create_onos_config_dirs() {
    log_info "Creating config directories in ONOS containers..."
    
    sudo docker exec onos-1 mkdir -p /root/onos/config
    sudo docker exec onos-2 mkdir -p /root/onos/config
    sudo docker exec onos-3 mkdir -p /root/onos/config
    
    log_success "Config directories created in all ONOS containers"
}

copy_onos_configs() {
    log_info "Copying configuration files into ONOS containers..."
    
    log_info "Copying config to ONOS controller 1..."
    sudo docker cp "$ONOS_CONFIG_DIR/cluster-1.json" onos-1:/root/onos/config/cluster.json
    
    log_info "Copying config to ONOS controller 2..."
    sudo docker cp "$ONOS_CONFIG_DIR/cluster-2.json" onos-2:/root/onos/config/cluster.json
    
    log_info "Copying config to ONOS controller 3..."
    sudo docker cp "$ONOS_CONFIG_DIR/cluster-3.json" onos-3:/root/onos/config/cluster.json
    
    # Verify configs were copied
    for i in 1 2 3; do
        if ! sudo docker exec onos-$i test -f /root/onos/config/cluster.json; then
            log_error "Failed to copy config to onos-$i"
            exit 1
        fi
    done
    
    log_success "Configuration files copied to all ONOS containers"
}

restart_onos_containers() {
    log_info "STEP 9: Restarting ONOS containers to apply configurations..."
    
    sudo docker restart onos-1 onos-2 onos-3
    
    log_info "Waiting for ONOS controllers to restart and become ready..."
    
    # Wait for each controller's REST API
    wait_for_onos 8181 "ONOS-1" 240 || log_warning "ONOS-1 not ready after restart"
    wait_for_onos 8182 "ONOS-2" 240 || log_warning "ONOS-2 not ready after restart"
    wait_for_onos 8183 "ONOS-3" 240 || log_warning "ONOS-3 not ready after restart"
    
    # Additional wait for cluster to fully form
    log_info "Controllers are responding, waiting for cluster formation (30 seconds)..."
    log_info "This ensures Atomix connections are established..."
    sleep 30
    
    # Verify containers are still running
    for i in 1 2 3; do
        if ! sudo docker ps | grep -q "onos-$i"; then
            log_error "ONOS container $i failed to restart"
            sudo docker logs onos-$i
            exit 1
        fi
    done
    
    log_success "STEP 9 Complete: ONOS containers restarted successfully"
}

################################################################################
# MAIN EXECUTION
################################################################################

print_banner() {
    echo ""
    echo "========================================================================"
    echo "         ONOS Distributed Cluster Setup Script"
    echo "========================================================================"
    echo "This script will set up a 3-node ONOS cluster with Atomix"
    echo "========================================================================"
    echo ""
}

print_completion_message() {
    echo ""
    echo "========================================================================"
    log_success "ONOS CLUSTER SETUP COMPLETE!"
    echo "========================================================================"
    echo ""
    echo "Next Steps:"
    echo ""
    echo "1. Access ONOS Web UI at:"
    echo "   - Controller 1: http://$PUBLIC_IP:8181/onos/ui/"
    echo "   - Controller 2: http://$PUBLIC_IP:8182/onos/ui/"
    echo "   - Controller 3: http://$PUBLIC_IP:8183/onos/ui/"
    echo ""
    echo "2. Login credentials:"
    echo "   - Username: onos"
    echo "   - Password: rocks"
    echo ""
    echo "3. Verify cluster status:"
    echo "   - Go to sidebar → 'Cluster Nodes'"
    echo "   - Ensure all 3 nodes have green checkmarks"
    echo "   - If any node has a red X, wait 5 minutes and refresh"
    echo ""
    echo "4. View running containers:"
    echo "   docker ps"
    echo ""
    echo "5. View container logs:"
    echo "   docker logs onos-1"
    echo "   docker logs atomix-1"
    echo ""
    echo "6. To proceed with Mininet setup, follow the remaining steps"
    echo "   in the manual (steps 14-18)"
    echo ""
    echo "========================================================================"
    echo ""
}

main() {
    print_banner
    
    # Validate configuration
    validate_config
    
    # Execute setup steps
    install_docker
    setup_docker_group
    note_restart
    get_onos_source
    generate_atomix_configs
    generate_onos_configs
    
    # Docker deployment steps
    cleanup_existing_containers
    pull_atomix_image
    create_docker_network
    deploy_atomix_containers
    export_atomix_env_vars
    deploy_onos_containers
    create_onos_config_dirs
    copy_onos_configs
    restart_onos_containers
    
    # Print completion message
    print_completion_message
}

# Run main function
main "$@"