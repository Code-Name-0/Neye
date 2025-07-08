#!/bin/bash
#
# NEye - Simple Install, Build, and Run Script with Python Virtualenv
#

set -e

# --- Colors for readable output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_step() { echo -e "\n${BLUE}>>> $1${NC}"; }
log_info() { echo -e "${GREEN}    $1${NC}"; }
log_error() { echo -e "${RED}!!! ERROR: $1${NC}"; }
log_warn() { echo -e "${YELLOW}--- $1 ---${NC}"; }

run_with_sudo() {
    if [ "$EUID" -ne 0 ]; then
        log_warn "Sudo privileges are required for this step."
        sudo "$@"
    else
        "$@"
    fi
}

# --- Install system dependencies (requires sudo) ---
log_step "Installing system dependencies..."
log_info "Updating APT and installing essential packages."
run_with_sudo apt-get update -y
run_with_sudo apt-get install -y build-essential cmake git python3-venv libpcap-dev libcurl4-openssl-dev xterm

# --- Set up Python virtual environment ---
log_step "Creating and activating Python virtual environment..."
VENV_DIR="venv"
if [ -d "$VENV_DIR" ]; then
    log_info "Existing virtual environment found at '$VENV_DIR'. Reusing it."
else
    log_info "No virtual environment found. Creating a new one at '$VENV_DIR'."
    python3 -m venv "$VENV_DIR"
fi



source "$VENV_DIR/bin/activate"

log_info "Virtual environment activated. Installing Python packages inside it."

# Install Conan inside the venv
pip install --upgrade pip
pip install conan

# --- Create build directory ---
BUILD_DIR="build"
log_step "Preparing clean build directory ('$BUILD_DIR')"
rm -rf "$BUILD_DIR"
mkdir "$BUILD_DIR"

# --- Configure Conan ---
log_step "Installing C++ dependencies with Conan..."

cd "$BUILD_DIR"

if ! conan profile list | grep -q default; then
    log_info "No default Conan profile found. Detecting..."
    conan profile detect --force
fi

conan install .. --build=missing -s build_type=Release

# --- Build with CMake ---
log_step "Building the NEye project with CMake..."

if [ ! -f "Release/generators/conan_toolchain.cmake" ]; then
    log_error "Conan did not create the toolchain file. 'conan install' may have failed."
    cd ..
    exit 1
fi

cmake .. -DCMAKE_TOOLCHAIN_FILE=Release/generators/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build . -- -j$(nproc)

if [ ! -f "NEye" ]; then
    log_error "Build failed. The 'NEye' executable was not found."
    cd ..
    exit 1
fi

log_info "Project built successfully! Executable is at '$BUILD_DIR/NEye'."

cd ..

# --- Run the application ---
log_step "Running NEye Network Monitor..."
log_warn "NEye requires root privileges for packet capture."
echo ""
run_with_sudo ./"$BUILD_DIR/NEye"
