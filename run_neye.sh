#!/bin/bash
#
# NEye - Simple Install, Build, and Run Script
# (Tailored to the 'cd build && cmake ..' workflow)
#

# Exit immediately if any command fails
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

# --- Sudo Check and Elevation ---
run_with_sudo() {
    if [ "$EUID" -ne 0 ]; then
        log_warn "Sudo privileges are required for this step."
        sudo "$@"
    else
        "$@"
    fi
}

# --- Main Script Logic ---

# 1. Install System Dependencies (Requires Sudo)
log_step "Installing system dependencies..."
log_info "This step requires root privileges to use 'apt'."
run_with_sudo apt-get update -y
run_with_sudo apt-get install -y build-essential cmake git python3-pip libpcap-dev libcurl4-openssl-dev xterm

# --- Create a clean build directory ---
BUILD_DIR="build"
log_step "Preparing a clean build directory ('$BUILD_DIR')"
rm -rf "$BUILD_DIR"
mkdir "$BUILD_DIR"

# 2. Configure Conan and Install C++ Dependencies (No Sudo Needed)
log_step "Installing C++ dependencies with Conan..."

# Change into the build directory
cd "$BUILD_DIR"

# Conan and CMake should run as the regular user.
if ! conan profile list | grep -q default; then
    log_info "No default Conan profile found. Detecting a new one..."
    conan profile detect --force
fi

log_info "Running 'conan install' for a Release build..."
# This is YOUR conan command. We run it from inside the build directory.
conan install .. --build=missing -s build_type=Release

# 3. Build the NEye Project with CMake (No Sudo Needed)
log_step "Building the NEye project with CMake..."

# Check if the Conan toolchain file was created at the expected path
if [ ! -f "Release/generators/conan_toolchain.cmake" ]; then
    log_error "Conan did not create the toolchain file. 'conan install' may have failed."
    cd ..
    exit 1
fi

# This is YOUR cmake command. We run it from inside the build directory.
cmake .. -DCMAKE_TOOLCHAIN_FILE=Release/generators/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release

# Compile the project using all available CPU cores
log_info "Compiling the project..."
cmake --build . -- -j$(nproc)

# Verify that the final executable was created in the current (build) directory
if [ ! -f "NEye" ]; then
    log_error "Build failed. The 'NEye' executable was not found."
    cd ..
    exit 1
fi

log_info "Project built successfully! Executable is at '$BUILD_DIR/NEye'."

# Return to the project's root directory
cd ..

# 4. Run the NEye Application (Requires Sudo for Packet Capture)
log_step "Running NEye Network Monitor..."
log_warn "NEye requires root privileges for network packet capture."
log_warn "You will be prompted for your password to run the application."
echo ""

# Run the compiled executable with sudo from the project root
run_with_sudo ./"$BUILD_DIR/NEye"
