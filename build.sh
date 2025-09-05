#!/bin/bash

# AntiWipe KPM Module Builder
# For KernelSU protection against malicious wipe scripts

set -e

MODULE_NAME="antiwipe"
MODULE_VERSION="1.0.0"
BUILD_DIR="$(pwd)/build"
OUTPUT_DIR="$(pwd)/output"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== AntiWipe KPM Module Builder ===${NC}"
echo -e "${YELLOW}Version: ${MODULE_VERSION}${NC}"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   echo -e "${RED}Please do not run as root${NC}"
   exit 1
fi

# Create directories
mkdir -p "$BUILD_DIR"
mkdir -p "$OUTPUT_DIR"

# Create main.c
cat > "$BUILD_DIR/main.c" << 'EOF'
[Insert the main.c content from above]
EOF

# Create Makefile
cat > "$BUILD_DIR/Makefile" << 'EOF'
[Insert the Makefile content from above]
EOF

# Create module.json
cat > "$BUILD_DIR/module.json" << 'EOF'
[Insert the module.json content from above]
EOF

# Create README
cat > "$BUILD_DIR/README.md" << 'EOF'
# AntiWipe KPM Module

## Description
This KernelSU KPM module protects your device against malicious wipe scripts that attempt to destroy your data.

## Features
- Blocks write access to critical partitions
- Intercepts dangerous commands (dd, mkfs, format, etc.)
- Protects /dev/input/* devices
- User confirmation dialog for dangerous operations
- Volume key controls (Volume+ to confirm, Volume- to deny)

## Installation
1. Install KernelSU on your device
2. Install this module through KernelSU Manager
3. Reboot your device

## Protected Partitions
persist, vm-persist, modem_a/b, modemst1/2, fsg, fsc, abl_a/b, featenabler_a/b, xbl_*, vendor_boot_a/b, ocdt

## Usage
When a dangerous operation is detected:
- A warning will appear in the kernel log
- Press Volume+ within 5 seconds to allow the operation
- Press Volume- or wait 5 seconds to block the operation

## License
GPL v2
EOF

# Build module
echo -e "${YELLOW}Building module...${NC}"
cd "$BUILD_DIR"

# Check for kernel headers
if [ ! -d "/lib/modules/$(uname -r)/build" ]; then
    echo -e "${RED}Error: Kernel headers not found${NC}"
    echo "Please install kernel headers for your kernel version"
    exit 1
fi

# Compile
make clean
make

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Build successful!${NC}"
    
    # Package module
    echo -e "${YELLOW}Packaging module...${NC}"
    
    # Create module structure
    MODULE_PKG="$OUTPUT_DIR/${MODULE_NAME}_v${MODULE_VERSION}"
    mkdir -p "$MODULE_PKG"
    
    cp "${MODULE_NAME}.ko" "$MODULE_PKG/"
    cp "module.json" "$MODULE_PKG/"
    cp "README.md" "$MODULE_PKG/"
    
    # Create install script
    cat > "$MODULE_PKG/install.sh" << 'INSTALL_EOF'
#!/system/bin/sh
# AntiWipe Module Installer

MODULE_PATH="/data/adb/kpm/antiwipe"
mkdir -p "$MODULE_PATH"

cp -f antiwipe.ko "$MODULE_PATH/"
cp -f module.json "$MODULE_PATH/"
cp -f README.md "$MODULE_PATH/"

# Set permissions
chmod 644 "$MODULE_PATH/antiwipe.ko"
chmod 644 "$MODULE_PATH/module.json"
chmod 644 "$MODULE_PATH/README.md"

# Load module
insmod "$MODULE_PATH/antiwipe.ko"

echo "AntiWipe module installed successfully!"
echo "The module will protect against malicious wipe attempts"
INSTALL_EOF
    
    chmod +x "$MODULE_PKG/install.sh"
    
    # Create ZIP package
    cd "$OUTPUT_DIR"
    zip -r "${MODULE_NAME}_v${MODULE_VERSION}.zip" "${MODULE_NAME}_v${MODULE_VERSION}"
    
    echo -e "${GREEN}Module packaged successfully!${NC}"
    echo -e "${GREEN}Output: $OUTPUT_DIR/${MODULE_NAME}_v${MODULE_VERSION}.zip${NC}"
else
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

# Cleanup
rm -rf "$BUILD_DIR"

echo ""
echo -e "${GREEN}=== Build Complete ===${NC}"
echo -e "${YELLOW}To install:${NC}"
echo "1. Copy ${MODULE_NAME}_v${MODULE_VERSION}.zip to your device"
echo "2. Install through KernelSU Manager"
echo "3. Reboot your device"
echo ""
echo -e "${YELLOW}GitHub Actions workflow:${NC}"
echo "Use the provided github-workflow.yml for automated builds"