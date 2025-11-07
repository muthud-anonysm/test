#!/bin/bash

# CMS Recon Tool - Scanner Installation Script
# This script installs common CMS and web application security scanning tools

set -e

echo "=================================="
echo "CMS Recon Scanner Installation"
echo "=================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${YELLOW}Warning: Running as root. Some tools may not work correctly.${NC}"
    sleep 2
fi

# Create tools directory
TOOLS_DIR="$HOME/security-tools"
mkdir -p "$TOOLS_DIR"
cd "$TOOLS_DIR"

echo -e "${GREEN}[+] Installing system dependencies...${NC}"
sudo apt update
sudo apt install -y git python3 python3-pip ruby ruby-dev build-essential curl wget

# Install WPScan (WordPress Scanner)
echo ""
echo -e "${GREEN}[+] Installing WPScan...${NC}"
if command -v wpscan &> /dev/null; then
    echo "WPScan already installed"
else
    sudo gem install wpscan
    echo "Run 'wpscan --update' to update the database"
fi

# Install JoomScan (Joomla Scanner)
echo ""
echo -e "${GREEN}[+] Installing JoomScan...${NC}"
if [ ! -d "$TOOLS_DIR/joomscan" ]; then
    git clone https://github.com/OWASP/joomscan.git
    cd joomscan
    chmod +x joomscan.pl
    # Create symlink
    sudo ln -sf "$PWD/joomscan.pl" /usr/local/bin/joomscan
    cd ..
    echo "JoomScan installed"
else
    echo "JoomScan already installed"
fi

# Install Droopescan (Drupal Scanner)
echo ""
echo -e "${GREEN}[+] Installing Droopescan...${NC}"
if command -v droopescan &> /dev/null; then
    echo "Droopescan already installed"
else
    pip3 install droopescan
fi

# Install CMSeeK (Multi-CMS Scanner)
echo ""
echo -e "${GREEN}[+] Installing CMSeeK...${NC}"
if [ ! -d "$TOOLS_DIR/CMSeeK" ]; then
    git clone https://github.com/Tuhinshubhra/CMSeeK.git
    cd CMSeeK
    pip3 install -r requirements.txt
    chmod +x cmseek.py
    # Create wrapper script
    echo '#!/bin/bash' > /usr/local/bin/cmseek
    echo "python3 $PWD/cmseek.py \"\$@\"" >> /usr/local/bin/cmseek
    sudo chmod +x /usr/local/bin/cmseek
    cd ..
    echo "CMSeeK installed"
else
    echo "CMSeeK already installed"
fi

# Install ffuf (Fuzzer)
echo ""
echo -e "${GREEN}[+] Installing ffuf...${NC}"
if command -v ffuf &> /dev/null; then
    echo "ffuf already installed"
else
    go install github.com/ffuf/ffuf/v2@latest
    # Add Go bin to PATH if not already there
    if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
        export PATH=$PATH:$HOME/go/bin
    fi
fi

# Install Gobuster (Directory brute force)
echo ""
echo -e "${GREEN}[+] Installing Gobuster...${NC}"
if command -v gobuster &> /dev/null; then
    echo "Gobuster already installed"
else
    go install github.com/OJ/gobuster/v3@latest
fi

# Install Nuclei (Vulnerability Scanner)
echo ""
echo -e "${GREEN}[+] Installing Nuclei...${NC}"
if command -v nuclei &> /dev/null; then
    echo "Nuclei already installed"
else
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    nuclei -update-templates
fi

# Install SecLists (Wordlists)
echo ""
echo -e "${GREEN}[+] Installing SecLists...${NC}"
if [ ! -d "/usr/share/seclists" ]; then
    if [ -d "$TOOLS_DIR/SecLists" ]; then
        echo "SecLists already in tools directory"
    else
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git
        sudo ln -sf "$PWD/SecLists" /usr/share/seclists
    fi
else
    echo "SecLists already installed"
fi

# Install common wordlists
echo ""
echo -e "${GREEN}[+] Installing common wordlists...${NC}"
sudo apt install -y wordlists

echo ""
echo -e "${GREEN}=================================="
echo "Installation Complete!"
echo "==================================${NC}"
echo ""
echo "Installed tools:"
echo "  - wpscan (WordPress)"
echo "  - joomscan (Joomla)"
echo "  - droopescan (Drupal)"
echo "  - cmseek (Multi-CMS)"
echo "  - ffuf (Fuzzer)"
echo "  - gobuster (Directory brute force)"
echo "  - nuclei (Vulnerability scanner)"
echo "  - SecLists (Wordlists)"
echo ""
echo -e "${YELLOW}Note: You may need to restart your shell or run 'source ~/.bashrc'${NC}"
echo ""
echo "Test installations:"
echo "  wpscan --version"
echo "  joomscan --version"
echo "  droopescan --version"
echo "  cmseek -h"
echo "  ffuf -V"
echo "  gobuster version"
echo "  nuclei -version"
echo ""
echo "Update WPScan database:"
echo "  wpscan --update"
echo ""
