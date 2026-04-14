#!/bin/bash

set -e

echo "Smart Net Mapper Installer"
echo "[+] Installing Smart Net Mapper..."

# Detect package manager and install nmap
if command -v pacman &> /dev/null; then
    sudo pacman -S --noconfirm nmap
elif command -v apt &> /dev/null; then
    sudo apt update && sudo apt install -y nmap
elif command -v dnf &> /dev/null; then
    sudo dnf install -y nmap
else
    echo "[-] Could not detect package manager. Install nmap manually."
    exit 1
fi

# Make script executable
chmod +x smart_net_mapper.py

# Install globally
sudo cp smart_net_mapper.py /usr/local/bin/netmap

echo "[+] Installation complete!"
echo "[+] Run the tool using: sudo netmap"
