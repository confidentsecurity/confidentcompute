#!/bin/bash

# Script to install mainline kernel 6.16.7 debs in /tmp/ directory

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# Required by the 6.16.7 kernel
sudo apt-get update -qq && apt-get install -qq -y wireless-regdb

echo "Extracting kernel debs..."
cd /tmp
tar -xf kernel-deb.tar

echo "Installing kernel packages..."

# Install packages in correct order
sudo dpkg -i /tmp/kernel-deb/linux-*.deb

# Fix any broken dependencies
sudo apt-get install -f -y

# Update GRUB
echo "Updating GRUB configuration..."
sudo update-grub

echo "Kernel from /tmp/linux-*.deb installed successfully!"
echo "The system will now reboot:"
shutdown -r now
