#!/bin/bash

# Script to install mainline kernel 6.16.7 debs in /tmp/ directory

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "Removing old kernels..."
apt-get purge --autoremove -qq --yes linux-image-5.* linux-headers-5.*

# Update GRUB
echo "Updating GRUB configuration..."
sudo update-grub
