#! /bin/sh

set -eu
# Check if NVIDIA drivers and software are already installed
echo "Checking if NVIDIA drivers and software are already installed"

if nvidia-smi > /dev/null 2>&1; then
    echo "NVIDIA drivers and software already installed"
    echo "."
    exit
fi

if [ -z "$CLOUD" ]; then
  echo "Error: CLOUD is not set or empty"
  exit 1
fi

echo "Installing NVIDIA drivers and software on first boot..."
apt-get -qq update --yes
DEBIAN_FRONTEND=noninteractive apt-get -qq install linux-headers-"$(uname -r)"
DEBIAN_FRONTEND=noninteractive apt-get -qq install -y build-essential libxml2 libncurses5-dev pkg-config libvulkan1

echo "Installing NVIDIA driver..."
DEBIAN_FRONTEND=noninteractive apt-get -qq install -y linux-modules-nvidia-550-server-open-"${CLOUD}" nvidia-driver-550-server-open

echo "Enable Linux Kernel Crypto API (LKCA) to configure a secure communication between the GPU and the GPU driver."
echo "install nvidia /sbin/modprobe ecdsa_generic; /sbin/modprobe ecdh; /sbin/modprobe --ignore-install nvidia" | tee /etc/modprobe.d/nvidia-lkca.conf
update-initramfs -u

echo "Enable persistence mode to ensure a secure Security Protocol and Data Model (SPDM) connection between the GPU and the GPU driver."
test -f /usr/lib/systemd/system/nvidia-persistenced.service && sed -i "s/no-persistence-mode/uvm-persistence-mode/g" /usr/lib/systemd/system/nvidia-persistenced.service

shutdown -r now
