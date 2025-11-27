#!/bin/bash

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "Installing NVIDIA drivers..."
# explicitly install dependencies of our version of nvidia drivers upfront because we
# have to disable default apt sources while installing nvidia drivers to prevent version conflicts
apt-get -qq install -y build-essential libxml2 libncurses5-dev pkg-config libvulkan1 \
  libgbm1 libwayland-server0 xorg-video-abi-25 xserver-xorg-core

echo "Download drivers installer..."
wget --no-verbose https://us.download.nvidia.com/tesla/580.82.07/nvidia-driver-local-repo-ubuntu2204-580.82.07_1.0-1_amd64.deb

echo "Installing NVIDIA driver repository..."
dpkg --install nvidia-driver-local-repo-*.deb &>/dev/null

echo "Adding NVIDIA GPG key..."
cp /var/nvidia-driver-local-repo-*/nvidia-driver-*-keyring.gpg /usr/share/keyrings/

# temporarily remove ubuntu apt sources, they may provide dependencies to nvidia drivers in versions newer than included in the local repository
# apt would prefer newer versions and we'd end up with mismatched versions of drivers and libraries
mv /etc/apt/sources.list /sources.list

echo "Updating package list..."
apt-get -qq update --yes

# echo DMKS config
apt-get install -y dkms
touch /etc/dkms/framework.conf
echo /etc/dkms/framework.conf
echo "mok_certificate=/tmp/signing_key.der" >> /etc/dkms/framework.conf
echo "mok_signing_key=/tmp/signing_key.pem" >> /etc/dkms/framework.conf
# done

echo "Installing NVIDIA drivers and tools..."
apt-get -qq install -y nvidia-open-580 nvidia-fabricmanager-580 libnvidia-nscq-580

mv /sources.list /etc/apt/sources.list

echo "Enable Linux Kernel Crypto API (LKCA) to configure a secure communication between the GPU and the GPU driver."
echo "install nvidia /sbin/modprobe ecdsa_generic; /sbin/modprobe ecdh; /sbin/modprobe --ignore-install nvidia" | tee /etc/modprobe.d/nvidia-lkca.conf
update-initramfs -u

echo "Enable persistence mode to ensure a secure Security Protocol and Data Model (SPDM) connection between the GPU and the GPU driver."

mkdir -p /etc/systemd/system/nvidia-persistenced.service.d
cat > /etc/systemd/system/nvidia-persistenced.service.d/override.conf <<'EOF'
[Unit]
# No Requires or single GPU won't work
# Requires=nvidia-fabricmanager.service
After=nvidia-fabricmanager.service

[Service]
# clear previous ExecStart value
ExecStart=
ExecStart=/usr/bin/nvidia-persistenced --user nvpd --uvm-persistence-mode --verbose
PIDFile=/var/run/nvidia-persistenced/nvidia-persistenced.pid
Restart=always
TimeoutSec=300

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /etc/systemd/system/ollama.service.d
cat > /etc/systemd/system/ollama.service.d/override.conf <<'EOF'
[Unit]
After=nvidia-persistenced.service
# no Required, we want to run ollama even if the nvidia-persistenced failed in case there are not GPUs available.
EOF

systemctl daemon-reload
systemctl enable nvidia-persistenced.service
systemctl enable nvidia-fabricmanager.service

# Remove local repository, we won't be installing anything more from it
rm /usr/share/keyrings/nvidia-driver-*-keyring.gpg
dpkg -l | grep nvidia-driver-local-repo | grep 'ii ' | awk '{print $2}' | xargs dpkg --purge
rm nvidia-driver-local-repo-*.deb

shutdown -r now
