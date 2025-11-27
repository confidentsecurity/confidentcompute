#!/bin/bash
set -eux

add-apt-repository -y universe
# add-apt-repository -y multiverse
apt-get update
apt-get -y upgrade
apt-get -y dist-upgrade
apt-get -y autoremove
apt-get -yf install
apt-get -y install \
	auditd \
	build-essential \
	clevis \
	clevis-dracut \
	clevis-luks \
	clevis-systemd \
	clevis-tpm2 \
	cloud-utils \
	cryptsetup \
	dracut \
	dracut-core \
	dracut-network \
	e2fsprogs \
	gdisk \
	grub-efi-amd64-signed \
	ima-evm-utils \
	keyutils \
	libnuma-dev \
	mount \
	openssl \
	policycoreutils \
	rsync \
	selinux-basics \
	selinux-policy-mls \
	selinux-utils \
	shim-signed \
	tpm2-tools \
	tree \
	ufw \
	unzip \
	zsh \
	jq

# ufw
ufw enable

# alloy
apt-get install -y apt-transport-https software-properties-common
curl -q https://apt.grafana.com/gpg.key | gpg --dearmor -o /usr/share/keyrings/grafana.gpg
echo "deb [signed-by=/usr/share/keyrings/grafana.gpg] https://apt.grafana.com stable main" >>/etc/apt/sources.list.d/grafana.list
apt-get update
apt-get install -y alloy
systemctl daemon-reload
systemctl enable alloy.service

# Install gcloud CLI only for GCP builds
if [ "${CLOUD:-}" = "gcp" ]; then
    # glcoud
    apt-get install -y apt-transport-https ca-certificates gnupg curl
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" >>/etc/apt/sources.list.d/google-cloud-sdk.list
    apt-get update
    apt-get -y install google-cloud-cli
fi

# Needed for the `install-nvidia.sh` script.
apt-get -y install initramfs-tools

# Yes, this is the documented and correct way to install ollama.
curl -fsSL https://ollama.com/install.sh | sh
systemctl daemon-reload
systemctl enable ollama.service

# Explicitly enable tpm support in GRUB.
echo "insmod tpm" >>/etc/grub.d/40_insmod_tpm
tree /etc/grub.d

for file in /etc/grub.d/*; do
	[ -f "$file" ] || continue
	echo "----- BEGIN $file -----"
	cat "$file"
	echo -e "\n----- END $file -----"
done

apt-get -y autoremove
apt-get -yf install
blkid
lsblk -f
