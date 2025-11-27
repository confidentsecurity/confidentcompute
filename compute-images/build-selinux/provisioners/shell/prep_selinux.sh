#!/bin/bash
# Liberas 2025
# Adding "ima_appraise=log" parameter to GRUB_CMDLINE_LINUX_DEFAULT
# used in conjunction with our ima_policy dropped in /etc

set -e
# Ubuntus default hardening is apparmor, it intereferes with selinux so it needs to go
systemctl stop apparmor
systemctl disable apparmor

# Activate selinux
selinux-activate

fixfiles onboot
useradd ubuntu || true
usermod ubuntu -s /usr/bin/zsh

# GRUB configuration file
GRUB_FILE="/etc/default/grub"
BACKUP_FILE="/etc/default/grub.bak.$(date +%Y%m%d%H%M%S)"

echo "Backing up $GRUB_FILE to $BACKUP_FILE..."
cp "$GRUB_FILE" "$BACKUP_FILE"

# Check if GRUB_CMDLINE_LINUX_DEFAULT already contains an IMA parameter.
if grep -q "ima_appraise" "$GRUB_FILE"; then
	echo "The GRUB configuration already contains an IMA appraisal parameter. No changes made."
else
	echo "Adding to GRUB_CMDLINE_LINUX"
	sed -i 's/\(GRUB_CMDLINE_LINUX="\(.*\)\)"/\1 ima_appraise=fix ima_appraise_tcb"/' "$GRUB_FILE"
	sed -i 's/quiet//' "$GRUB_FILE"
fi

# We need to enable initramfs booting here (-f because this file may not exist on qemu images)
rm -f /etc/default/grub.d/40-force-partuuid.cfg

cat "$GRUB_FILE"

echo "Updating GRUB configuration..."
update-grub

echo "Configuration complete. Please reboot your system for IMA measurement mode to take effect."

cp -r /tmp/confident_policy /etc/selinux/confident_policy
sed -i 's/default/confident_policy/g' /etc/selinux/config
cat /etc/selinux/config

reboot
# Sleeping to avoid the next provisioning step from happening
sleep 20
