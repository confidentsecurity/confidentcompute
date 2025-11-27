#!/bin/sh
set -eux

OLD_ROOT_ID="1"
# OLD_EFI_ID="15"

case "$CONFSEC_DISK_INTERFACE" in
"NVME")
	OLD_DEV="/dev/nvme0n1"
	NEW_DEV="/dev/nvme0n2"
	PART_PREFIX="p"
	;;
"SCSI")
	OLD_DEV="/dev/sda"
	NEW_DEV="/dev/sdb"
	PART_PREFIX=""
	;;
*)
	echo "$CONFSEC_DISK_INTERFACE not a valid disk interface." >&2
	exit 64
	;;
esac

OLD_ROOT_DEV="${OLD_DEV}${PART_PREFIX}${OLD_ROOT_ID}"
# OLD_EFI_DEV="${OLD_DEV}${PART_PREFIX}${OLD_EFI_ID}"

# NEW_ROOT_DEV="${NEW_DEV}${PART_PREFIX}${OLD_ROOT_ID}"
# NEW_EFI_DEV="${NEW_DEV}${PART_PREFIX}${OLD_EFI_ID}"

mount
blkid
lsblk

if ! findmnt $OLD_ROOT_DEV; then
	echo "Primary / partition not mounted. This is due to a race condition in GCP. Please try again." >&2
	exit 13
fi

# TODO: We don't care about this anymore.
# if ! findmnt $NEW_EFI_DEV; then
# 	if findmnt $OLD_EFI_DEV; then
# 		echo "Wrong /boot/efi partition is mounted. Attempting to fix..."
# 		umount /boot/efi
# 		mount --source $NEW_EFI_DEV --target /boot/efi
# 	fi
# fi

# NOTE: Basic sanity checks. This can be made more robust.
check_root_dev() {
	if [ -b "$1" ]; then
		echo "$1 exists."
	else
		echo "$1 does not exist." >&2
		exit 1
	fi

	if file -s "$1" | grep -q "ext4"; then
		echo "$1 is ext4."
	else
		echo "$1 is not ext4." >&2
		exit 1
	fi
}

check_root_dev $OLD_ROOT_DEV
# check_root_dev $NEW_ROOT_DEV

HOST_SIZE=$(blockdev --getsize64 $OLD_DEV)
AUX_SIZE=$(blockdev --getsize64 $NEW_DEV)

if [ "$HOST_SIZE" -gt "$AUX_SIZE" ]; then
	echo "Source volume cannot be larger than destination volume." >&2
	exit 1
fi

echo "----- BEGIN BLOCK DEVICE INFO -----"
lsblk -f
fdisk $OLD_DEV <<EOF
p
x
p
EOF
fdisk $NEW_DEV <<EOF
p
x
p
EOF
blkid
echo "----- END BLOCK DEVICE INFO -----"
