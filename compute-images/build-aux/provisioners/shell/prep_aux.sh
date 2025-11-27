#!/bin/bash
# Because we're building the base image with two mounted instances of the same exact Ubuntu image,
# we need to first tweak the partition UUIDs so that our machine mounts everything in the correct order
# deterministically.
set -eux

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

ROOT_ID="1"
GRUB_ID="14"
EFI_ID="15"

OLD_ROOT_DEV="${OLD_DEV}${PART_PREFIX}${ROOT_ID}"

NEW_ROOT_DEV="${NEW_DEV}${PART_PREFIX}${ROOT_ID}"
NEW_GRUB_DEV="${NEW_DEV}${PART_PREFIX}${GRUB_ID}"
NEW_EFI_DEV="${NEW_DEV}${PART_PREFIX}${EFI_ID}"

get_dev_sector_size() {
	blockdev --getss "$1"
}

get_dev_sectors() {
	blockdev --getsz "$1"
}

wait_umount() {
	while mountpoint -q "$1"; do
		umount -fl "$1" || true
		echo "Waiting for $1 to unmount..."
		sleep 1
	done

	findmnt "$1" || echo "$1 unmounted successfully"
}

lsblk -f
mount
blkid

if ! findmnt $OLD_ROOT_DEV; then
	echo "Primary / partition not mounted. This is potentially due to a race condition in GCP. Please try again." >&2
	exit 13
fi

echo "----- BEGIN CHANGING UUIDS -----"
wait_umount /boot/efi
e2fsck -f -y $NEW_ROOT_DEV
tune2fs -U random $NEW_ROOT_DEV
sgdisk --randomize-guids=$ROOT_ID $NEW_DEV
partprobe
udevadm settle
lsblk -o NAME,PARTTYPE,PARTUUID,PARTLABEL,TYPE,UUID,LABEL
blkid $NEW_ROOT_DEV
echo "----- END CHANGING UUIDS -----"

echo "----- BEGIN WIPING PARTITIONS -----"
dd if=/dev/zero of="$NEW_ROOT_DEV" bs="$(get_dev_sector_size "$NEW_ROOT_DEV")" count="$(get_dev_sectors "$NEW_ROOT_DEV")"
dd if=/dev/zero of="$NEW_GRUB_DEV" bs="$(get_dev_sector_size "$NEW_GRUB_DEV")" count="$(get_dev_sectors "$NEW_GRUB_DEV")"
dd if=/dev/zero of="$NEW_EFI_DEV" bs="$(get_dev_sector_size "$NEW_EFI_DEV")" count="$(get_dev_sectors "$NEW_EFI_DEV")"
echo "----- END WIPING PARTITIONS -----"
