#!/bin/bash
# WARNING: This script is written for the ubuntu-2204-jammy-v20250508 image on GCP.
set -eux

if [ -z "$CONFSEC_BUILD_ID" ]; then
	echo "CONFSEC_BUILD_ID must be set!" >&2
	exit 64
fi

if ! [[ "$CONFSEC_BUILD_ID" =~ ^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$ ]]; then
	echo "CONFSEC_BUILD_ID must be a valid UUID: $CONFSEC_BUILD_ID" >&2
	exit 64
fi

if ! [[ "$CONFSEC_HARDENING_SCOPE" =~ ^[0-9]+$ ]] || [ "$CONFSEC_HARDENING_SCOPE" -lt 0 ]; then
	echo "CONFSEC_HARDENING_SCOPE must be a non-negative integer: $CONFSEC_HARDENING_SCOPE" >&2
	exit 64
fi

HARDEN_KERNEL_CMDLINE=" lsm=lockdown,capability,landlock,yama,selinux,integrity apparmor=0 selinux=1"
HARDEN_INTEGRITY_FLAGS=""
HARDEN_VERITY_MODE="ignore-corruption"
HARDEN_DRACUT_PANIC="emergency_shell"
HARDEN_NO_SERIAL=0
DISABLE_VLLM_METRICS="false"

case "$CONFSEC_HARDENING_SCOPE" in
0)
	# SEE: https://wiki.archlinux.org/title/Dm-verity#Additional%20recommended%20options
	# enforcing=1 enables SELinux enforcing
	# lockdown=confidentiality prevents users from accessing kernel memory
	# rd.emergency=reboot to prevents access to a shell if the root is corrupt
	# rd.shell=0 to prevents access to a shell if boot fails
	HARDEN_KERNEL_CMDLINE+=" enforcing=1 lockdown=confidentiality rd.emergency=reboot rd.shell=0"
	HARDEN_DRACUT_PANIC="die"
	DISABLE_VLLM_METRICS="true"
	;;
1)
	HARDEN_KERNEL_CMDLINE+=" enforcing=1"
	HARDEN_INTEGRITY_FLAGS="--integrity hmac-sha256"
	;;
*)
	HARDEN_KERNEL_CMDLINE+=" enforcing=1"
	echo "WARNING: Setting root password randomly for debug purposes."
	echo "root:$(head -c 48 /dev/urandom | base64 | head -c 64)" | chpasswd
	;;
esac

if [ "$CONFSEC_EPHEMERAL_INTEGRITY" = "true" ]; then
	echo "Enabling dm-integrity for ephemeral partitions!"
	HARDEN_INTEGRITY_FLAGS="--integrity hmac-sha256"
fi

if [ "$CONFSEC_VERITY_PANIC" = "true" ]; then
	echo "Enabling dm-verity panic-on-corruption!"
	HARDEN_VERITY_MODE="panic-on-corruption"
fi

if [ "$CONFSEC_NO_SERIAL" = "true" ]; then
	echo "Set to disable the cloud serial console!"
	HARDEN_NO_SERIAL=1
fi

if ! [[ "$CONFSEC_DEBUG_SCOPE" =~ ^[0-9]+$ ]] || [ "$CONFSEC_DEBUG_SCOPE" -lt 0 ]; then
	echo "CONFSEC_DEBUG_SCOPE must be a non-negative integer: $CONFSEC_DEBUG_SCOPE" >&2
	exit 64
fi

DEBUG_KERNEL_CMDLINE=""
DEBUG_UFW_LOGLEVEL="low"

case "$CONFSEC_DEBUG_SCOPE" in
0)
	DEBUG_KERNEL_CMDLINE=" systemd.log_level=debug systemd.log_target=console"
	DEBUG_UFW_LOGLEVEL="high"
	;;
1)
	DEBUG_UFW_LOGLEVEL="medium"
	;;
*) ;;
esac

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

OLD_ROOT_ID="1"
OLD_GRUB_ID="14"
OLD_EFI_ID="15"

NEW_EFI_ID="1"
NEW_BOOT_ID="2"
NEW_VERITY_ID="3"
NEW_VERITYROOT_ID="4"
NEW_ROOT_ID="5"
NEW_LVM_ID="6"

OLD_ROOT_DEV="${OLD_DEV}${PART_PREFIX}${OLD_ROOT_ID}"
OLD_EFI_DEV="${OLD_DEV}${PART_PREFIX}${OLD_EFI_ID}"

NEW_EFI_DEV="${NEW_DEV}${PART_PREFIX}${NEW_EFI_ID}"
NEW_BOOT_DEV="${NEW_DEV}${PART_PREFIX}${NEW_BOOT_ID}"
NEW_VERITY_DEV="${NEW_DEV}${PART_PREFIX}${NEW_VERITY_ID}"
NEW_VERITYROOT_DEV="${NEW_DEV}${PART_PREFIX}${NEW_VERITYROOT_ID}"
NEW_ROOT_DEV="${NEW_DEV}${PART_PREFIX}${NEW_ROOT_ID}"
NEW_LVM_DEV="${NEW_DEV}${PART_PREFIX}${NEW_LVM_ID}"

NEW_LVM_VG="os"
NEW_HOME_LV="home"
NEW_VAR_LV="var"

NEW_HOME_DEV="/dev/${NEW_LVM_VG}/${NEW_HOME_LV}"
NEW_VAR_DEV="/dev/${NEW_LVM_VG}/${NEW_VAR_LV}"

NEW_BOOT_NAME="BOOT"
NEW_VERITY_NAME="VERITY"
NEW_VERITYROOT_NAME="VERITYROOT"
NEW_ROOT_NAME="ROOT"
NEW_LVM_NAME="OS"
NEW_HOME_NAME="confident-home"
NEW_VAR_NAME="confident-var"

NEW_VERITY_MOUNT="/mnt/meta-verity"
NEW_ROOT_MOUNT="/mnt/aux"
NEW_VAR_MOUNT="${NEW_ROOT_MOUNT}/var"
NEW_HOME_MOUNT="${NEW_ROOT_MOUNT}/home"

get_dev_sector_size() {
	blockdev --getss "$1"
}

get_dev_sectors() {
	blockdev --getsz "$1"
}

print_dev_info() {
	echo ----- BEGIN DEV INFO "$1" -----
	parted "$1" print
	fdisk "$1" <<EOF
p
x
p
EOF
	lsblk -f
	partitions=$(lsblk -ln -o NAME,TYPE "$1" | awk '$2 == "part" {print "/dev/"$1}')

	for partition in $partitions; do
		blkid "$partition"
	done

	echo ----- END DEV INFO "$1" -----
}

get_dev_uuid() {
	blkid -s UUID "$1" | grep -oP 'UUID="\K[^"]+'
}

get_dev_partuuid() {
	blkid -s PARTUUID -o value "$1"
}

get_dev_partlabel() {
	blkid -s PARTLABEL -o value "$1"
}

get_dev_parttype() {
	lsblk -no PARTTYPE "$1" | sed -z 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

zero_dev() {
	if [ "$CONFSEC_OPTIMIZE_DISK" = "true" ]; then
		echo "Zeroing out $1"
		dd if=/dev/zero of="$1" bs="$(get_dev_sector_size "$1")" count="$(get_dev_sectors "$1")" || true
		sync
	fi
}

zero_dev_with_file() {
	if [ "$CONFSEC_OPTIMIZE_DISK" = "true" ]; then
		echo "Zeroing out remainder of $1 mounted at $2"
		zero_fill=$(uuidgen)
		dd if=/dev/zero of="$2/$zero_fill" bs="$(get_dev_sector_size "$1")" || true
		rm "$2/$zero_fill"
		sync
	fi
}

wait_umount() {
	while mountpoint -q "$1"; do
		umount -fl "$1" || true
		echo "Waiting for $1 to unmount..."
		sleep 1
	done

	findmnt "$1" || echo "$1 unmounted successfully"
}

hex_to_uuid() {
	# Lowercase
	local input="${1,,}"
	# Strip
	input="${input//[^0-9a-f]/}"

	# Pad
	while ((${#input} < 32)); do
		input="${input}0"
	done

	# Truncate
	input="${input:0:32}"

	# Format
	printf "%s-%s-%s-%s-%s\n" \
		"${input:0:8}" "${input:8:4}" "${input:12:4}" "${input:16:4}" "${input:20:12}"
}

hex32_to_uuid() {
	if [[ ! "$1" =~ ^[0-9a-fA-F]{32}$ ]]; then
		echo "Error: Input must be a 32-character hexadecimal string" >&2
		exit 13
	fi

	echo "${1:0:8}-${1:8:4}-${1:12:4}-${1:16:4}-${1:20:12}" | tr '[:upper:]' '[:lower:]'
}

xor_hex32() {
	hex="$1"
	mask="$2"
	result=""

	for i in {0..31..2}; do
		byte_uuid="0x${hex:$i:2}"
		byte_mask="0x${mask:$i:2}"
		xor_result=$(printf "%02x" $((byte_uuid ^ byte_mask)))
		result+="$xor_result"
	done

	echo "$result"
}

umount_retry() {
	local target="$1"
	local retries=10
	local count=0

	while ((count < retries)); do
		# Try to unmount and capture any error message
		if err_msg=$(umount "$target" 2>&1); then
			return 0
		elif [[ "$err_msg" == *"target is busy"* ]]; then
			echo "Attempt $((count + 1)) failed: $target is busy. Retrying in 1 second..."
			sleep 1
			count=$((count + 1))
		else
			echo "Failed to unmount $target: $err_msg"
			return 1
		fi
	done

	echo "Failed to unmount $target after $retries attempts: target is still busy."
	return 1
}

selinux_relabel() {
	# ROOT_MOUNT RELABEL_DIR [RELABEL_DIR ...]
	local root_mnt="$1"
	shift
	mount --bind /dev "${root_mnt}/dev"
	mount --bind /proc "${root_mnt}/proc"
	mount --bind /sys "${root_mnt}/sys"
	chroot "$root_mnt" /bin/bash -s "$@" <<'EOF'
for relabel_dir in "$@"; do
    restorecon -Rv "$relabel_dir"
done
exit
EOF
	# (QEMU only) Unmounting //dev sometimes fails with 'device is busy', retry if that happens
	umount_retry "${root_mnt}/dev"
	umount_retry "${root_mnt}/proc"
	umount_retry "${root_mnt}/sys"
}

echo "----- BEGIN FORMATTING AUXILIARY VOLUME -----"
lsblk -f
wait_umount /boot/efi
# Blow away the ext4 metadata on the old root so fdisk doesn't yell at us.
dd if=/dev/zero of="${NEW_DEV}${PART_PREFIX}${OLD_ROOT_ID}" bs="$(get_dev_sector_size "${NEW_DEV}${PART_PREFIX}${OLD_ROOT_ID}")" count=1024
# Blow away the GRUB BIOS & UEFI partitions.
dd if=/dev/zero of="${NEW_DEV}${PART_PREFIX}${OLD_GRUB_ID}" bs="$(get_dev_sector_size "${NEW_DEV}${PART_PREFIX}${OLD_GRUB_ID}")" count="$(get_dev_sectors "${NEW_DEV}${PART_PREFIX}${OLD_GRUB_ID}")"
dd if=/dev/zero of="${NEW_DEV}${PART_PREFIX}${OLD_EFI_ID}" bs="$(get_dev_sector_size "${NEW_DEV}${PART_PREFIX}${OLD_EFI_ID}")" count="$(get_dev_sectors "${NEW_DEV}${PART_PREFIX}${OLD_EFI_ID}")"

# 106M
EFI_SECTORS=$(get_dev_sectors "$OLD_EFI_DEV")
# 1G
BOOT_SECTORS=2097152
# 512M
VERITY_SECTORS=1048576
# 512M
VERITYROOT_SECTORS=1048576
# 24G
ROOT_SECTORS=50331648

# Wipe the old partitions and start over.
fdisk $NEW_DEV <<EOF
d
$OLD_ROOT_ID
d
$OLD_GRUB_ID
d
n
$NEW_EFI_ID

+$EFI_SECTORS
n
$NEW_BOOT_ID

+$BOOT_SECTORS
n
$NEW_VERITY_ID

+$VERITY_SECTORS
n
$NEW_VERITYROOT_ID

+$VERITYROOT_SECTORS
n
$NEW_ROOT_ID

+$ROOT_SECTORS
n
$NEW_LVM_ID


w
EOF
partprobe
udevadm settle
sleep 15
lsblk -f

OLD_EFI_PARTLABEL=$(get_dev_partlabel $OLD_EFI_DEV)
OLD_EFI_PARTTYPE=$(get_dev_parttype $OLD_EFI_DEV)
OLD_EFI_SECTOR_SIZE=$(get_dev_sector_size $OLD_EFI_DEV)
NEW_EFI_SECTOR_SIZE=$(get_dev_sector_size $NEW_EFI_DEV)

if [[ "$OLD_EFI_SECTOR_SIZE" != "$NEW_EFI_SECTOR_SIZE" ]]; then
	echo "UEFI partition sector size mismatch: $OLD_EFI_SECTOR_SIZE != $NEW_EFI_SECTOR_SIZE" >&2
	exit 13
fi

# NOTE: Zero-out the new meta-verity parition because fdisk only modifies the GPT layout, not the underlying partition.
dd if=$OLD_EFI_DEV of=$NEW_EFI_DEV bs="$NEW_EFI_SECTOR_SIZE"
dd if=/dev/zero of=$NEW_BOOT_DEV bs="$(get_dev_sector_size $NEW_BOOT_DEV)" count=$BOOT_SECTORS
dd if=/dev/zero of=$NEW_VERITY_DEV bs="$(get_dev_sector_size $NEW_VERITY_DEV)" count=$VERITY_SECTORS
dd if=/dev/zero of=$NEW_VERITYROOT_DEV bs="$(get_dev_sector_size $NEW_VERITYROOT_DEV)" count=$VERITYROOT_SECTORS
# NOTE: Wiping disk moved to build-aux
# zero_dev $NEW_ROOT_DEV
# zero_dev $NEW_LVM_DEV

sgdisk --disk-guid="$(uuidgen -n @dns -N "confident.security" --sha1)" "$NEW_DEV"
EFI_GUID=$(hex_to_uuid "$CONFSEC_GIT")
sgdisk --partition-guid="$NEW_EFI_ID":"$EFI_GUID" "$NEW_DEV"
# NOTE: This gets set to the inverse of the git commit hash of the `compute-base` build downstream.
BOOT_GUID=$(hex32_to_uuid "$(xor_hex32 "${EFI_GUID//-/}" "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")")
sgdisk --partition-guid="$NEW_BOOT_ID":"$BOOT_GUID" "$NEW_DEV"
sgdisk --partition-guid="$NEW_ROOT_ID":"$CONFSEC_BUILD_ID" "$NEW_DEV"
sgdisk --change-name="$NEW_EFI_ID":"$OLD_EFI_PARTLABEL" "$NEW_DEV"
sgdisk --change-name="$NEW_BOOT_ID":"$NEW_BOOT_NAME" "$NEW_DEV"
sgdisk --change-name="$NEW_VERITY_ID":"$NEW_VERITY_NAME" "$NEW_DEV"
sgdisk --change-name="$NEW_VERITYROOT_ID":"$NEW_VERITYROOT_NAME" "$NEW_DEV"
sgdisk --change-name="$NEW_ROOT_ID":"$NEW_ROOT_NAME" "$NEW_DEV"
sgdisk --change-name="$NEW_LVM_ID":"$NEW_LVM_NAME" "$NEW_DEV"
# SEE: https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs
#      https://uapi-group.org/specifications/specs/discoverable_partitions_specification/
sgdisk --typecode="$NEW_EFI_ID":"${OLD_EFI_PARTTYPE^^}" "$NEW_DEV"
sgdisk --typecode="$NEW_VERITYROOT_ID":"41092B05-9FC8-4523-994F-2DEF0408B176" "$NEW_DEV"

case "$(uname -m)" in
"x86_64")
	sgdisk --typecode="$NEW_ROOT_ID":"4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709" "$NEW_DEV"
	;;
"aarch64")
	sgdisk --typecode="$NEW_ROOT_ID":"B921B045-1DF0-41C3-AF44-4C6F280D3FAE" "$NEW_DEV"
	;;
*)
	echo "Unhandled processor architecture: $(uname -m)" >&2
	;;
esac

sgdisk --typecode="$NEW_LVM_ID":"6D6D379-F507-44C2-A23C-238F2A3DF928" "$NEW_DEV"
parted "$NEW_DEV" set "$NEW_EFI_ID" boot on
parted "$NEW_DEV" set "$NEW_EFI_ID" esp on
partprobe
udevadm settle
sleep 10

lsblk -o NAME,PARTTYPE,PARTUUID,PARTLABEL,TYPE,UUID,LABEL
mount $NEW_EFI_DEV /boot/efi
lsblk -o NAME,PARTTYPE,PARTUUID,PARTLABEL,TYPE,UUID,LABEL
print_dev_info $NEW_DEV
echo "----- END FORMATTING AUXILIARY VOLUME -----"

echo "----- BEGIN CONFIGURING LVM -----"
pvcreate $NEW_LVM_DEV
vgcreate $NEW_LVM_VG $NEW_LVM_DEV
lvcreate -L 256M -n $NEW_HOME_LV $NEW_LVM_VG
lvcreate -L 4G -n $NEW_VAR_LV $NEW_LVM_VG
pvs
vgs
lvs
echo "----- END CONFIGURING LVM -----"

create_and_bind_luks_null() {
	# usage: create_and_bind_luks_tang DEV NAME KEY_FILE
	# NOTE: Configure our LUKS volume on the auxiliary volume.
	#       We then image that rather than swapping our root file system in-place.
	luks_key=$(head -c 48 /dev/zero | base64 | head -c 64)
	echo "Creating LUKS volume."
	echo -n "$luks_key" | cryptsetup -y -v luksFormat "$1" --key-file=- "$HARDEN_INTEGRITY_FLAGS"
	lsblk -f
	echo "Opening LUKS volume."
	echo -n "$luks_key" | cryptsetup -y -v luksOpen "$1" "$2" --key-file=-
	lsblk -f
	echo "Checking LUKS volume status."
	cryptsetup status "$2"
	echo "Dumping LUKS volume metadata."
	cryptsetup luksDump "$1"
	mkdir -p "$(dirname "$3")" && touch "$3"
	echo -n "$luks_key" >"$3"
	chmod 400 "$3"
}

# create_and_bind_luks_tang() {
# 	# usage: create_and_bind_luks_tang DEV NAME TANG_URL
# 	# NOTE: Configure our LUKS volume on the auxiliary volume.
# 	#       We then image that rather than swapping our root file system in-place.
# 	luks_key=$(head -c 48 /dev/urandom | base64 | head -c 64)
# 	echo "Creating LUKS volume."
# 	echo "$luks_key" | cryptsetup -y -v luksFormat "$1" --key-file=- "$HARDEN_INTEGRITY_FLAGS"
# 	lsblk -f
# 	echo "Opening LUKS volume."
# 	echo "$luks_key" | cryptsetup -y -v luksOpen "$1" "$2" --key-file=-
# 	lsblk -f
# 	echo "Checking LUKS volume status."
# 	cryptsetup status "$2"
# 	echo "Dumping LUKS volume metadata."
# 	cryptsetup luksDump "$1"
# 	echo "Preparing to bind LUKS volume to tang server."
# 	# NOTE: clevis isn't properly escaping input from stdin through the `-k -` flag, so this is a workaround.
# 	echo "$luks_key" >/tmp/tmp_key
# 	echo "Checking if tang server is reachable."
# 	curl "${3}/adv"
# 	echo ""
# 	echo "Binding LUKS volume to tang server."
# 	clevis luks bind -yf -d "$1" -k /tmp/tmp_key tang "{\"url\":\"$3\"}"
# 	rm /tmp/tmp_key # WARNING: Definitely make sure this line stays here :-).
# 	echo "Listing LUKS slots."
# 	clevis luks list -d "$1"
# }

echo "----- BEGIN DM-CRYPT SETUP -----"
# Add root to tss group for TPM access (needed for clevis operations)
usermod -a -G tss root

create_and_bind_luks_null $NEW_VAR_DEV $NEW_VAR_NAME /null.key
create_and_bind_luks_null $NEW_HOME_DEV $NEW_HOME_NAME /null.key
echo "Partitioning LUKS volumes."
mkfs.ext4 -L $NEW_ROOT_NAME $NEW_ROOT_DEV
mkfs.ext4 -L $NEW_VAR_NAME /dev/mapper/$NEW_VAR_NAME
mkfs.ext4 -L $NEW_HOME_NAME /dev/mapper/$NEW_HOME_NAME
print_dev_info $NEW_DEV
echo "----- END DM-CRYPT SETUP -----"

echo "----- BEGIN TAB SETUP -----"
# NOTE: Now that we have a LUKS volume available, let's modify our boot parameters to auto-mount it.
echo "Performing boot modifications."
lsblk -f
# Remove the existing root partition.
OLD_ROOT_UUID=$(get_dev_uuid $OLD_ROOT_DEV)
sed -i "/LABEL=cloudimg-rootfs/d" /etc/fstab
sed -i "/UUID=$OLD_ROOT_UUID/d" /etc/fstab

configure_luks_tabs() {
	# Usage: configure_luks_tabs DEV NAME KEYFILE MOUNTPOINT CRYPT_OPTIONS FS_OPTIONS
	uuid=$(get_dev_uuid "$1")
	mapper_uuid=$(get_dev_uuid "/dev/mapper/$2")
	# Remove any conflicting names. This should not be an issue on a clean image.
	sed -i "/$2/d" /etc/crypttab
	sed -i "/$mapper_uuid/d" /etc/fstab
	echo "$2 UUID=$uuid $3 $5" >>/etc/crypttab
	echo "UUID=$mapper_uuid $4 ext4 $6 0 1" >>/etc/fstab
}

configure_luks_tabs $NEW_VAR_DEV $NEW_VAR_NAME none /var luks defaults
configure_luks_tabs $NEW_HOME_DEV $NEW_HOME_NAME none /home luks defaults
echo "----- END TAB SETUP -----"

echo "----- BEGIN COPYING BOOT PARTITION -----"
# Create the boot FS without journaling to avoid dm-verity corruption errors.
mkfs.ext4 -O ^has_journal -L $NEW_BOOT_NAME $NEW_BOOT_DEV
# We have to re-point the /boot/efi GRUB config to the new /boot partition.
NEW_BOOT_UUID=$(get_dev_uuid $NEW_BOOT_DEV)

echo "Fixing EFI ubuntu grub.cfg"
cat /boot/efi/EFI/ubuntu/grub.cfg
sed -i "/search.fs_uuid/c\search.fs_uuid $NEW_BOOT_UUID root hd1,gpt$NEW_BOOT_ID" /boot/efi/EFI/ubuntu/grub.cfg
echo "Fixed /boot/efi/EFI/ubuntu/grub.cfg"
cat /boot/efi/EFI/ubuntu/grub.cfg

echo "Mounting boot."
mkdir -p /mnt/boot
mount $NEW_BOOT_DEV /mnt/boot
time rsync -aAXXHpEogtUh --inplace --whole-file --no-compress --stats /boot/* /mnt/boot --exclude=efi
umount /mnt/boot
umount /boot/efi

# shellcheck disable=SC2114
rm -rf /boot
mkdir -p /boot
mount $NEW_BOOT_DEV /boot
mkdir -p /boot/efi
mount $NEW_EFI_DEV /boot/efi
zero_dev_with_file $NEW_EFI_DEV /boot/efi
lsblk -f
echo "----- END COPYING BOOT PARTITION -----"

echo "----- BEGIN BOOT MODIFICATIONS -----"
echo "Finalizing boot modifications."

systemctl enable clevis-luks-askpass.path
systemctl disable multipathd.service
systemctl mask multipathd.service
systemctl daemon-reload

echo "Reconfiguring GRUB."
# NOTE: No longer need this since it's being removed earlier.
# cat /etc/default/grub.d/40-force-partuuid.cfg
# sed -i "/GRUB_FORCE_PARTUUID=/d" /etc/default/grub.d/40-force-partuuid.cfg
# cat /etc/default/grub.d/40-force-partuuid.cfg
tree /etc/default/grub.d
cat /etc/default/grub.d/50-cloudimg-settings.cfg || true
cat /etc/default/grub.d/init-select.cfg || true

NEW_ROOT_UUID=$(get_dev_uuid $NEW_ROOT_DEV)
KERNEL_CMDLINE="rd.dm=1 systemd.verity=1 rd.neednet=1"
KERNEL_CMDLINE+=$HARDEN_KERNEL_CMDLINE
KERNEL_CMDLINE+=$DEBUG_KERNEL_CMDLINE
KERNEL_CMDLINE+=" root=/dev/mapper/verity-root confsec.root=none confsec.efi=none confsec.crypt.git=$CONFSEC_GIT confsec.crypt.build_id=$CONFSEC_BUILD_ID confsec.crypt.hardening_scope=$CONFSEC_HARDENING_SCOPE confsec.crypt.ephemeral_integrity=$CONFSEC_EPHEMERAL_INTEGRITY confsec.crypt.verity_panic=$CONFSEC_VERITY_PANIC confsec.crypt.no_serial=$CONFSEC_NO_SERIAL confsec.crypt.debug_scope=$CONFSEC_DEBUG_SCOPE confsec.crypt.optimize_disk=$CONFSEC_OPTIMIZE_DISK confsec.opt=none"
sed -i "s|^GRUB_CMDLINE_LINUX=\".*\"|GRUB_CMDLINE_LINUX=\"$KERNEL_CMDLINE\"|" /etc/default/grub

# NOTE: The auxiliary volume is already mounted as /boot/efi, so we don't need to again.
echo "Updating /boot/efi"
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=ubuntu
echo "Updating GRUB."
update-grub

# Delete the grubenv file entirely to avoid dm-verity corruption errors.
# Note that grub has logic to ignore writing to grubenv if it doesn't exist.
rm /boot/grub/grubenv

# NOTE: GRUB loves to populate the old root UUID, even if we chroot.
sed -i "s/root=UUID=$OLD_ROOT_UUID //g" /boot/grub/grub.cfg
sed -i "s/$OLD_ROOT_UUID/$NEW_ROOT_UUID/g" /boot/grub/grub.cfg
sed -i '/LABEL=UEFI/d' /etc/fstab
sed -i '/LABEL=BOOT/d' /etc/fstab
# Azure doesnt use labels
sed -i '/\/boot\/efi/d' /etc/fstab

# Modify dracut config.
echo "Performing dm-verity dracut modifications."
# Disable multipath.
echo 'omit_dracutmodules+=" multipath "' >/etc/dracut.conf.d/20-no-multipath.conf

# dm-verity for /
# NOTE: This version of Ubuntu doesn't come bundled with systemd-veritysetup-generator in initramfs.
#       So, we mimic the verityboot module since it's simpler than rebuilding our systemd or dracut from scratch.
echo 'add_dracutmodules+=" verityroot "' >/etc/dracut.conf.d/10-verityroot.conf
mkdir -p /usr/lib/dracut/modules.d/10verityroot
cat <<'EOF' >/usr/lib/dracut/modules.d/10verityroot/module-setup.sh
#!/bin/bash

check() { return 0; }
depends() { echo rootfs-block systemd dm; }
installkernel() {
    hostonly='' instmods dm-verity
}
install() {
    inst_hook initqueue/settled 00 "$moddir/verityroot.sh"
    inst_multiple veritysetup
}
EOF
chmod +x /usr/lib/dracut/modules.d/10verityroot/module-setup.sh
cat <<EOF >/usr/lib/dracut/modules.d/10verityroot/verityroot.sh
#!/bin/bash

CONFSEC_DEBUG_SCOPE=\$(getarg confsec.crypt.debug_scope || $HARDEN_DRACUT_PANIC "confsec.crypt.debug_scope not specified in kernel command line")

if [ "\$CONFSEC_DEBUG_SCOPE" -lt 2 ]; then
    set -x
fi

if ! [ -e /dev/mapper/verity-root ]; then
    ROOT_DEV=/dev/disk/by-label/$NEW_ROOT_NAME
    ROOT_HASHES=/dev/disk/by-partlabel/$NEW_VERITYROOT_NAME
    ROOT_ROOT_HASH=\$(getarg confsec.root || $HARDEN_DRACUT_PANIC "confsec.root not specified in kernel command line")
    modprobe dm-verity || true
    veritysetup open \$ROOT_DEV verity-root \$ROOT_HASHES \$ROOT_ROOT_HASH --$HARDEN_VERITY_MODE || $HARDEN_DRACUT_PANIC "Failed to open verity-root"
else
    echo "skipping veritysetup for verity-root, since /dev/mapper/verity-root already exists"
fi

if [ "\$CONFSEC_DEBUG_SCOPE" -lt 2 ]; then
    set +x
fi
EOF
chmod +x /usr/lib/dracut/modules.d/10verityroot/verityroot.sh

# dm-verity for /boot
echo 'add_dracutmodules+=" verityboot "' >/etc/dracut.conf.d/20-verityboot.conf
mkdir -p /usr/lib/dracut/modules.d/20verityboot
cat <<'EOF' >/usr/lib/dracut/modules.d/20verityboot/module-setup.sh
#!/bin/bash

check() { return 0; }
depends() { echo dm rootfs-block systemd; }
installkernel() {
    hostonly='' instmods dm-verity
}
install() {
    inst_hook pre-pivot 20 "$moddir/verityboot.sh"
    inst_multiple blockdev blkid mount veritysetup
}
EOF
chmod +x /usr/lib/dracut/modules.d/20verityboot/module-setup.sh
cat <<EOF >/usr/lib/dracut/modules.d/20verityboot/verityboot.sh
#!/bin/bash

CONFSEC_DEBUG_SCOPE=\$(getarg confsec.crypt.debug_scope || $HARDEN_DRACUT_PANIC "confsec.crypt.debug_scope not specified in kernel command line")

if [ "\$CONFSEC_DEBUG_SCOPE" -lt 2 ]; then
    set -x
fi

get_dev_partuuid() {
    blkid -s PARTUUID -o value "\$1" || $HARDEN_DRACUT_PANIC "Failed get PARTUUID for \$1"
}

get_dev_sector_size() {
	blockdev --getss "\$1"
}

BOOT_DEV=/dev/disk/by-label/$NEW_BOOT_NAME
BOOT_HASH_0=\$(get_dev_partuuid /dev/disk/by-partlabel/$NEW_VERITY_NAME)
BOOT_HASH_1=\$(get_dev_partuuid /dev/disk/by-partlabel/$NEW_VERITYROOT_NAME)
BOOT_ROOT_HASH="\${BOOT_HASH_0//-/}\${BOOT_HASH_1//-/}"
BOOT_HASHES=/sysroot/meta-verity/boot.hashes
BOOT_SECTOR_SIZE=\$(get_dev_sector_size \$BOOT_DEV)

modprobe dm-verity || true
mount /dev/disk/by-label/$NEW_VERITY_NAME /sysroot/meta-verity || $HARDEN_DRACUT_PANIC "Failed to mount /sysroot/meta-verity"
veritysetup open \$BOOT_DEV verity-boot \$BOOT_HASHES \$BOOT_ROOT_HASH --$HARDEN_VERITY_MODE --data-block-size="\$BOOT_SECTOR_SIZE" --hash-block-size="\$BOOT_SECTOR_SIZE" || $HARDEN_DRACUT_PANIC "Failed to open verity-boot"
# NOTE: Not mounting since we have /etc/fstab entries.
# mount -o ro,noload /dev/mapper/verity-boot /sysroot/boot || $HARDEN_DRACUT_PANIC "Failed to mount /sysroot/boot"

if [ "\$CONFSEC_DEBUG_SCOPE" -lt 2 ]; then
    set +x
fi
EOF
chmod +x /usr/lib/dracut/modules.d/20verityboot/verityboot.sh

# Re-encrypt /home and /var
mkdir -p /etc/cache/cracklib
cp -R /var/cache/cracklib/* /etc/cache/cracklib/
echo 'add_dracutmodules+=" lvm reencrypt "' >/etc/dracut.conf.d/30-reencrypt.conf
mkdir -p /usr/lib/dracut/modules.d/30reencrypt
cat <<'EOF' >/usr/lib/dracut/modules.d/30reencrypt/module-setup.sh
#!/bin/bash

check() { return 0; }
depends() { echo dm rootfs-block systemd; }
installkernel() {
    hostonly='' instmods dm-crypt tpm tpm_tis tpm_crb tpm_tis_core tpm_svsm
}
install() {
    inst_hook pre-pivot 30 "$moddir/reencrypt.sh"
    inst_multiple base64 basename clevis clevis-decrypt clevis-decrypt-tpm2 clevis-encrypt-tpm2 clevis-luks-bind clevis-luks-common-functions clevis-luks-unlock cryptsetup cryptsetup-reencrypt growpart jose lvdisplay lvextend lvm mktemp pvresize pvs pwmake resize2fs sort tail tpm2_create tpm2_createpolicy tpm2_createprimary tpm2_evictcontrol tpm2_getrandom tpm2_load tpm2_pcrread tpm2_unseal xargs
    inst /dev/tpm0
}
EOF
chmod +x /usr/lib/dracut/modules.d/30reencrypt/module-setup.sh
cat <<EOF >/usr/lib/dracut/modules.d/30reencrypt/reencrypt.sh
#!/bin/bash

CONFSEC_DEBUG_SCOPE=\$(getarg confsec.crypt.debug_scope || $HARDEN_DRACUT_PANIC "confsec.crypt.debug_scope not specified in kernel command line")
EXTRA_ARGS=""
MOUNT_PREFIX="/sysroot"

# NOTE: A keen observer would note that this being set leaks the value of \$tmp_pass in the serial logs.
#       This shouldn't matter in practice, since this key slot only lives for the duration
#       of the re-encryption process (and we kill serial output).
#       But, "confsec.crypt.debug_scope >= 2" in production prevents any leak.
if [ "\$CONFSEC_DEBUG_SCOPE" -lt 2 ]; then
    EXTRA_ARGS="--debug"
    set -x
fi

# Hacks to get this to work in initramfs.
OLD_LD_LIBRARY_PATH="\$LD_LIBRARY_PATH"
export LD_LIBRARY_PATH="\$LD_LIBRARY_PATH:\${MOUNT_PREFIX}/usr/lib/x86_64-linux-gnu/"
mkdir -p /var/cache/cracklib
cp -R "\${MOUNT_PREFIX}/etc/cache/cracklib" /var/cache/

reencrypt_mount() {
    # NOTE: Because we bind with the null key before dropping that key slot,
    #       there's a brief window of time where the null key can be used to snag the volume key.
    #       This shouldn't matter, since this is all happening in initramfs where we *know* there
    #       aren't any malicious dracut modules racing to decrypt the volume key after it is re-keyed.
    #       For additional paranoia, we add a step to bind a new key slot to a random key, remove the null key,
    #       then re-encrypt using the random key before binding to the TPM and deleting the random key slot.
    tmp_pass=\$(tpm2_getrandom 48 | base64) || $HARDEN_DRACUT_PANIC "Failed to get random password from TPM"
    echo -n "\$tmp_pass" | cryptsetup luksAddKey "/dev/os/\$1" --key-file "\${MOUNT_PREFIX}/null.key" --key-slot 1 || $HARDEN_DRACUT_PANIC "Failed to add random key slot to /dev/os/\$1"
    cryptsetup luksKillSlot "/dev/os/\$1" 0 -q || $HARDEN_DRACUT_PANIC "Failed to luksKillSlot /dev/os/\$1 for the null key"
    echo -n "\$tmp_pass" | cryptsetup-reencrypt "/dev/os/\$1" --key-file - --key-slot 1 --use-urandom --use-directio \$EXTRA_ARGS || $HARDEN_DRACUT_PANIC "Failed to reencrypt /dev/os/\$1"
    cryptsetup luksDump "/dev/os/\$1"
    # NOTE: PCR 5 binds to the GPT layout; PCR 8 binds to the GRUB config (kernel command line).
    #       Additional registers can be added as desired.
    echo -n "\$tmp_pass" | clevis luks bind -yf -d "/dev/os/\$1" -k - tpm2 '{"pcr_bank":"sha256","pcr_ids":"5,8"}' || $HARDEN_DRACUT_PANIC "Failed to bind /dev/os/\$1 to TPM"
    cryptsetup luksKillSlot "/dev/os/\$1" 1 -q || $HARDEN_DRACUT_PANIC "Failed to luksKillSlot /dev/os/\$1 for the random key"
    cryptsetup luksDump "/dev/os/\$1"
    # NOTE: Not unlocking since we have /etc/crypttab entries.
    # clevis luks unlock -d "/dev/os/\$1" -n "confident-\$1" || $HARDEN_DRACUT_PANIC "Failed to unlock /dev/os/\$1"
    # NOTE: Not mounting since we have /etc/fstab entries.
    # mount "/dev/mapper/confident-\$1" "\${MOUNT_PREFIX}/\$1" || $HARDEN_DRACUT_PANIC "Failed to mount /dev/os/\$1"
}

lvm vgscan
lvm vgchange -ay
reencrypt_mount home &
reencrypt_mount var &
wait

# Expand /var to fill the remaining disk space to support arbitrarily large models.
# This also reduces the overall time to re-encrypt the ephemeral partitions.
LVM_DEV=\$(pvs --no-headings --select vgname=$NEW_LVM_VG -o pv_name | xargs)
VAR_DEV=/dev/$NEW_LVM_VG/$NEW_VAR_LV
VAR_MAPPER=/dev/mapper/$NEW_VAR_NAME

# "growpart" requires us to pass it the disk and partition number separately, so we need to split them here.
if [[ "\$LVM_DEV" =~ ^(/dev/nvme[0-9]+n[0-9]+)p([0-9]+)$ ]]; then
    DISK_DEV="\${BASH_REMATCH[1]}"
    LVM_PART="\${BASH_REMATCH[2]}"
elif [[ "\$LVM_DEV" =~ ^(/dev/sd[a-z]+)([0-9]+)$ ]]; then
    DISK_DEV="\${BASH_REMATCH[1]}"
    LVM_PART="\${BASH_REMATCH[2]}"
else
    $HARDEN_DRACUT_PANIC "Unrecognized disk naming scheme: \$LVM_DEV"
fi

growpart \$DISK_DEV \$LVM_PART || true
pvresize \$LVM_DEV || true
lvextend -l +100%FREE \$VAR_DEV || true
clevis luks unlock -d \$VAR_DEV -n confident-var || $HARDEN_DRACUT_PANIC "Failed to unlock confident-var"
e2fsck -fp \$VAR_MAPPER || $HARDEN_DRACUT_PANIC "Failed to e2fsck confident-var"
resize2fs \$VAR_MAPPER || $HARDEN_DRACUT_PANIC "Failed to resize ext4 partition confident-var"
cryptsetup luksClose \$VAR_MAPPER || $HARDEN_DRACUT_PANIC "Failed to luksClose confident-var"

export LD_LIBRARY_PATH="\$OLD_LD_LIBRARY_PATH"

if [ "\$CONFSEC_DEBUG_SCOPE" -lt 2 ]; then
    set +x
fi
EOF
chmod +x /usr/lib/dracut/modules.d/30reencrypt/reencrypt.sh

# Download models in initramfs
echo 'add_dracutmodules+=" modeldl "' >/etc/dracut.conf.d/40-modeldl.conf
mkdir -p /usr/lib/dracut/modules.d/40modeldl
install -m 0755 -D /tmp/modeldl_helpers.sh /usr/lib/dracut/modules.d/40modeldl/modeldl_helpers.sh
cat <<'EOF' >/usr/lib/dracut/modules.d/40modeldl/module-setup.sh
#!/bin/bash

check() { return 0; }
depends() { echo dm rootfs-block systemd network url-lib; }
installkernel() {
    hostonly='' instmods
}
install() {
    inst_hook pre-pivot 40 "$moddir/modeldl.sh"
    inst_multiple blkid mount curl tpm2_pcrextend sha256sum write jq dirname basename ip awk unzip sort
    inst /dev/tpm0

    # used by ollama
    inst_binary /lib/x86_64-linux-gnu/libpthread.so.0 /lib/x86_64-linux-gnu/libpthread.so.0
    inst_binary /lib/x86_64-linux-gnu/libdl.so.2 /lib/x86_64-linux-gnu/libdl.so.2
    inst_binary /lib/x86_64-linux-gnu/libstdc++.so.6 /lib/x86_64-linux-gnu/libstdc++.so.6
    inst_binary /lib/x86_64-linux-gnu/librt.so.1 /lib/x86_64-linux-gnu/librt.so.1

    # used by tpm2_pcrextend
    inst_binary /lib/x86_64-linux-gnu/libtss2-tcti-device.so.0 /lib/x86_64-linux-gnu/libtss2-tcti-device.so.0

    inst_simple "$moddir/modeldl_helpers.sh" "/lib/modeldl_helpers.sh"
}
EOF
chmod +x /usr/lib/dracut/modules.d/40modeldl/module-setup.sh

cat <<EOF >/usr/lib/dracut/modules.d/40modeldl/modeldl.sh
#!/bin/bash

CONFSEC_DEBUG_SCOPE=\$(getarg confsec.crypt.debug_scope || $HARDEN_DRACUT_PANIC "confsec.crypt.debug_scope not specified in kernel command line")
MOUNT_PREFIX="/sysroot"

if [ "\$CONFSEC_DEBUG_SCOPE" -lt 2 ]; then
    set -x
fi

HARDEN_DRACUT_PANIC=$HARDEN_DRACUT_PANIC MOUNT_PREFIX="\${MOUNT_PREFIX}" . /lib/modeldl_helpers.sh || $HARDEN_DRACUT_PANIC "failed to execute modeldl_helpers.sh"

# Make the tempfs. Make it large enough to support most models, since actual capacity will depend on available RAM.
mount -t tmpfs -o size=64G tmpfs "\${MOUNT_PREFIX}/models" || $HARDEN_DRACUT_PANIC "Unable to create model tempfs"

if [ "$CLOUD" = "azure" ]; then
	WORKLOAD_AUDIENCE=\$(fetch_${CLOUD}_instance_metadata "WORKLOAD_AUDIENCE" || $HARDEN_DRACUT_PANIC "failed to fetch workload audience")
	SERVICE_ACCOUNT_IMPERSONATION_URL=\$(fetch_${CLOUD}_instance_metadata "SERVICE_ACCOUNT_IMPERSONATION_URL" || $HARDEN_DRACUT_PANIC "failed to fetch service account impersonation url")
	azure_token=\$(azure_get_ad_token_exchange_token | tail -n 1 || $HARDEN_DRACUT_PANIC "failed to get Azure AD token exchange token")
	gcp_token=\$(azure_exchange_token_for_gcp_token "\${azure_token}" "\${WORKLOAD_AUDIENCE}" "\${SERVICE_ACCOUNT_IMPERSONATION_URL}" || $HARDEN_DRACUT_PANIC "failed to exchange token for GCP token")
elif [ "$CLOUD" = "qemu" ]; then
	gcp_token=\$(fetch_qemu_instance_metadata "GCP_ACCESS_TOKEN")
else
	gcp_token=\$(fetch_gcp_access_token || $HARDEN_DRACUT_PANIC "failed to fetch GCP access token")
fi

MODELS_BUCKET=\$(fetch_${CLOUD}_instance_metadata "MODELS_BUCKET" || $HARDEN_DRACUT_PANIC "failed to fetch models bucket")
MODEL_NAME=\$(fetch_${CLOUD}_instance_metadata "MODEL_NAME" || $HARDEN_DRACUT_PANIC "failed to fetch ollama model")
MODEL_ID=\$(fetch_${CLOUD}_instance_metadata "MODEL_ID" || $HARDEN_DRACUT_PANIC "failed to fetch models id")
model_type=\$(get_model_type "\${gcp_token}" "\${MODELS_BUCKET}" "\${MODEL_ID}" || $HARDEN_DRACUT_PANIC "failed to get model type")

if [ "\${model_type}" = "ollama" ]; then
	OLLAMA_MODELS_DIR="\${MOUNT_PREFIX}/models/ollama/.ollama/models"
	mkdir -p "\${OLLAMA_MODELS_DIR}" || $HARDEN_DRACUT_PANIC "Unable to mkdir for ollama models"

	# setup ollama environment and start ollama server
	ollama_home_dir="\${MOUNT_PREFIX}/models/ollama"
	export HOME="\${ollama_home_dir}"
	export OLLAMA_MODELS="\${OLLAMA_MODELS_DIR}"
	mkdir -p "\${OLLAMA_MODELS_DIR}/downloads"
	ollama_pid=\$(ollama_start_server || $HARDEN_DRACUT_PANIC "failed to start ollama server")

	model_path=\$(download_from_gcs_bucket "\${gcp_token}" "\${MODELS_BUCKET}" "\${MODEL_ID}/weights" "\${OLLAMA_MODELS_DIR}/downloads" || $HARDEN_DRACUT_PANIC "failed to download model weights from GCS")
	modelfile_path=\$(download_from_gcs_bucket "\${gcp_token}" "\${MODELS_BUCKET}" "\${MODEL_ID}/Modelfile" "\${OLLAMA_MODELS_DIR}/downloads"|| $HARDEN_DRACUT_PANIC "failed to download Modelfile from GCS")

	model_hash=\$(create_model_from_file "\${modelfile_path}" "\${model_path}" "\${MODEL_NAME}" || $HARDEN_DRACUT_PANIC "failed to create ollama model from file")
	tpm2_pcrextend 12:sha256="\${model_hash}" || $HARDEN_DRACUT_PANIC "Unable to extend PCR with model digest"

	kill \${ollama_pid}
elif [ "\${model_type}" = "vllm" ]; then
	VLLM_DIR="\${MOUNT_PREFIX}/models/vllm"
	VLLM_DOWNLOADS_DIR="\${VLLM_DIR}/downloads"
	VLLM_MODELS_DIR="\${VLLM_DIR}/models"
	mkdir -p \${VLLM_DIR} \${VLLM_DOWNLOADS_DIR} \${VLLM_MODELS_DIR} || $HARDEN_DRACUT_PANIC "Unable to mkdir for vllm models"

	zip_path=\$(download_from_gcs_bucket "\${gcp_token}" "\${MODELS_BUCKET}" "\${MODEL_ID}/model.zip" "\${VLLM_DOWNLOADS_DIR}" || $HARDEN_DRACUT_PANIC "failed to download model weights from GCS")
	validate_zip_model_file "\${zip_path}" || $HARDEN_DRACUT_PANIC "failed to validate zip model file"
	mkdir -p "\${VLLM_MODELS_DIR}/model0" || $HARDEN_DRACUT_PANIC "Unable to mkdir for vllm models"
	unzip "\${zip_path}" -d "\${VLLM_MODELS_DIR}/model0" || $HARDEN_DRACUT_PANIC "failed to unzip model weights"
	rm "\${zip_path}" || $HARDEN_DRACUT_PANIC "failed to delete zip file"

	read -ra MODEL_HASH_RESULT <<<\$((find "\${VLLM_MODELS_DIR}/model0" -type f -print0 | xargs -0 sha256sum) | LC_ALL=C sort | sha256sum || $HARDEN_DRACUT_PANIC "failed to calculate sha256sum of model files")
	model_hash="\${MODEL_HASH_RESULT[0]}"

	# Create a config files for vLLM with proper model path and model name.
	if [ "$CLOUD" = "azure" ]; then
		config_yaml="\$(fetch_azure_instance_userdata | jq -r . | jq -r .vllm_config_yaml || echo '')"
	else
		config_yaml="\$(fetch_${CLOUD}_instance_metadata "VLLM_CONFIG" || echo '')"
	fi
	model_path="\${VLLM_MODELS_DIR#\$MOUNT_PREFIX}/model0"
	config_path="\${VLLM_DIR}/config.yaml"

	echo "\${config_yaml}" > "\${config_path}"
	echo "model: \"\${model_path}\"" >> "\${config_path}"
	echo "disable-log-stats: ${DISABLE_VLLM_METRICS}" >> "\${config_path}"
fi

if [ "$CLOUD" = "azure" ]; then
    ip route flush table main
fi

if [ "\$CONFSEC_DEBUG_SCOPE" -lt 2 ]; then
    set +x
fi
EOF
chmod +x /usr/lib/dracut/modules.d/40modeldl/modeldl.sh

ls -la /usr/lib/dracut/modules.d
ls -la /etc/dracut.conf.d
dracut -f --regenerate-all --hostonly-cmdline --add network --add crypt --add dm --add lvm --add systemd --add url-lib
echo "Printing /etc/default/grub"
cat /etc/default/grub
echo "Printing /boot/grub/grub.cfg"
cat /boot/grub/grub.cfg
echo "----- END BOOT MODIFICATIONS -----"

echo "----- BEGIN DISABLING CLOUD-INIT NETWORKING -----"
echo -e "---\nnetwork: {config: disabled}\n" >/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
echo "----- END DISABLING CLOUD-INIT NETWORKING -----"

echo "----- BEGIN ENABLING NETPLAN NETWORKING -----"
# Only configure netplan for Azure (eth* interfaces)
# GCP uses ens* interfaces which are configured automatically
if [ "$CLOUD" = "azure" ]; then
	cat <<EOF >/etc/netplan/99-predictable-interface-name.yaml
network:
  ethernets:
    id0:
      match:
        name: "eth*"
      dhcp4: true
      dhcp6: true
  version: 2
EOF
	echo "Configured netplan for Azure eth* interfaces"
else
	echo "Skipping netplan configuration (not Azure)"
fi
echo "----- END ENABLING NETPLAN NETWORKING -----"

echo "----- BEGIN ADDING TMP FS -----"
echo "tmpfs /tmp tmpfs defaults,size=2G,mode=1777 0 0" >>/etc/fstab
# TODO: cloud-init needs this right now.
echo "tmpfs /snap tmpfs defaults,size=2G,mode=1777 0 0" >>/etc/fstab
echo "----- END ADDING TMP FS -----"

echo "----- BEGIN MOUNTING meta-verity -----"
mkfs.ext4 -L $NEW_VERITY_NAME $NEW_VERITY_DEV
echo "Mounting meta-verity."
mkdir -p $NEW_VERITY_MOUNT
mount $NEW_VERITY_DEV $NEW_VERITY_MOUNT
echo "----- END MOUNTING meta-verity -----"

echo "----- BEGIN EFI VERITY SETUP -----"
# SELinux
echo "Computing SELinux xattrs."
selinux_relabel / /boot/efi

sync
wait_umount /boot/efi
EFI_SECTOR_SIZE=$(get_dev_sector_size $NEW_EFI_DEV)
time veritysetup -v --debug format $NEW_EFI_DEV $NEW_VERITY_MOUNT/efi.hashes --root-hash-file $NEW_VERITY_MOUNT/efi.roothash --data-block-size="$EFI_SECTOR_SIZE" --hash-block-size="$EFI_SECTOR_SIZE"
print_dev_info $NEW_DEV
ls -la $NEW_VERITY_MOUNT
EFI_ROOT_HASH=$(cat $NEW_VERITY_MOUNT/efi.roothash)
touch /etc/veritytab
EFI_UUID=$(get_dev_uuid $NEW_EFI_DEV)
echo "verity-efi UUID=$EFI_UUID /meta-verity/efi.hashes $EFI_ROOT_HASH data-block-size=$EFI_SECTOR_SIZE,hash-block-size=$EFI_SECTOR_SIZE,$HARDEN_VERITY_MODE" >>/etc/veritytab
echo "/dev/mapper/verity-boot /boot ext4 ro,noload,defaults 0 0" >>/etc/fstab
echo "/dev/mapper/verity-efi /boot/efi vfat ro,defaults 0 0" >>/etc/fstab
echo "----- END EFI VERITY SETUP -----"

echo "----- BEGIN ROOT MODIFICATIONS -----"
# Truncate the auto-generated hostname
true >/etc/hostname

# Disable ssh
systemctl disable ssh
systemctl mask ssh

# Disable serial
if ((HARDEN_NO_SERIAL)); then
	echo "WARNING: Disabling serial!"
	systemctl disable serial-getty@ttyS0.service
	systemctl mask serial-getty@ttyS0.service
fi

# Disable hyperv kvp daemon (Azure only)
if [ "$CLOUD" = "azure" ]; then
  sudo systemctl disable hv-kvp-daemon.service
  sudo systemctl mask hv-kvp-daemon.service
fi

# Delete all user accounts (user ID >= 1000)
who
users=$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd)

for user in $users; do
	case $user in
	nobody | packer | ubuntu)
		echo "Skipping $user"
		;;
	*)
		echo "Deleting $user ..."
		deluser --remove-home "$user"
		;;
	esac
done

cat <<EOF >/etc/ufw/ufw.conf
# /etc/ufw/ufw.conf
#

# Set to yes to start on boot. If setting this remotely, be sure to add a rule
# to allow your remote connection before starting ufw. Eg: 'ufw allow 22/tcp'
ENABLED=yes

# Please use the 'ufw' command to set the loglevel. Eg: 'ufw logging medium'.
# See 'man ufw' for details.
LOGLEVEL=$DEBUG_UFW_LOGLEVEL
EOF
cat <<EOF >/etc/default/ufw
# /etc/default/ufw
#

# Set to yes to apply rules to support IPv6 (no means only IPv6 on loopback
# accepted). You will need to 'disable' and then 'enable' the firewall for
# the changes to take affect.
IPV6=yes

# Set the default input policy to ACCEPT, DROP, or REJECT. Please note that if
# you change this you will most likely want to adjust your rules.
# NB: We use Drop instead of Reject since Drop is technically more secure
# in that it doesn't respond to the request at all.
DEFAULT_INPUT_POLICY="DROP"

# Set the default output policy to ACCEPT, DROP, or REJECT. Please note that if
# you change this you will most likely want to adjust your rules.
# NB: We use Drop instead of Reject since Drop is technically more secure
# in that it doesn't respond to the request at all.
DEFAULT_OUTPUT_POLICY="DROP"

# Set the default forward policy to ACCEPT, DROP or REJECT.  Please note that
# if you change this you will most likely want to adjust your rules
DEFAULT_FORWARD_POLICY="DROP"

# Set the default application policy to ACCEPT, DROP, REJECT or SKIP. Please
# note that setting this to ACCEPT may be a security risk. See 'man ufw' for
# details
DEFAULT_APPLICATION_POLICY="SKIP"

# By default, ufw only touches its own chains. Set this to 'yes' to have ufw
# manage the built-in chains too. Warning: setting this to 'yes' will break
# non-ufw managed firewall rules
MANAGE_BUILTINS=no

#
# IPT backend
#
# only enable if using iptables backend
IPT_SYSCTL=/etc/ufw/sysctl.conf

# Extra connection tracking modules to load. IPT_MODULES should typically be
# empty for new installations and modules added only as needed. See
# 'CONNECTION HELPERS' from 'man ufw-framework' for details. Complete list can
# be found in net/netfilter/Kconfig of your kernel source. Some common modules:
# nf_conntrack_irc, nf_nat_irc: DCC (Direct Client to Client) support
# nf_conntrack_netbios_ns: NetBIOS (samba) client support
# nf_conntrack_pptp, nf_nat_pptp: PPTP over stateful firewall/NAT
# nf_conntrack_ftp, nf_nat_ftp: active FTP support
# nf_conntrack_tftp, nf_nat_tftp: TFTP support (server side)
# nf_conntrack_sane: sane support
IPT_MODULES=""
EOF

# Configure UFW firewall rules based on cloud provider.
# Start with common rules for all clouds.
# Note that we are configuring UFW's user rules file directly rather than using
# UFW's CLI. We do this for a few reasons:
#
# - The UFW CLI isn't the most user friendly interface and tends to return non-zero exit codes if UFW isn't enabled.
# - On top of that, enabling UFW during build requires us to allow list SSH (which we do NOT want to do for the final image).
# - The UFW CLI syntax is confusing (certainly a departure from classic IP tables syntax).
#
# There are a few downsides to this approach:
# - We have to manually manage the UFW state file (`/etc/ufw/user.rules`), including ### tuple ### comments.
# - We can use in-line comments in this file, but UFW will most likely strip them later.
#
# However, the core benefit is that we only have to tolerate a few UFW commands potentially returning a non-zero exit code,
# instead of having to tolerate every UFW CLI command for each rule returning a non-zero exit code. Comments would
# also require an additional CLI call, which is annoying.
#
# Note that these UFW rules are finalized and cannot be modified at runtime.
# That being said, compute_boot's systemd service currently appends a manually crafted
# iptables rule to the same outbound UFW chain to temporarily allow outbound HTTPS traffic,
# for the life of compute boot only. xref CS-1246, which outlines refactoring compute_boot
# itself to dynamically open ports as needed for PKI / attestation flows.
#
# The important thing to know here is that trying to allow-list Intel's PCS, AMD's KCS, and NVIDIA's NRAS
# via the following UFW rules is non-trivial given the dynamic IP ranges used by each provider,
# and the fact that UFW does not support hostname based filtering.
cat <<'EOF' >/etc/ufw/user.rules
*filter
:ufw-user-input - [0:0]
:ufw-user-output - [0:0]
:ufw-user-forward - [0:0]
:ufw-user-limit - [0:0]
:ufw-user-limit-accept - [0:0]
### RULES ###

### tuple ### allow tcp 8081 10.1.0.0/16 any 0.0.0.0/0 in
-A ufw-user-input -d 10.1.0.0/16 -p tcp --dport 8081 -j ACCEPT # router_com
### tuple ### allow tcp 8081 10.2.0.0/16 any 0.0.0.0/0 in
-A ufw-user-input -d 10.2.0.0/16 -p tcp --dport 8081 -j ACCEPT # router_com
### tuple ### allow tcp 8000 10.1.0.0/16 any 0.0.0.0/0 out
-A ufw-user-output -d 10.1.0.0/16 -p tcp --dport 8000 -j ACCEPT # router

### tuple ### allow tcp 3100 10.1.0.0/16 any 0.0.0.0/0 out
-A ufw-user-output -d 10.1.0.0/16 -p tcp --dport 3100 -j ACCEPT # monitoring
### tuple ### allow tcp 3200 10.1.0.0/16 any 0.0.0.0/0 out
-A ufw-user-output -d 10.1.0.0/16 -p tcp --dport 3200 -j ACCEPT # monitoring
### tuple ### allow tcp 4318 10.1.0.0/16 any 0.0.0.0/0 out
-A ufw-user-output -d 10.1.0.0/16 -p tcp --dport 4318 -j ACCEPT # monitoring

EOF

# Append cloud-specific rules
if [ "$CLOUD" = "gcp" ]; then
	cat <<'EOF' >>/etc/ufw/user.rules
### tuple ### allow tcp 80 169.254.169.254/32 any 0.0.0.0/0 out
-A ufw-user-output -d 169.254.169.254/32 -p tcp --dport 80 -j ACCEPT # GCP metadata
### tuple ### allow tcp 443 169.254.169.254/32 any 0.0.0.0/0 out
-A ufw-user-output -d 169.254.169.254/32 -p tcp --dport 443 -j ACCEPT # GCP metadata

### tuple ### allow udp 53 169.254.169.254/32 any 0.0.0.0/0 out
-A ufw-user-output -d 169.254.169.254/32 -p udp --dport 53 -j ACCEPT # GCP DNS
### tuple ### allow tcp 53 169.254.169.254/32 any 0.0.0.0/0 out
-A ufw-user-output -d 169.254.169.254/32 -p tcp --dport 53 -j ACCEPT # GCP DNS

### tuple ### allow tcp 443 199.36.153.8/30 any 0.0.0.0/0 out
-A ufw-user-output -d 199.36.153.8/30 -p tcp --dport 443 -j ACCEPT # GCP PGA

### tuple ### allow tcp 8081 0.0.0.0/0 any 35.191.0.0/16 in
-A ufw-user-input -s 35.191.0.0/16 -p tcp --dport 8081 -j ACCEPT # GCP health check
### tuple ### allow tcp 8081 0.0.0.0/0 any 130.211.0.0/22 in
-A ufw-user-input -s 130.211.0.0/22 -p tcp --dport 8081 -j ACCEPT # GCP health check

### END RULES ###

COMMIT
EOF
elif [ "$CLOUD" = "azure" ]; then
	cat <<'EOF' >>/etc/ufw/user.rules
### tuple ### allow tcp 80 169.254.169.254/32 any 0.0.0.0/0 out
-A ufw-user-output -d 169.254.169.254/32 -p tcp --dport 80 -j ACCEPT # Azure metadata

### tuple ### allow tcp 80 168.63.129.16/32 any 0.0.0.0/0 out
-A ufw-user-output -d 168.63.129.16/32 -p tcp --dport 80 -j ACCEPT # Azure WireServer
### tuple ### allow tcp 32526 168.63.129.16/32 any 0.0.0.0/0 out
-A ufw-user-output -d 168.63.129.16/32 -p tcp --dport 32526 -j ACCEPT # Azure WireServer

### tuple ### allow udp 53 168.63.129.16/32 any 0.0.0.0/0 out
-A ufw-user-output -d 168.63.129.16/32 -p udp --dport 53 -j ACCEPT # Azure DNS
### tuple ### allow tcp 53 168.63.129.16/32 any 0.0.0.0/0 out
-A ufw-user-output -d 168.63.129.16/32 -p tcp --dport 53 -j ACCEPT # Azure DNS

### END RULES ###

COMMIT
EOF
elif [ "$CLOUD" = "qemu" ]; then
	cat <<'EOF' >>/etc/ufw/user.rules
### tuple ### allow tcp 8091 10.0.2.2/32 any 0.0.0.0/0 out
-A ufw-user-output -d 10.0.2.2/32 -p tcp --dport 8091 -j ACCEPT # QEMU metadata

### tuple ### allow udp 53 10.0.2.3/32 any 0.0.0.0/0 out
-A ufw-user-output -d 10.0.2.3/32 -p udp --dport 53 -j ACCEPT # QEMU DNS
### tuple ### allow tcp 53 10.0.2.3/32 any 0.0.0.0/0 out
-A ufw-user-output -d 10.0.2.3/32 -p tcp --dport 53 -j ACCEPT # QEMU DNS

### tuple ### allow tcp 8081 10.0.2.15/32 any 0.0.0.0/0 in
-A ufw-user-input -d 10.0.2.15/32 -p tcp --dport 8081 -j ACCEPT # router_com

### END RULES ###

COMMIT
EOF
else
	echo "Unknown CLOUD value: $CLOUD" >&2
	exit 64
fi

echo "Configuring UFW logging level to $DEBUG_UFW_LOGLEVEL"
# Necessary to reload the ufw configuration with proper IP tables logging rules.
# Since UFW is NOT enabled, we have to tolerate this returning a non-zero exit code, which is annoying.
# This should still properly update the IP tables logging rules, though, and can be verified via the below commands.
ufw logging $DEBUG_UFW_LOGLEVEL || true

# Print everything we just did so we can verify in the logs.
cat /etc/ufw/ufw.conf
cat /etc/default/ufw
cat /etc/ufw/user.rules

echo "----- END ROOT MODIFICATIONS -----"

echo "----- BEGIN COPYING ROOT PARTITION -----"
mkdir -p $NEW_ROOT_MOUNT
mount $NEW_ROOT_DEV $NEW_ROOT_MOUNT
mkdir -p $NEW_VAR_MOUNT
mount /dev/mapper/$NEW_VAR_NAME $NEW_VAR_MOUNT
mkdir -p $NEW_HOME_MOUNT
mount /dev/mapper/$NEW_HOME_NAME $NEW_HOME_MOUNT

mkdir -p ${NEW_ROOT_MOUNT}/dev ${NEW_ROOT_MOUNT}/media ${NEW_ROOT_MOUNT}/mnt ${NEW_ROOT_MOUNT}/proc ${NEW_ROOT_MOUNT}/run ${NEW_ROOT_MOUNT}/snap ${NEW_ROOT_MOUNT}/sys ${NEW_ROOT_MOUNT}/tmp ${NEW_ROOT_MOUNT}/meta-verity ${NEW_ROOT_MOUNT}/boot ${NEW_ROOT_MOUNT}/models

# Rsync the root file system

# Parallelize the two largest directories to speed up the copy first
time rsync -aAXXHpEogtUh --inplace --whole-file --no-compress /usr $NEW_ROOT_MOUNT &
time rsync -aAXXHpEogtUh --inplace --whole-file --no-compress /var $NEW_ROOT_MOUNT &
wait

# Everything else in one go (which should be quick)
time rsync -aAXXHpEogtUh --inplace --whole-file --no-compress --stats \
  / $NEW_ROOT_MOUNT --exclude=/{usr,var,boot,dev,lost+found,media,mnt,proc,run,snap,sys,tmp}/

ls -la $NEW_ROOT_MOUNT
sleep 15
echo "----- END COPYING ROOT PARTITION -----"

echo "----- BEGIN ROOT VERITY SETUP -----"
# SELinux
echo "Computing SELinux xattrs."
selinux_relabel $NEW_ROOT_MOUNT /

sync
wait_umount $NEW_ROOT_MOUNT
time veritysetup -v --debug format $NEW_ROOT_DEV $NEW_VERITYROOT_DEV --root-hash-file $NEW_VERITY_MOUNT/root.roothash
echo "----- END ROOT VERITY SETUP -----"

echo "----- BEGIN UPDATING VERITY CMDLINE -----"
# NOTE: The kernel command line arguments for the verity root hashes must be updated *before* we compute the /boot partition Merkle tree.
sed -i "s/confsec.efi=none/confsec.efi=$EFI_ROOT_HASH/g" /boot/grub/grub.cfg
ROOT_ROOT_HASH=$(cat $NEW_VERITY_MOUNT/root.roothash)
sed -i "s/confsec.root=none/confsec.root=$ROOT_ROOT_HASH/g" /boot/grub/grub.cfg
cat /boot/grub/grub.cfg
echo "----- END UPDATING VERITY CMDLINE -----"

echo "----- BEGIN BOOT VERITY SETUP -----"
# SELinux
selinux_relabel / /boot
sync
wait_umount /boot

BOOT_SECTOR_SIZE=$(get_dev_sector_size $NEW_BOOT_DEV)
time veritysetup -v --debug format $NEW_BOOT_DEV $NEW_VERITY_MOUNT/boot.hashes --root-hash-file $NEW_VERITY_MOUNT/boot.roothash --data-block-size="$BOOT_SECTOR_SIZE" --hash-block-size="$BOOT_SECTOR_SIZE"
print_dev_info $NEW_DEV
ls -la $NEW_VERITY_MOUNT
echo "----- END BOOT VERITY SETUP -----"

echo "----- BEGIN SETTING VERITY PARTUUIDS -----"
BOOT_ROOT_HASH=$(cat $NEW_VERITY_MOUNT/boot.roothash)
BOOT_HASH_0="${BOOT_ROOT_HASH:0:32}"
BOOT_HASH_1="${BOOT_ROOT_HASH:32:32}"
BOOT_HASH_PARTUUID_0=$(hex32_to_uuid "$BOOT_HASH_0")
BOOT_HASH_PARTUUID_1=$(hex32_to_uuid "$BOOT_HASH_1")

# NOTE: We have to split up the naming between VERITYROOT and VERITY.
#       So, when we validate the boot partition's hash in the UEFI event log,
#       we combine these two PARTUUIDs to reconstruct the root hash.
lsblk -o LABEL,PARTLABEL,PARTUUID
sgdisk --partition-guid="$NEW_VERITY_ID":"$BOOT_HASH_PARTUUID_0" "$NEW_DEV"
sgdisk --partition-guid="$NEW_VERITYROOT_ID":"$BOOT_HASH_PARTUUID_1" "$NEW_DEV"
partprobe
lsblk -o LABEL,PARTLABEL,PARTUUID
echo "----- END SETTING VERITY PARTUUIDS -----"

echo "----- BEGIN PARTITION OUTPUT -----"
print_dev_info $OLD_DEV
print_dev_info $NEW_DEV
echo "----- END PARTITION OUTPUT -----"

echo "All done! :-)"
