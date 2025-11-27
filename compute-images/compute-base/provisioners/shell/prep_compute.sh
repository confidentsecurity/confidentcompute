#!/bin/bash
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

HARDEN_VERITY_MODE="ignore-corruption"

case "$CONFSEC_HARDENING_SCOPE" in
*)
    # Nothing for now.
	;;
esac

if [ "$CONFSEC_VERITY_PANIC" = "true" ]; then
	echo "Enabling dm-verity panic-on-corruption!"
	HARDEN_VERITY_MODE="panic-on-corruption"
fi

if ! [[ "$CONFSEC_DEBUG_SCOPE" =~ ^[0-9]+$ ]] || [ "$CONFSEC_DEBUG_SCOPE" -lt 0 ]; then
	echo "CONFSEC_DEBUG_SCOPE must be a non-negative integer: $CONFSEC_DEBUG_SCOPE" >&2
	exit 64
fi

case "$CONFSEC_DEBUG_SCOPE" in
*)
    # Nothing for now.
    ;;
esac

case "$CONFSEC_DISK_INTERFACE" in
"NVME")
	DEV="/dev/nvme0n2"
	PART_PREFIX="p"
	;;
"SCSI")
	DEV="/dev/sdb"
	PART_PREFIX=""
	;;
*)
	echo "$CONFSEC_DISK_INTERFACE not a valid disk interface." >&2
	exit 64
	;;
esac

EFI_ID="1"
BOOT_ID="2"
VERITY_ID="3"
VERITYROOT_ID="4"
ROOT_ID="5"
LVM_ID="6"

ROOT_DEV="${DEV}${PART_PREFIX}${ROOT_ID}"
# LVM_DEV="${DEV}${PART_PREFIX}${LVM_ID}"
VERITYROOT_DEV="${DEV}${PART_PREFIX}${VERITYROOT_ID}"
VERITY_DEV="${DEV}${PART_PREFIX}${VERITY_ID}"
EFI_DEV="${DEV}${PART_PREFIX}${EFI_ID}"
BOOT_DEV="${DEV}${PART_PREFIX}${BOOT_ID}"

LVM_VG="os"
# HOME_LV="home"
VAR_LV="var"
OPT_LV="opt"

# HOME_DEV="/dev/$LVM_VG/$HOME_LV"
VAR_DEV="/dev/$LVM_VG/$VAR_LV"
OPT_DEV="/dev/$LVM_VG/$OPT_LV"

# HOME_NAME="confident-home"
VAR_NAME="confident-var"
OPT_NAME="confident-opt"

print_dev_info() {
	echo "----- BEGIN DEV INFO $1 -----"
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

	echo "----- END DEV INFO $1 -----"
}

get_dev_sector_size() {
	blockdev --getss "$1"
}

get_dev_uuid() {
	blkid -s UUID "$1" | grep -oP 'UUID="\K[^"]+'
}

get_dev_partuuid() {
	blkid -s PARTUUID -o value "$1"
}

zero_dev_with_file() {
	if [ "$CONFSEC_OPTIMIZE_DISK" = "true" ]; then
		echo "Zeroing out remainder of $1 mounted at $2"
		zero_fill=$(uuidgen)
		dd if=/dev/zero of="$2/$zero_fill" bs="$(get_dev_sector_size "$1")" status=progress || true
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

selinux_relabel() {
	setfiles -r "$1" /etc/selinux/confident_policy/contexts/files/file_contexts "$2"
}

# NOTE: We expect the `crypt_base` image to have populated the EFI GUID
#       with the current git commit hash.
EFI_GUID=$(get_dev_partuuid $EFI_DEV)
GIT_GUID=$(hex_to_uuid "$CONFSEC_GIT")
BOOT_GUID=$(hex32_to_uuid "$(xor_hex32 "${EFI_GUID//-/}" "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")")
# GPT_GUID=$(sgdisk -p $DEV | awk '/Disk identifier/ {print $4}' | tr '[:upper:]' '[:lower:]')

if [[ "$EFI_GUID" != "$GIT_GUID" ]]; then
	# NOTE: This isn't an error, but indicates that `crypt-base` was built with a different commit than `compute-base`.
	echo "WARNING: git commit hash mismatch in GPT layout. crypt-base image is coming from a different git revision: $EFI_GUID != $GIT_GUID." >&2
fi

# We set the UEFI partition GUID to the bitflipped version of the current git commit hash.
# This prevents collisions with the `crypt-base` stage if they're from the same commit.
sgdisk --partition-guid="$BOOT_ID":"$BOOT_GUID" "$DEV"
print_dev_info $DEV
pvs
vgs
lvs

echo "----- BEGIN UPDATING GPT -----"
sgdisk --partition-guid="$LVM_ID":"$CONFSEC_BUILD_ID" "$DEV"
partprobe
echo "----- END UPDATING GPT -----"

echo "----- BEGIN CREATING OPT PARTITION -----"
partprobe $DEV
growpart $DEV $LVM_ID
lvcreate -l 100%FREE -n $OPT_LV $LVM_VG
mkfs.ext4 -L $OPT_NAME $OPT_DEV
pvs
vgs
lvs
print_dev_info $DEV
echo "----- END CREATING OPT PARTITION -----"

echo "----- BEGIN TOOLING ON HOST -----"
tree /tmp
mkdir -p /opt/confidentsec/etc
mkdir -p /run/environment.d
# Copy over system.conf placeholder file.
# Note that this is required for router_com.service.d/after_system_conf.conf to work.
install -m 0755 -D /tmp/system.conf /opt/confidentsec/etc/system.conf
# Install compute binaries, config, and wrappers
srcdir=/tmp
basedir=/opt/confidentsec
install -m 0755 -D "${srcdir}/compute_boot" "${basedir}/bin/compute_boot"
install -m 0755 -D "${srcdir}/router_com" "${basedir}/bin/router_com"
install -m 0755 -D "${srcdir}/compute_worker" "${basedir}/bin/compute_worker"

install -m 0755 -D "${srcdir}/make-compute-config" "${basedir}/bin/make-compute-config"
install -m 0755 -D "${srcdir}/make-compute-boot" "${basedir}/bin/make-compute-boot"

install -m 0755 -D "${srcdir}/router-com-secret-wrapper" "${basedir}/bin/router-com-secret-wrapper"
install -m 0755 -D "${srcdir}/compute-boot-secret-wrapper" "${basedir}/bin/compute-boot-secret-wrapper"

install -m 0644 -D "${srcdir}/router_com.yaml.template" "${basedir}/etc/router_com.yaml.template"
install -m 0644 -D "${srcdir}/compute_boot.yaml.template" "${basedir}/etc/compute_boot.yaml.template"
# Compute systemd service files are installed in the "root modifications" step.
echo "----- END TOOLING ON HOST -----"

echo "----- BEGIN MOUNTING AUX -----"
# mount_tang() {
# 	clevis luks unlock -d "$1" -n "$2"
# 	mkdir -p "$3"
# 	mount "/dev/mapper/$2" "$3"
# }
mount_null() {
	# mount_null DEV NAME KEY_FILE MOUNT_POINT
	cryptsetup luksOpen "$1" "$2" --key-file "$3"
	mount "/dev/mapper/$2" "$4"
}

mkdir -p /mnt/aux
mount $ROOT_DEV /mnt/aux
# mount_tang $HOME_DEV $HOME_NAME /mnt/aux/home
# Apply SELinux labels to /var (even before we mount it)
selinux_relabel /mnt/aux /mnt/aux/var
mount_null "$VAR_DEV" "$VAR_NAME" /mnt/aux/null.key /mnt/aux/var
mkdir -p /mnt/aux/opt
mount $OPT_DEV /mnt/aux/opt
mkdir -p /mnt/boot
mount $BOOT_DEV /mnt/boot
mkdir -p /mnt/meta-verity
mount $VERITY_DEV /mnt/meta-verity
lsblk -f
echo "Copying /opt over to auxiliary volume."
cp -R /opt /mnt/aux
zero_dev_with_file $OPT_DEV /mnt/aux/opt
echo "----- END MOUNTING AUX -----"

echo "----- BEGIN ROOT MODIFICATIONS -----"
# Uncomment this block if you want to copy in a newer version of our SE linux policy!
# See also the commented blocks in compute_base.pkr.hcl & packer-build-compute-base.yaml.
# rm -rf /mnt/aux/etc/selinux/confident_policy/
# cp -r /etc/selinux/confident_policy/ /mnt/aux/etc/selinux/

# system_conf.service
install -m 0755 -D /tmp/system_conf.sh /mnt/aux/opt/confidentsec/bin/system_conf.sh
install -m 0644 -D /tmp/system_conf.service /mnt/aux/etc/systemd/system/system_conf.service
systemctl --root=/mnt/aux enable system_conf.service

# compute_boot.service
install -m 0644 -D /tmp/compute_boot.service /mnt/aux/etc/systemd/system/compute_boot.service
mkdir -p /mnt/aux/etc/systemd/system/compute_boot.service.d
install -m 0644 -D /tmp/after_system_conf.conf /mnt/aux/etc/systemd/system/compute_boot.service.d/after_system_conf.conf
systemctl --root=/mnt/aux enable compute_boot.service

# router_com.service
install -m 0644 -D /tmp/router_com.service /mnt/aux/etc/systemd/system/router_com.service
mkdir -p /mnt/aux/etc/systemd/system/router_com.service.d
install -m 0644 -D /tmp/after_system_conf.conf /mnt/aux/etc/systemd/system/router_com.service.d/after_system_conf.conf
systemctl --root=/mnt/aux enable router_com.service

# vllm services
systemctl --root=/mnt/aux enable vllm-cpu.service
systemctl --root=/mnt/aux enable vllm-gpu.service

ls -l /mnt/aux/etc/systemd/system/multi-user.target.wants

# ollama modifications for r/w support.
# TODO: If this gets any more complicated, switch to OverlayFS.
mkdir -p /mnt/aux/models/ollama/.ollama
mv /mnt/aux/usr/share/ollama/.ollama/models /mnt/aux/models/ollama/.ollama/models
ln -fs /models/ollama/.ollama/models /mnt/aux/usr/share/ollama/.ollama/models

# alloy config and working directory.
mkdir -p /mnt/aux/etc/systemd/system/alloy.service.d
mkdir -p /mnt/aux/var/lib/alloy
install -m 0644 -D /tmp/after_system_conf.conf /mnt/aux/etc/systemd/system/alloy.service.d/after_system_conf.conf
install -m 0644 -D /tmp/config.alloy /mnt/aux/etc/alloy/config.alloy
echo "----- END ROOT MODIFICATIONS -----"

echo "----- BEGIN PRUNING FILE SYSTEM -----"
# TODO
# Truncating the audit log and removing the log backup to avoid clogging dev-graphana
# true command used for no-op
# Truncate audit log if it exists, otherwise log a warning
if [ -f /mnt/aux/var/log/audit/audit.log ]; then
    true > /mnt/aux/var/log/audit/audit.log
else
    echo "Warning: audit.log not found, skipping truncation (possible on Azure and QEMU builds)" >&2
    mkdir -p /mnt/aux/var/log/audit # the audit directory has to exist or auditd will fail to start.
fi

# Remove audit log backups if they exist
rm -f /mnt/aux/var/log/audit/audit.log.*
echo "----- END PRUNING FILE SYSTEM -----"

echo "----- BEGIN OPT VERITY SETUP -----"
lsblk -f

# SELinux
echo "Computing SELinux xattrs."
selinux_relabel /mnt/aux /mnt/aux/opt
echo "Syncing opt changes to disk."
sync
umount -f /mnt/aux/opt
findmnt /mnt/aux/opt || echo "/mnt/aux/opt unmounted successfully"
lsblk -f
ls -la /mnt/meta-verity
time veritysetup -v --debug format $OPT_DEV /mnt/meta-verity/opt.hashes --root-hash-file /mnt/meta-verity/opt.roothash
tree /mnt/meta-verity
OPT_ROOT_HASH=$(cat /mnt/meta-verity/opt.roothash)
touch /mnt/aux/etc/veritytab
OPT_UUID=$(get_dev_uuid $OPT_DEV)
echo "verity-opt UUID=$OPT_UUID /meta-verity/opt.hashes $OPT_ROOT_HASH $HARDEN_VERITY_MODE" >>/mnt/aux/etc/veritytab
echo "/dev/mapper/verity-opt /opt ext4 ro,defaults 0 0" >>/mnt/aux/etc/fstab
ls -la /mnt/meta-verity
echo "----- END OPT VERITY SETUP -----"

echo "----- BEGIN ROOT VERITY SETUP -----"
# SELinux
echo "Computing SELinux xattrs."
selinux_relabel /mnt/aux /mnt/aux/etc
selinux_relabel /mnt/aux /mnt/aux/usr
selinux_relabel /mnt/aux /mnt/aux/home
selinux_relabel /mnt/aux /mnt/aux/var
sync
wait_umount /mnt/aux
time veritysetup -v --debug format $ROOT_DEV $VERITYROOT_DEV --root-hash-file /mnt/meta-verity/root.roothash
echo "----- END ROOT VERITY SETUP -----"

echo "----- BEGIN UPDATING VERITY CMDLINE -----"
# NOTE: The kernel command line arguments for the verity root hashes must be updated *before* we compute the /boot partition Merkle tree.
ROOT_ROOT_HASH=$(cat /mnt/meta-verity/root.roothash)
sed -i -E "s/\bconfsec.root=\S+/confsec.root=$ROOT_ROOT_HASH/" /mnt/boot/grub/grub.cfg
sed -i "s/confsec.opt=none/confsec.opt=$OPT_ROOT_HASH confsec.compute.git=$CONFSEC_GIT confsec.compute.build_id=$CONFSEC_BUILD_ID confsec.compute.hardening_scope=$CONFSEC_HARDENING_SCOPE confsec.compute.verity_panic=$CONFSEC_VERITY_PANIC confsec.compute.debug_scope=$CONFSEC_DEBUG_SCOPE confsec.compute.optimize_disk=$CONFSEC_OPTIMIZE_DISK/g" /mnt/boot/grub/grub.cfg
cat /mnt/boot/grub/grub.cfg > /tmp/grub.cfg
cat /tmp/grub.cfg
echo "----- END UPDATING VERITY CMDLINE -----"

echo "----- BEGIN BOOT VERITY SETUP -----"
sync
blockdev --flushbufs $BOOT_DEV
wait_umount /mnt/boot
e2fsck -fp $BOOT_DEV
BOOT_SECTOR_SIZE=$(get_dev_sector_size $BOOT_DEV)
time veritysetup -v --debug format $BOOT_DEV /mnt/meta-verity/boot.hashes --root-hash-file /mnt/meta-verity/boot.roothash --data-block-size="$BOOT_SECTOR_SIZE" --hash-block-size="$BOOT_SECTOR_SIZE"
print_dev_info $DEV

echo "Computing SELinux xattrs."
selinux_relabel /mnt /mnt/meta-verity

for file in /mnt/meta-verity/*.roothash; do
	[ -f "$file" ] || continue
	echo "----- BEGIN $file -----"
	cat "$file"
	echo -e "\n----- END $file -----"
done
echo "----- END BOOT VERITY SETUP -----"

echo "----- BEGIN SETTING VERITY PARTUUIDS -----"
BOOT_ROOT_HASH=$(cat /mnt/meta-verity/boot.roothash)
BOOT_HASH_0="${BOOT_ROOT_HASH:0:32}"
BOOT_HASH_1="${BOOT_ROOT_HASH:32:32}"
BOOT_HASH_PARTUUID_0=$(hex32_to_uuid "$BOOT_HASH_0")
BOOT_HASH_PARTUUID_1=$(hex32_to_uuid "$BOOT_HASH_1")

# NOTE: We have to split up the naming between VERITYROOT and VERITY.
#       So, when we validate the boot partition's hash in the UEFI event log,
#       we combine these two PARTUUIDs to reconstruct the root hash.
lsblk -o LABEL,PARTLABEL,PARTUUID
sgdisk --partition-guid="$VERITY_ID":"$BOOT_HASH_PARTUUID_0" "$DEV"
sgdisk --partition-guid="$VERITYROOT_ID":"$BOOT_HASH_PARTUUID_1" "$DEV"
partprobe
lsblk -o LABEL,PARTLABEL,PARTUUID
echo "----- END SETTING VERITY PARTUUIDS -----"

construct_json_manifest() {
	# DEVICE GRUB_CFG
	cmdlines_list="[]"
	cmdlines=()

	while IFS= read -r line; do
		cmdline=$(echo "$line" | sed -E 's/^\s*linux(efi)?\s+\S+\s*//' | awk '{$1=$1; print}')
		cmdlines+=("$cmdline")
	done < <(grep -E '^\s*linux(efi)?\b' "$2")

	for i in "${!cmdlines[@]}"; do
		cmdline=${cmdlines[$i]}
		cmdline_obj="{}"

		for arg in $cmdline; do
			if [[ "$arg" == *=* ]]; then
				key="${arg%%=*}"
				value="${arg#*=}"
				cmdline_obj=$(jq --arg k "$key" --arg v "$value" '. + {($k): $v}' <<<"$cmdline_obj")
			else
				key="$arg"
				cmdline_obj=$(jq --arg k "$key" '. + {($k): null}' <<<"$cmdline_obj")
			fi
		done

		cmdlines_list=$(jq --argjson c "$cmdline_obj" '. += [$c]' <<<"$cmdlines_list")
	done

	gpt_header=$(dd if="$1" bs=512 skip=1 count=1 iflag=direct 2>/dev/null | xxd -p -c 512 | tr -d '\n')
	env_obj="{}"

	for var in $(compgen -e); do
		env_obj=$(jq --arg k "$var" --arg v "${!var}" '. += {($k): $v}' <<<"$env_obj")
	done

	selinux_policy_version=$(cat /etc/selinux/confident_policy/policy/policy-version.txt)
	selinux_policy_hash=$(find /etc/selinux/confident_policy -type f -exec sha256sum {} \; | cut -d ' ' -f1 | sort | sha256sum | cut -d ' ' -f1)

	manifest="{}"
	manifest=$(jq --argjson e "$env_obj" '. + {"build_env": $e}' <<<"$manifest")
	manifest=$(jq --argjson cs "$cmdlines_list" '. + {"kernel_cmdlines": $cs}' <<<"$manifest")
	manifest=$(jq --arg g "$gpt_header" '. + {"gpt_layout": $g}' <<<"$manifest")
	manifest=$(jq --arg s "$selinux_policy_version" '. + {"selinux_policy_version": $s}' <<<"$manifest")
	manifest=$(jq --arg h "$selinux_policy_hash" '. + {"selinux_policy_hash": $h}' <<<"$manifest")

	echo "----- BEGIN $1 $2 MANIFEST -----"
	echo "$manifest"
	echo "----- END $1 $2 MANIFEST -----"
	echo "$manifest" >/tmp/manifest.json
}

echo "Constructing JSON manifest."
# NOTE: Don't load the journal so we don't corrupt the dm-verity Merkle tree.
# mount -o ro,noload,norecovery $BOOT_DEV /mnt/boot
# construct_json_manifest $DEV /mnt/boot/grub/grub.cfg
construct_json_manifest $DEV /tmp/grub.cfg
