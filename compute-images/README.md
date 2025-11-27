# compute-images
This directory contains the packer build manifests and associated provisioners to generate the `compute_base` image used for hardened compute work deployments.

Packer build times can be time consuming to run. Build targets such as selinux-base require a double reboot to enable SELinux and apply ima file signatures to the root filesystem. The crypt-base build target requires copying over the entirety of the root file system to an auxiliary disk using rsync.

Note: there is no inherent security difference between the stages, they are only partitioned to increase the workflow efficiency of developers. The hardened security measures including SELinux enforcing, ima appraisal, dm-verity are only active at instance provisioning time, with their kernel command line activation parameters being set during the build step of compute base.


## Principle of Operation
The `compute-base` image is the hardened base image used for the CONFSEC compute worker. We package in and enable several security controls, and disable non-essential packages:

### dm-verity
dm-verity[^1] provides integrity checks on a block device by computing a Merkle tree (one-way function tree) for the block device and using that data structure to perform runtime integrity checks on the data being accessed. If the read-only sector accessed does not conform to the hashes stored in the dm-verity Merkle tree, the block is marked as corrupted and dm-verity will optionally enforce `panic-on-corruption`, `restart-on-corruption`, or `ignore-corruption`.

[^1]: https://wiki.archlinux.org/title/Dm-verity

### dm-crypt
dm-crypt[^2] is a disk encryption kernel module that operates on a block device. For us, we bind the runtime sandbox read-write partitions `/home` and `/var` to dm-crypt using LUKS. This is initially done using a null key (all zeros). We then re-key the partitions to

[^2]: https://wiki.archlinux.org/title/Dm-crypt

### dm-integrity
dm-integrity[^3] is an extension to dm-crypt that adds an HMAC to each dm-crypt block, so the data can be checked for corruption rather than returning garbage to the caller.

[^3]: https://wiki.archlinux.org/title/Dm-integrity

### SELinux
SELinux[^4] is used for granular access control for the image, only allowing permitted actions for the binaries in the `/opt` partition (i.e., the CONFSEC tooling). We determine the allowed permissions based on an auditing procedure where the image is configured to run in auditing mode and the resulting SELinux output is collected into an allow list, with massaging.

[^4]: https://wiki.gentoo.org/wiki/SELinux

#### SELinux Caveat
Due to licensing issues with the Ubuntu base SELinux policy we use to derive our SELinux policy, this is hosted in a separate repository to prevent GPLv2 contamination. This is resolved at build time by cross-referencing the [compute-sepolicy repo](https://github.com/confidentsecurity/compute-sepolicy) build artifacts.

### IMA
IMA[^5] is used to check file hashes against known values at runtime and panic if deviations are detected. This is often paired with EVM[^6] for read-only enforcement of the IMA hashes, but since our volumes are protected under dm-verity and the system is constrained to only boot once (i.e., no reboots allowed/no state between reboots), we do not need EVM protection.

[^5]: https://wiki.gentoo.org/wiki/Integrity_Measurement_Architecture
[^6]: https://wiki.gentoo.org/wiki/Extended_Verification_Module

## Directory Structure
- `build-aux/`
	- An intermediate image mounted as a secondary volume during the `crypt-base` and `compute-base`  build process.
	- Consists of zeroed out partitions with randomly adjusted root partition `UUID`s and `PARTUUID`s to prevent the secondary volume from being mounted as root due to a race condition.
- `build-host/`
	- An intermediate image acting as the primary volume and root mount point for later steps.
	- Includes a provisioner script to update the upstream Ubuntu 22.04 image and install known dependencies.
- `build-selinux/`
	- An intermediate image that applies SELinux policy to the `build-host` image.
	- Dependent on `build-host`
- `compute-base/`
	- Hardened base image extending `crypt-base` to include:
		- dm-verity protected `/opt` partition including the CONFSEC compute toolchain
		- Updated root partition to include `router_com.service` and `compute_boot.service`
		- Updated dm-verity Merkle trees, kernel command line and GPT layout
	- Dependent on `build-selinux` and `crypt-base`
- `crypt-base/`
	- Hardened base image consisting of:
		- dm-verity protected root partition
		- dm-verity protected `/boot` and `/boot/efi` partitions
		- LVM partition for expandable OS partitions
		- LUKS `/home` and `/var` partitions, set to a null key
		- `VERITY` and `VERITYROOT` partitions to hold the dm-verity Merkle trees
		- Updated GRUB config
		- Updated kernel command line to reflect dm-verity root hashes
		- Updated GPT layout to include the boot partition dm-verity root hash, along with build metadata.
	- Dependent on `build-selinux` and `build-aux`
- `scripts/`
	- Small collection of utility scripts used during the image development process
- `build_all.sh`
	- Utility script to locally trigger a build on all images specified in the `BUILD` variable
	- Build parameters can be specified through the `CONFSEC_*` variables

## Build Flow
```
          ubuntu-2204                      ubuntu-2204 ubuntu-2204
               │                               └───┐ ┌───┘
               │                                   │ │
               ▼                                   ▼ ▼
          ┌──────────┐                         ┌─────────┐
          │build-host│                         │build-aux│
          └────┬─────┘                         └────┬────┘
               ▼                                    ▼
     build-host-%YYYYMMDD-$BUILD_ID        build-aux-%YYYYMMDD-$BUILD_ID
               │                                    │
               │                                    │
               │                                    │
               │    ┌─────────────┐                 │
               └───►│build-selinux│                 │
                    └───────┬─────┘                 │
                            ▼                       │
               build-selinux-%YYYYMMDD-$BUILD_ID    │
                 ┌──────────┤                       │
                 │          │                       │
                 │          │                       │
                 │          │       ┌──────────┐    │
                 │          └──────►│crypt-base│◄───┘
                 │                  └────┬─────┘
                 │                       ▼
                 │             crypt-base-%YYYYMMDD-$BUILD_ID
                 │                       │
                 │                       │
                 │                       │
                 ▼                       │
         ┌────────────┐                  │
         │compute-base│◄─────────────────┘
         └───────┬────┘
                 ▼
     compute-base-%YYYYMMDD-$BUILD_ID
```

## Optimizations and Tuning Knobs
The `crypt_base` and `compute_base` images have the following packer environment variables which modify the build process and can speed up iteration speed during development:

- `CONFSEC_GIT`: Current git commit hash
- `CONFSEC_HARDENING_SCOPE`: Scope of hardening the image (0 is maximally hardened)
	- `0`: Fully hardened with dm-verity enforcement, SELinux enforcement, and dm-integrity
	- `1`: Mostly hardened with dm-verity & SELinux enforcement disabled, dm-integrity disabled
	- `2`: Same as `1`, but with a randomly generated root password to use in serial port debugging
- `CONFSEC_DEBUG_SCOPE`: Scope of debug output for the image (0 is maximally verbose debug output)
	- `0`: Verbose kernel debug logs; verbose initramfs logs
	- `1`: Verbose initramfs logs only
	- `2`: Verbose logging disabled
- `CONFSEC_OPTIMIZE_DISK`: Whether or not to optimize for disk size
- `CONFSEC_AUX_SOURCE_IMAGE`: URI path for the auxiliary image

## Instance Metadata and Runtime Environment Variables
At runtime, the CONFSEC tooling requires several environment variables to operate correctly. We provide these by populating the GCP/Azure instance metadata, and pull them down in the `system_conf.service` systemd service, which is introduced as a dependency for the`alloy.service`, `router_com.service`, and `compute_boot.service`.

```
#!/bin/bash
set -eux

fetch_instance_metadata() {
    curl -sf -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1" || echo ""
}

expose_var() {
    echo "$1=$(printf '%q' "$2")"
    echo "$1=$(printf '%q' "$2")" >> "$3"
}

ENV_FILE="/run/environment.d/system.conf"
mkdir -p "$(dirname "$ENV_FILE")"
touch "$ENV_FILE"
true > "$ENV_FILE"

KEYS="TEMPO_URL LOKI_URL ROUTER_URL NODE_TYPE STACK_NAME OLLAMA_MODEL GIT_SHA GITHUB_RUN_ID"

for key in $KEYS; do
    value="$(fetch_instance_metadata "$key")"
    expose_var "$key" "$value" "$ENV_FILE"
done

xargs -d '\n' -r systemctl set-environment < "$ENV_FILE"
systemctl daemon-reexec
```
