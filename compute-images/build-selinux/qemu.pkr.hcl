packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1"
    }
    qemu-sshkey = {
      version = ">= 1.1.0"
      source  = "github.com/ivoronin/sshkey"
    }
    external = {
      version = ">= 0.0.3"
      source  = "github.com/joomcode/external"
    }
  }
}

### Variables
variable "qemu_artifact_registry_location" {
  type = string
  # packer will invoke our external-raw datasource even if qemu build is skipped and variabled are undefined.
  # Let's define all vars needed by the datasource to some invalid values and our datasource script will early
  # exit if the value was not changed.
  default = "<empty>"
}

variable "qemu_artifact_registry_repository_name" {
  type    = string
  default = "<empty>"
}

variable "qemu_artifact_registry_project_id" {
  type      = string
  default   = "<empty>"
  sensitive = true
}

variable "qemu_artifact_registry_primary_source_artifact_name" {
  type    = string
  default = "build-host:0.0.0:<empty>"
  validation {
    condition     = can(regex("^[^:]+:[^:]+:[^:]+$", var.qemu_artifact_registry_primary_source_artifact_name))
    error_message = "The artifact name must match the pattern '<package>:<version>:<name>', e.g., build-host:2025.1014.153721:build-host.img."
  }
  validation {
    condition     = can(regex("^build-host:.*", var.qemu_artifact_registry_primary_source_artifact_name))
    error_message = "The package name of primary source artifact name should be 'build-host'."
  }
}

variable "qemu_source_primary_img_path" {
  description = "Where to store primary img image after downloading (or where it is stored if qemu_local_only is set)"
  default     = "/tmp/build-selinux-primary.img"
}

variable "qemu_artifact_registry_target_package" {
  type    = string
  default = "build-selinux"
}

variable "qemu_local_only" {
  type    = bool
  default = false
}

variable "qemu_smp" {
  type        = number
  default     = 4
  description = "Number of vCPUs to use."
}

variable "qemu_accelerator" {
  type        = string
  default     = "kvm"
  description = "Qemu accelerator to use. On Linux use kvm and macOS use hvf."
}

### Locals

# Generate temporary key pair to be used to access the build VM
data "qemu-sshkey" "qemu_install_key" {
  name = "build-selinux-key-pair-${timestamp()}"
}

# cloud-init contents
locals {
  install_meta_data = <<-EOF
    instance-id: build-selinux-${timestamp()}
    local-hostname: build-selinux
    EOF

  install_user_data = <<-EOF
    #cloud-config
    users:
      - name: packer
        lock_passwd: true
        ssh_authorized_keys:
          - ${data.qemu-sshkey.qemu_install_key.public_key}
        sudo: [ 'ALL=(ALL) NOPASSWD:ALL' ]
        group: sudo
        shell: /bin/bash
    EOF
}

data "external-raw" "download-primary-img" {
  program = ["../scripts/qemu_download_image_from_repository.sh", var.qemu_artifact_registry_project_id, var.qemu_artifact_registry_location, var.qemu_artifact_registry_repository_name, var.qemu_artifact_registry_primary_source_artifact_name, var.qemu_source_primary_img_path, var.qemu_local_only]
  # qemu_download_image_from_repository returns a path where downloaded image is stored. Use it to create explicit dependency.
}

locals {
  qemu_iso_path         = data.external-raw.download-primary-img.result
  qemu_iso_checksum     = "none"
  qemu_output_directory = "output-${var.image_family}-${local.image_version}-${local.build_id}"
  qemu_image_name       = "${local.build_vm_name}.img"
  qemu_image_path       = "${local.qemu_output_directory}/${local.qemu_image_name}"
}

### Source

source "qemu" "default" {
  # input config
  iso_url        = local.qemu_iso_path
  iso_checksum   = local.qemu_iso_checksum
  disk_image     = true                     # iso_url points to a bootable ISO image
  disk_size      = "${var.host_disk_size}G" # resize input disk to this value
  disk_interface = "virtio-scsi"            # attach it as SCSI disk, we do not support NVME now

  # output config
  output_directory = local.qemu_output_directory
  vm_name          = local.qemu_image_name
  skip_compaction  = false # run `qemu-img convert` the disk to save some disk space, this is fast (<1m, reduces size to 1/3 of the original)
  disk_compression = false # but do not compress it because it's slow (>10m, reduces size to 1/3 of the compacted disk size)

  # SSH setup
  ssh_private_key_file      = data.qemu-sshkey.qemu_install_key.private_key_path
  ssh_clear_authorized_keys = true
  ssh_username              = "packer"
  ssh_timeout               = "10m"

  # cloud-init http server contents
  http_content = {
    "/meta-data" = local.install_meta_data,
    "/user-data" = local.install_user_data
  }

  # Custom QEMU args
  qemuargs = [
    ["-m", "8G"],
    ["-cpu", "host"],
    ["-serial", "mon:stdio"],
    # cloud-init data
    ["-smbios", "type=1,serial=ds=nocloud;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/"],
  ]

  # misc configs
  accelerator      = var.qemu_accelerator
  headless         = true
  shutdown_command = "sudo shutdown -P now"
}
