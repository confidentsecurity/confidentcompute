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
  default = "ubuntu2204:0.0.0:<empty>"
  validation {
    condition     = can(regex("^[^:]+:[^:]+:[^:]+$", var.qemu_artifact_registry_primary_source_artifact_name))
    error_message = "The artifact name must match the pattern '<package>:<version>:<name>', e.g., ubuntu2204:1.0.0:ubuntu-22.04.img."
  }
  validation {
    condition     = can(regex("^ubuntu2204:.*", var.qemu_artifact_registry_primary_source_artifact_name))
    error_message = "The package name of primary source artifact name should be 'ubuntu2204'."
  }
}

variable "qemu_source_primary_img_path" {
  description = "Where to store primary img image after downloading (or where it is stored if qemu_local_only is set)"
  default     = "/tmp/build-host-primary.img"
}

variable "qemu_artifact_registry_kernel_source_artifact_name" {
  type    = string
  default = "kernel-ubuntu22.04:0.0.0:<empty>"
  validation {
    condition     = can(regex("^[^:]+:[^:]+:[^:]+$", var.qemu_artifact_registry_kernel_source_artifact_name))
    error_message = "The artifact name must match the pattern '<package>:<version>:<name>', e.g., kernel-ubuntu22.04:6.16.7:kernel-deb.tar."
  }
  validation {
    condition     = can(regex("^kernel-ubuntu22.04:.*", var.qemu_artifact_registry_kernel_source_artifact_name))
    error_message = "The package name of primary source artifact name should be 'kernel-ubuntu22.04'."
  }
}

variable "qemu_source_kernel_tar_path" {
  description = "Where to store kernel tar after downloading (or where it is stored if qemu_local_only is set)"
  default     = "/tmp/build-host-kernel.tar"
}

variable "qemu_artifact_registry_target_package" {
  type    = string
  default = "build-host"
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

variable "qemu_signing_key_dir" {
  type = string
  # Directory containing signing_key.pem and signing_cert.pem for image signing.
  # Can be generated as follows, for example:
  # openssl req -new -x509 -newkey rsa:2048 \
  #   -keyout signing_key.pem -out signing_key.x509 \
  #   -nodes -days 36500 -subj "/CN=Custom Kernel Signing/"
  default = "dev_signing_certs"
  validation {
    condition     = var.qemu_signing_key_dir != ""
    error_message = "Please specify qemu_signing_key_dir."
  }
}

### Locals

data "qemu-sshkey" "qemu_install_key" {
  name = "build-host-key-pair-${timestamp()}"
}

locals {
  install_meta_data = <<-EOF
    instance-id: build-host-${timestamp()}
    local-hostname: build-host
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

data "external-raw" "download-kernel-tar" {
  program = ["../scripts/qemu_download_image_from_repository.sh", var.qemu_artifact_registry_project_id, var.qemu_artifact_registry_location, var.qemu_artifact_registry_repository_name, var.qemu_artifact_registry_kernel_source_artifact_name, var.qemu_source_kernel_tar_path, var.qemu_local_only]
  # qemu_download_image_from_repository returns a path where downloaded kernel tar is stored. Use it to create explicit dependency.
}

locals {
  qemu_iso_path     = data.external-raw.download-primary-img.result
  qemu_iso_checksum = "none"
  kernel_tar_path   = data.external-raw.download-kernel-tar.result

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
    ["-m", "8G"],     # 8GBs of RAM
    ["-cpu", "host"], # Use current CPU architecture
    ["-smp", var.qemu_smp],
    ["-serial", "mon:stdio"],
    # setup cloud-init datasource to QEMU http server's IP:PORT
    ["-smbios", "type=1,serial=ds=nocloud;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/"],
  ]

  # misc configs
  accelerator      = var.qemu_accelerator
  headless         = true
  shutdown_command = "sudo shutdown -P now"
}
