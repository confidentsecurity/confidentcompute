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
  default = "ubuntu2404:0.0.0:<empty>"
  validation {
    condition     = can(regex("^[^:]+:[^:]+:[^:]+$", var.qemu_artifact_registry_primary_source_artifact_name))
    error_message = "The artifact name must match the pattern '<package>:<version>:<name>', e.g., ubuntu2404:2025.1014.153721:build-aux.img."
  }
  validation {
    condition     = can(regex("^ubuntu2404:.*", var.qemu_artifact_registry_primary_source_artifact_name))
    error_message = "The package name of aux-source artifact name should be 'ubuntu2404'."
  }
}

variable "qemu_artifact_registry_aux_source_artifact_name" {
  type    = string
  default = "ubuntu2204:0.0.0:<empty>"
  validation {
    condition     = can(regex("^[^:]+:[^:]+:[^:]+$", var.qemu_artifact_registry_aux_source_artifact_name))
    error_message = "The artifact name must match the pattern '<package>:<version>:<name>', e.g., ubuntu2204:2025.1014.153721:build-aux.img."
  }
  validation {
    condition     = can(regex("^ubuntu2204:.*", var.qemu_artifact_registry_aux_source_artifact_name))
    error_message = "The package name of aux-source artifact name should be 'ubuntu2204'."
  }
}

variable "qemu_source_primary_img_path" {
  description = "Where to store primary img image after downloading (or where it is stored if qemu_local_only is set)"
  default     = "/tmp/build-aux-primary.img"
}

variable "qemu_source_aux_img_path" {
  description = "Where to store aux img image after downloading (or where it is stored if qemu_local_only is set)"
  default     = "/tmp/build-aux-aux.img"
}

variable "qemu_artifact_registry_target_package" {
  type    = string
  default = "build-aux"
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

variable "qemu_qmp_port" {
  type        = number
  default     = 1235
  description = "Run qmp server on this port."
}


### Locals

# Generate temporary key pair to be used to access the build VM
data "qemu-sshkey" "qemu_install_key" {
  name = "build-aux-key-pair-${timestamp()}"
}

# cloud-init contents
locals {
  install_meta_data = <<-EOF
    instance-id: build-aux-${timestamp()}
    local-hostname: build-aux
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

data "external-raw" "download-aux-img" {
  program = ["../scripts/qemu_download_image_from_repository.sh", var.qemu_artifact_registry_project_id, var.qemu_artifact_registry_location, var.qemu_artifact_registry_repository_name, var.qemu_artifact_registry_aux_source_artifact_name, var.qemu_source_aux_img_path, var.qemu_local_only]
  # qemu_download_image_from_repository returns a path where downloaded image is stored. Use it to create explicit dependency.
}

# Auxilary image is not supported by packer plugin, we have to copy the input and resize it
data "external-raw" "prepare-aux-img" {
  program = ["../scripts/qemu_prepare_aux_input.sh", "build-aux", data.external-raw.download-aux-img.result, "aux-ubuntu.img", "${var.aux_disk_size}G"]
}

locals {
  qemu_iso_path     = data.external-raw.download-primary-img.result
  qemu_iso_checksum = "none"

  qemu_aux_img_path = data.external-raw.prepare-aux-img.result

  qemu_output_directory = "output-${var.image_family}-${local.image_version}-${local.build_id}"
  qemu_image_name       = "${local.build_vm_name}.img"
  qemu_image_path       = "${local.qemu_output_directory}/${local.qemu_image_name}"
  aux_output_image_name = "${local.qemu_output_directory}/aux-${local.qemu_image_name}"
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
  skip_compaction  = true # Don't optimize the primary output because we only care about the auxilary disk.
  disk_compression = false

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
  # qemuargs overrides parameters generated by packer making using custom -device and -drive directives hard, because the main image has to be attached manually
  # We are recreating default config along with secondary image manually.
  # We cannot use disk_additional_size to create aux disk, because it creates an empty drive and we need ubuntu partition structure.
  qemuargs = [
    ["-m", "8G"],     # 8GBs of RAM
    ["-cpu", "host"], # Use current CPU architecture
    ["-smp", var.qemu_smp],
    ["-serial", "mon:stdio"],

    # Attach data drives:
    # input-output image - packer copies input iso to output location and runs the VM with the output mounted
    ["-drive", "if=none,file=${local.qemu_image_path},id=drive0,cache=writethrough,discard=ignore,format=qcow2"],

    # auxilary drive
    ["-drive", "if=none,file=${local.qemu_aux_img_path},id=drive1,cache=writethrough,discard=ignore,format=qcow2"],

    # create SCSI controller to connect SCSI drives
    ["-device", "virtio-scsi-pci,id=scsi0"],

    # connect drives to the bus using their respective drive ids
    ["-device", "scsi-hd,bus=scsi0.0,drive=drive0"],

    # Don't attach drive1 yet, we'll attach it while VM is running to prevent mount ordering issues
    # ["-device", "scsi-hd,bus=scsi0.0,drive=drive1"],
    # Start qmp server to control devices while VM is running
    ["-qmp", "tcp:127.0.0.1:${var.qemu_qmp_port},server,nowait"],

    # setup cloud-init datasource to QEMU http server's IP:PORT
    ["-smbios", "type=1,serial=ds=nocloud;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/"],
  ]

  # misc configs
  accelerator      = var.qemu_accelerator
  headless         = true
  shutdown_command = "sudo shutdown -P now"
}
