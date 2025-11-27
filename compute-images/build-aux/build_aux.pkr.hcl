/*
  build_aux

  Variables:
    - CONF_GCP_BUILD_ZONE: GCP zone to build the image in
    - CONF_GCP_PROJECT_ID: GCP project to build the image in
    - CONF_AZURE_REGION: Azure region to build the image in
    - CONF_AZURE_SUBSCRIPTION: Azure subscription to build the image in
    - CONF_AZURE_IMAGE_GALLERY: Azure image gallery to build the image in
    - CONFSEC_GIT: Current git commit hash
*/

packer {
  required_plugins {
    googlecompute = {
      source  = "github.com/hashicorp/googlecompute"
      version = "~> 1"
    }
    azure = {
      source  = "github.com/confidentsecurity/azure"
      version = "= 2.5.1"
    }
  }
}

# GCP Build Variables
variable "gcp_build_zone" {
  type    = string
  default = env("CONF_GCP_BUILD_ZONE")
  validation {
    condition     = var.gcp_build_zone == "" || can(regex("^us-[a-z]+[0-9]-[a-c]$", var.gcp_build_zone))
    error_message = "The zone must match the pattern 'us-<region><number>-<zone>', e.g., us-central1-a."
  }
}
variable "use_iap" {
  type    = bool
  default = false
}
# NOTE: Different image versions for host vs. aux to prevent the race condition mounting the root file system.
variable "source_gcp_image_host" {
  type    = string
  default = "ubuntu-2404-noble-amd64-v20250502a"
}
variable "source_gcp_image_aux" {
  type    = string
  default = "projects/ubuntu-os-cloud/global/images/ubuntu-2204-jammy-v20250508"
}
variable "gcp_project_id" {
  type    = string
  default = env("CONF_GCP_PROJECT_ID")
  validation {
    condition     = var.gcp_project_id == "" || can(regex("^[a-z0-9-]+$", var.gcp_project_id))
    error_message = "The GCP project ID must be all lowercase and can contain letters, numbers, and hyphens."
  }
}

# Azure Build Variables
variable "azure_subscription_id" {
  type    = string
  default = env("CONF_AZURE_SUBSCRIPTION")
  validation {
    condition     = var.azure_subscription_id == "" || can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.azure_subscription_id))
    error_message = "Must provide a valid azure subscription ID."
  }
}
variable "source_azure_image_publisher" {
  type    = string
  default = "Canonical"
}
variable "source_azure_image_offer" {
  type    = string
  default = "0001-com-ubuntu-server-jammy"
}
variable "source_azure_image_sku" {
  type    = string
  default = "22_04-lts-gen2"
}
variable "azure_resource_group" {
  type    = string
  default = env("CONF_AZURE_RESOURCE_GROUP")
  validation {
    condition     = var.azure_resource_group == "" || can(regex("^[a-z0-9-]+$", var.azure_resource_group))
    error_message = "The azure resource group must be all lowercase and can contain letters, numbers, and hyphens."
  }
}
variable "azure_region" {
  type    = string
  default = env("CONF_AZURE_REGION")
  validation {
    condition     = var.azure_region == "" || can(regex("^[a-z0-9]+$", var.azure_region))
    error_message = "The azure region must be all lowercase and have no spaces, e.g., eastus2."
  }
}
variable "azure_image_gallery_name" {
  type    = string
  default = env("CONF_AZURE_IMAGE_GALLERY")
  validation {
    condition     = var.azure_image_gallery_name == "" || can(regex("^[a-z0-9_]+$", var.azure_image_gallery_name))
    error_message = "The azure image gallery name must be all lowercase and can contain letters, numbers, and underscores."
  }
}

# Shared Build Variables
variable "image_family" {
  type    = string
  default = env("CONFSEC_IMAGE_FAMILY") != "" ? env("CONFSEC_IMAGE_FAMILY") : "build-aux"
}

variable "git_hash" {
  type    = string
  default = env("CONFSEC_GIT")
  validation {
    condition     = can(regex("^[0-9a-f]{7,40}$", var.git_hash))
    error_message = "Must provide a valid git commit hash."
  }
}
variable "host_disk_size" {
  type    = number
  default = 32
}
variable "aux_disk_size" {
  type    = number
  default = 32
}
variable "disk_interface" {
  type    = string
  default = "NVME"
  validation {
    condition     = can(regex("^(NVME|SCSI)$", var.disk_interface))
    error_message = "Interface type must be NVME or SCSI."
  }
}

# GCP Build Locals
local "gcp_disk_type" {
  expression = var.disk_interface == "NVME" ? "pd-ssd" : "pd-standard"
}

# Azure Build Locals (VM SKU)
local "azure_vm_size" {
  expression = var.disk_interface == "NVME" ? "Standard_D4s_v6" : "Standard_D4s_v4"
}

# Shared Build Locals
local "build_id" {
  expression = uuidv4()
}
local "image_name" {
  expression = "${var.image_family}-${formatdate("YYYYMMDD", timestamp())}-${local.build_id}"
}
local "build_vm_name" {
  expression = "${var.image_family}-${local.build_id}"
}

local "image_version" {
  expression = "${formatdate("YYYY", timestamp())}.${formatdate("MMDD", timestamp())}.${formatdate("hhmmss", timestamp())}"
}

source "googlecompute" "default" {
  instance_name = local.build_vm_name
  disk_size     = var.host_disk_size
  image_name    = local.image_name
  image_family  = var.image_family
  image_labels = {
    "git" = var.git_hash
  }
  use_iap      = var.use_iap
  project_id   = var.gcp_project_id
  source_image = var.source_gcp_image_host
  zone         = var.gcp_build_zone
  ssh_username = "packer"
  machine_type = "c3-standard-4"
  disk_type    = local.gcp_disk_type
  disk_attachment {
    create_image   = true
    source_image   = var.source_gcp_image_aux
    volume_size    = var.aux_disk_size
    volume_type    = local.gcp_disk_type
    interface_type = var.disk_interface
  }
}

source "azure-arm" "default" {
  temp_compute_name = local.build_vm_name
  os_disk_size_gb   = var.host_disk_size
  # Note that we cannot bump the disk tier here since we are using a marketplace image.
  temp_os_disk_name = local.build_vm_name

  image_publisher = var.source_azure_image_publisher
  image_offer     = var.source_azure_image_offer
  image_sku       = var.source_azure_image_sku

  subscription_id          = var.azure_subscription_id
  location                 = var.azure_region
  temp_resource_group_name = local.build_vm_name

  use_azure_cli_auth = true

  vm_size = local.azure_vm_size
  os_type = "Linux"

  managed_image_name                 = local.image_name
  managed_image_resource_group_name  = var.azure_resource_group
  managed_image_storage_account_type = "Premium_LRS"

  shared_image_gallery_destination {
    subscription   = var.azure_subscription_id
    resource_group = var.azure_resource_group
    gallery_name   = var.azure_image_gallery_name
    image_name     = var.image_family
    # The SIG API requires semver, which is annoying for our use case.
    # Use the year as the major version, month/day as the minor, and hour(24h format)/minute/seconds as the patch (all padded).
    # This should give us a unique version for each build, while still being sortable chronologically,
    # which means the "latest" tag will always point to the most recent build.
    image_version        = local.image_version
    storage_account_type = "Premium_LRS"
    target_region {
      name = var.azure_region
    }
    use_shallow_replication = true
  }

  azure_tags = {
    "git" = var.git_hash
  }
}

locals {
  build_args = {
    disk_interface = {
      qemu          = "SCSI", # NVME is not configured in QEMU now.
      azure-arm     = var.disk_interface,
      googlecompute = var.disk_interface,
    }
  }
}

build {
  name = local.image_name
  sources = [
    "source.googlecompute.default",
    "source.azure-arm.default",
    "source.qemu.default"
  ]

  # log the exact source image being used for azure builds
  provisioner "shell-local" {
    only = ["azure-arm.default"]
    inline = [
      "echo 'azure vm source image details:'",
      "az vm show --resource-group ${local.build_vm_name} --name ${local.build_vm_name} --query 'storageProfile.imageReference' --output table"
    ]
  }

  provisioner "shell-local" {
    only = ["azure-arm.default"]
    environment_vars = [
      "RESOURCE_GROUP=${local.build_vm_name}",
      "VM_NAME=${local.build_vm_name}",
      "LOCATION=${var.azure_region}",
      "AUX_DISK_SIZE=${var.aux_disk_size}",
      "SOURCE_IMAGE_PUBLISHER=${var.source_azure_image_publisher}",
      "SOURCE_IMAGE_OFFER=${var.source_azure_image_offer}",
      "SOURCE_IMAGE_SKU=${var.source_azure_image_sku}",
    ]
    script = "../scripts/attach_azure_disk_from_urn.sh"
  }

  provisioner "shell-local" {
    # (QEMU only) Attach secondary drive
    only = ["qemu.default"]
    inline = [
      "echo '{\"execute\": \"qmp_capabilities\"} {\"execute\": \"device_add\", \"arguments\": {\"driver\": \"scsi-hd\", \"bus\": \"scsi0.0\", \"drive\": \"drive1\"}}' | nc -N localhost ${var.qemu_qmp_port}"
    ]
  }

  provisioner "shell" {
    script          = "provisioners/shell/prep_aux.sh"
    execute_command = "CONFSEC_DISK_INTERFACE=${local.build_args.disk_interface[source.type]} sudo -E bash '{{.Path}}'"
  }

  post-processors {
    post-processor "shell-local" {
      only = ["qemu.default"]
      inline = [
        # We've attached auxilary image manually, so we have to move it to the output directory manually.
        "mv ${local.qemu_aux_img_path} ${local.aux_output_image_name}",
        # And we don't care about primary image at all, so we can delete it.
        "rm ${local.qemu_image_path}"
      ]
    }

    post-processor "shell-local" {
      only = ["qemu.default"]
      environment_vars = [
        "SOURCE_IMG=${local.aux_output_image_name}",
        "TARGET_REPOSITORY_PROJECT_ID=${var.qemu_artifact_registry_project_id}",
        "TARGET_REPOSITORY_LOCATION=${var.qemu_artifact_registry_location}",
        "TARGET_REPOSITORY_NAME=${var.qemu_artifact_registry_repository_name}",
        "TARGET_PACKAGE=${var.qemu_artifact_registry_target_package}",
        "TARGET_VERSION=${local.image_version}",
        "LOCAL_ONLY=${var.qemu_local_only}"
      ]
      script = "../scripts/qemu_upload_image_to_repository.sh"
    }
  }
}
