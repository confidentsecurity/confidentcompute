/*
  build_selinux

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
  default = env("CONFSEC_IMAGE_FAMILY") != "" ? env("CONFSEC_IMAGE_FAMILY") : "build-selinux"
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
variable "policy_path" {
  type = string
  # Downloaded via https://github.com/confidentsecurity/compute-sepolicy/actions/workflows/compile_policy.yml
  default = "/tmp/confident_policy"
}
variable "source_image_family" {
  type    = string
  default = env("CONFSEC_HOST_SOURCE_IMAGE_FAMILY") != "" ? env("CONFSEC_HOST_SOURCE_IMAGE_FAMILY") : "build-host"
}

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
  use_iap             = var.use_iap
  project_id          = var.gcp_project_id
  source_image_family = var.source_image_family
  zone                = var.gcp_build_zone
  ssh_username        = "packer"
}

source "azure-arm" "default" {
  temp_compute_name        = local.build_vm_name
  os_disk_size_gb          = var.host_disk_size
  os_disk_performance_tier = "P30"
  temp_os_disk_name        = local.build_vm_name

  shared_image_gallery {
    subscription   = var.azure_subscription_id
    resource_group = var.azure_resource_group
    gallery_name   = var.azure_image_gallery_name
    image_name     = var.source_image_family
  }

  subscription_id          = var.azure_subscription_id
  location                 = var.azure_region
  temp_resource_group_name = local.build_vm_name

  use_azure_cli_auth = true

  vm_size           = "Standard_D4s_v6"
  os_type           = "Linux"
  disk_caching_type = "None"

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
  provisioner "file" {
    sources     = [var.policy_path]
    destination = "/tmp/"
  }
  provisioner "shell" {
    script            = "provisioners/shell/prep_selinux.sh"
    execute_command   = "sudo -E bash '{{.Path}}'"
    expect_disconnect = true
    # Skip cleaning up the provisioner script in /tmp since that requires reconnecting to the VM,
    # and the VM may take a bit to reboot (see timeouts below).
    skip_clean = true
  }
  provisioner "shell" {
    start_retry_timeout = "15m"
    pause_before        = "30s"
    script              = "provisioners/shell/ima_touch_files.sh"
    execute_command     = "sudo -E bash '{{.Path}}'"
  }

  post-processor "shell-local" {
    only = ["qemu.default"]
    environment_vars = [
      "SOURCE_IMG=${local.qemu_image_path}",
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
