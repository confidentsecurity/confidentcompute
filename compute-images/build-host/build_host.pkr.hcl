/*
  build_host

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
variable "source_gcp_image" {
  type    = string
  default = "ubuntu-2204-jammy-v20250508"
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
  default = env("CONFSEC_IMAGE_FAMILY") != "" ? env("CONFSEC_IMAGE_FAMILY") : "build-host"
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
  source_image = var.source_gcp_image
  zone         = var.gcp_build_zone
  ssh_username = "packer"
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

  vm_size = "Standard_D4s_v6"
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
  provisioner "shell" {
    # Unattended upgrades can interrupt graceful VM shutdown, and cause SE linux denial spam.
    # This shows up on qemu builds, unattended upgrades is taking forever to finish and we don't want to kill the VM.
    # TODO: We can probably just uninstall unattended-upgrades entirely, but that needs to be tested.
    scripts         = ["provisioners/shell/stop_unattended_upgrades.sh"]
    execute_command = "sudo -E bash '{{.Path}}'"
  }
  provisioner "shell" {
    only            = ["qemu.default"]
    script          = "provisioners/shell/prep_host.sh"
    execute_command = "CLOUD=gcp sudo -E bash '{{.Path}}'"
  }
  provisioner "file" {
    only        = ["qemu.default"]
    source      = local.kernel_tar_path
    destination = "/tmp/kernel-deb.tar"
  }
  provisioner "shell" {
    # install 6.16 kernel with SVSM support
    only              = ["qemu.default"]
    scripts           = ["provisioners/shell/install_kernel_tmp.sh"]
    execute_command   = "sudo -E bash '{{.Path}}'"
    expect_disconnect = true
  }
  provisioner "shell" {
    pause_before    = "1m"
    only            = ["qemu.default"]
    scripts         = ["provisioners/shell/cleanup_old_kernel.sh"]
    execute_command = "sudo -E bash '{{.Path}}'"
  }
  # Packer won't let us set a local based on the current build source (since its dynamic),
  # so we have to duplicate the provisioner for each source to deduce what
  # `CLOUD` should be at runtime, unfortunately.
  provisioner "shell" {
    only            = ["googlecompute.default"]
    script          = "provisioners/shell/prep_host.sh"
    execute_command = "CLOUD=gcp sudo -E bash '{{.Path}}'"
  }
  provisioner "shell" {
    only            = ["azure-arm.default"]
    script          = "provisioners/shell/prep_host.sh"
    execute_command = "CLOUD=azure sudo -E bash '{{.Path}}'"
  }
  provisioner "shell" {
    only            = ["azure-arm.default", "googlecompute.default", "qemu.default"]
    script          = "./provisioners/shell/install_vllm.sh"
    execute_command = "sudo -E bash '{{.Path}}'"
  }
  provisioner "shell" {
    only              = ["googlecompute.default"]
    script            = "../scripts/install-nvidia.sh"
    execute_command   = "CLOUD=gcp sudo -E bash '{{.Path}}'"
    expect_disconnect = true
  }
  provisioner "shell" {
    only              = ["azure-arm.default"]
    script            = "../scripts/install-nvidia.sh"
    execute_command   = "CLOUD=azure sudo -E bash '{{.Path}}'"
    expect_disconnect = true
  }
  provisioner "file" {
    only        = ["qemu.default"]
    sources     = ["${var.qemu_signing_key_dir}/signing_key.pem", "${var.qemu_signing_key_dir}/signing_key.der"]
    destination = "/tmp/"
  }
  provisioner "shell" {
    only = ["qemu.default"]
    # We are using custom kernel installation, we cannot install drivers from the ubuntu repository
    script            = "./provisioners/shell/install_nvidia_local_repo.sh"
    execute_command   = "sudo -E bash '{{.Path}}'"
    expect_disconnect = true
  }
  provisioner "shell" {
    # Check if the machine rebooted and finish script
    pause_before    = "1m"
    only            = ["qemu.default"]
    inline          = ["echo 'boot'"]
    execute_command = "sudo -E bash '{{.Path}}'"
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
