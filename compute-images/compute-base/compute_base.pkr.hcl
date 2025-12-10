/*
  compute_base

  Variables:
    - CONF_GCP_BUILD_ZONE: GCP zone to build the image in
    - CONF_GCP_PROJECT_ID: GCP project to build the image in
    - CONF_AZURE_REGION: Azure region to build the image in
    - CONF_AZURE_SUBSCRIPTION: Azure subscription to build the image in
    - CONF_AZURE_IMAGE_GALLERY: Azure image gallery to build the image in
    - CONF_UNRESTRICTED_TELEMETRY: Whether or not to enable unrestricted telemetry
    - CONFSEC_GIT: Current git commit hash
    - CONFSEC_HARDENING_SCOPE: Scope of hardening the image (0 is maximally hardened)
    - CONFSEC_VERITY_PANIC: Whether or not dm-verity will panic on corruption (or ignore corruption)
    - CONFSEC_DEBUG_SCOPE: Scope of debug output for the image (0 is maxmimal debug output)
    - CONFSEC_OPTIMIZE_DISK: Whether or not to optimize for disk size
    - CONFSEC_HOST_SOURCE_IMAGE: URI path for the host image
    - CONFSEC_AUX_SOURCE_IMAGE: URI path for the auxiliary image
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
variable "src_image_gcp_project_id" {
  type    = string
  default = env("CONFSEC_IMAGE_SRC_PROJECT_NAME")
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
variable "build_artifact_directory" {
  type    = string
  default = env("CONF_BUILD_ARTIFACT_DIRECTORY") != "" ? env("CONF_BUILD_ARTIFACT_DIRECTORY") : "../../../../build"
  validation {
    condition     = var.build_artifact_directory != ""
    error_message = "Must provide a valid build artifact directory containing confident compute binaries."
  }
}
variable "git_hash" {
  type    = string
  default = env("CONFSEC_GIT")
  validation {
    condition     = can(regex("^[0-9a-f]{7,40}$", var.git_hash))
    error_message = "Must provide a valid git commit hash."
  }
}
variable "hardening_scope" {
  type    = number
  default = env("CONFSEC_HARDENING_SCOPE") != "" ? env("CONFSEC_HARDENING_SCOPE") : 0
  validation {
    condition     = var.hardening_scope >= 0
    error_message = "Hardening scope must be non-negative."
  }
}
variable "verity_panic" {
  type    = bool
  default = env("CONFSEC_VERITY_PANIC") != "" ? env("CONFSEC_VERITY_PANIC") == "true" : false
}
variable "debug_scope" {
  type    = number
  default = env("CONFSEC_DEBUG_SCOPE") != "" ? env("CONFSEC_DEBUG_SCOPE") : 0
  validation {
    condition     = var.debug_scope >= 0
    error_message = "Debug scope must be non-negative."
  }
}
variable "optimize_disk" {
  type    = bool
  default = env("CONFSEC_OPTIMIZE_DISK") != "" ? env("CONFSEC_OPTIMIZE_DISK") == "true" : false
}
variable "host_disk_size" {
  type    = number
  default = 32
}
variable "aux_disk_size" {
  type    = number
  default = 36
}
variable "aux_source_image_family" {
  type    = string
  default = env("CONFSEC_AUX_SOURCE_IMAGE_FAMILY") != "" ? env("CONFSEC_AUX_SOURCE_IMAGE_FAMILY") : "crypt-base"
}
variable "aux_source_image" {
  type    = string
  default = env("CONFSEC_AUX_SOURCE_IMAGE")
  validation {
    condition     = var.aux_source_image == "" || can(regex(".*crypt-base-.+$", var.aux_source_image))
    error_message = "The auxiliary image path must conform to the naming scheme."
  }
}
variable "host_source_image_family" {
  type    = string
  default = env("CONFSEC_HOST_SOURCE_IMAGE_FAMILY") != "" ? env("CONFSEC_HOST_SOURCE_IMAGE_FAMILY") : "build-selinux"
}
variable "host_source_image" {
  type    = string
  default = env("CONFSEC_HOST_SOURCE_IMAGE")
  validation {
    condition     = var.host_source_image == "" || can(regex(".*build-selinux-.+$", var.host_source_image))
    error_message = "The host image path must conform to the naming scheme."
  }
}
variable "disk_interface" {
  type    = string
  default = "NVME"
  validation {
    condition     = can(regex("^(NVME|SCSI)$", var.disk_interface))
    error_message = "Interface type must be NVME or SCSI."
  }
}
variable "image_family" {
  type    = string
  default = env("CONFSEC_IMAGE_FAMILY") != "" ? env("CONFSEC_IMAGE_FAMILY") : "compute-base"
}
variable "unrestricted_telemetry" {
  type    = bool
  default = env("CONF_UNRESTRICTED_TELEMETRY") != "" ? env("CONF_UNRESTRICTED_TELEMETRY") == "true" : false
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
  # The SIG API requires semver, which is annoying for our use case.
  # Use the year as the major version, month/day as the minor, and hour(24h format)/minute/seconds as the patch (all padded).
  # This should give us a unique version for each build, while still being sortable chronologically,
  # which means the "latest" tag will always point to the most recent build.
  # We calculate this ahead of the build so we can pass it to the split_azure_gallery_image_lun.sh script.
  expression = "${formatdate("YYYY", timestamp())}.${formatdate("MMDD", timestamp())}.${formatdate("hhmmss", timestamp())}"
}

local "build_args" {
  expression = {
    disk_interface = {
      qemu          = "SCSI", # NVME is not configured in QEMU now.
      azure-arm     = var.disk_interface,
      googlecompute = var.disk_interface,
    },
    build_manifest_path = {
      qemu : "/tmp/qemu-manifest.json",
      azure-arm : "/tmp/azure-manifest.json",
      googlecompute : "/tmp/gcp-manifest.json",
    }
  }
}

source "googlecompute" "default" {
  instance_name = local.build_vm_name
  disk_size     = var.host_disk_size
  image_name    = local.image_name
  image_family  = var.image_family
  image_labels = {
    "git"             = var.git_hash
    "hardening_scope" = var.hardening_scope
    "debug_scope"     = var.debug_scope
    "verity_panic"    = var.verity_panic
    "optimize_disk"   = var.optimize_disk
  }
  use_iap                 = var.use_iap
  project_id              = var.gcp_project_id
  source_image            = var.host_source_image
  source_image_project_id = [var.src_image_gcp_project_id]
  zone                    = var.gcp_build_zone
  ssh_username            = "packer"
  machine_type            = "c3-standard-4"
  disk_type               = local.gcp_disk_type
  disk_attachment {
    create_image   = true
    source_image   = var.aux_source_image
    volume_size    = var.aux_disk_size
    volume_type    = local.gcp_disk_type
    interface_type = var.disk_interface
  }
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
    image_name     = var.host_source_image_family
  }

  subscription_id            = var.azure_subscription_id
  location                   = var.azure_region
  temp_resource_group_name   = local.build_vm_name
  async_resourcegroup_delete = true

  use_azure_cli_auth = true

  vm_size           = local.azure_vm_size
  os_type           = "Linux"
  disk_caching_type = "None"

  managed_image_name                 = local.image_name
  managed_image_resource_group_name  = var.azure_resource_group
  managed_image_storage_account_type = "Premium_LRS"

  shared_image_gallery_destination {
    subscription         = var.azure_subscription_id
    resource_group       = var.azure_resource_group
    gallery_name         = var.azure_image_gallery_name
    image_name           = "${var.image_family}-combined"
    image_version        = local.image_version
    storage_account_type = "Premium_LRS"
    target_region {
      name = var.azure_region
    }
    use_shallow_replication = true
  }

  azure_tags = {
    "git"             = var.git_hash
    "hardening_scope" = var.hardening_scope
    "debug_scope"     = var.debug_scope
    "verity_panic"    = var.verity_panic
    "optimize_disk"   = var.optimize_disk
  }
}

build {
  name = local.image_name
  sources = [
    "source.googlecompute.default",
    "source.azure-arm.default",
    "source.qemu.default",
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
      "IMAGE_RESOURCE_GROUP=${var.azure_resource_group}",
      "IMAGE_GALLERY=${var.azure_image_gallery_name}",
      "VM_NAME=${local.build_vm_name}",
      "LOCATION=${var.azure_region}",
      "AUX_DISK_SIZE=${var.aux_disk_size}",
      "BUILD_FAMILY=${var.aux_source_image_family}",
    ]
    script = "../scripts/attach_azure_disk_from_gallery_lun.sh"
  }
  provisioner "file" {
    sources = [
      "${var.build_artifact_directory}/compute_boot",
      "${var.build_artifact_directory}/compute_worker",
      "${var.build_artifact_directory}/router_com",
      "../../cmd/compute_boot/make-compute-boot",
      "../../cmd/router_com/make-compute-config",
      "../../cmd/compute_boot/compute-boot-secret-wrapper",
      "../../cmd/router_com/router-com-secret-wrapper",
      "../../cmd/compute_boot/compute_boot.yaml.template",
      "../../cmd/router_com/router_com.yaml.template",
      "../../cmd/compute_boot/compute_boot.service",
      "../../cmd/router_com/router_com.service",
      "provisioners/files/after_system_conf.conf",
      "provisioners/files/system.conf",
      "provisioners/files/system_conf.service",
      "provisioners/files/wait-for-nvidia-driver-init.sh",
      "provisioners/files/wait-for-nvidia-driver-init.service",
    ]
    destination = "/tmp/"
  }
  # copy the right alloy file depending on this being an unrestricted telemetry build or not.
  provisioner "file" {
    source      = var.unrestricted_telemetry ? "provisioners/files/config_unrestricted.alloy" : "provisioners/files/config.alloy"
    destination = "/tmp/config.alloy"
  }
  provisioner "file" {
    only = ["googlecompute.default"]
    sources = [
      "provisioners/files/gcp/system_conf.sh"
    ]
    destination = "/tmp/"
  }
  provisioner "file" {
    only = ["azure-arm.default"]
    sources = [
      "provisioners/files/azure/system_conf.sh"
    ]
    destination = "/tmp/"
  }
  provisioner "file" {
    only = ["qemu.default"]
    sources = [
      "provisioners/files/qemu/system_conf.sh"
    ]
    destination = "/tmp/"
  }
  # Uncomment this block if you want to copy in a newer version of the Confident
  # SE linux policy from your local machine into the final VM image.
  # See also the commented blocks in prep_compute.sh & packer-build-compute-base.yaml.
  # This is useful for iterating on SE linux policy changes without having to rebuild
  # the SE linux and crypt base images every time. Note that once the policy is correct,
  # you may still want to test building new SE linux and crypt base images to ensure
  # the policy is correctly applied in the final image. Images using this trick
  # should NOT be pushed to the common dev / stage image families.
  # provisioner "file" {
  #   sources     = ["/tmp/confident_policy"]
  #   destination = "/tmp/"
  # }
  # provisioner "shell" {
  #   inline = [
  #     "sudo cp -r /tmp/confident_policy/* /etc/selinux/confident_policy/",
  #     "sudo semodule -R" # Rebuild and reload all policy modules
  #   ]
  # }
  provisioner "shell" {
    scripts         = ["provisioners/shell/prep_compute.sh"]
    execute_command = <<EOF
      CONFSEC_GIT=${var.git_hash}                    \
      CONFSEC_BUILD_ID=${local.build_id}             \
      CONFSEC_HARDENING_SCOPE=${var.hardening_scope} \
      CONFSEC_VERITY_PANIC=${var.verity_panic}       \
      CONFSEC_DEBUG_SCOPE=${var.debug_scope}         \
      CONFSEC_OPTIMIZE_DISK=${var.optimize_disk}     \
      CONFSEC_DISK_INTERFACE=${local.build_args.disk_interface[source.type]}   \
      sudo -E bash '{{.Path}}'
    EOF
  }
  provisioner "file" {
    direction   = "download"
    sources     = ["/tmp/manifest.json"]
    destination = local.build_args.build_manifest_path[source.type]
  }
  post-processor "manifest" {
    output     = "packer-build.json"
    strip_path = false
  }

  post-processor "shell-local" {
    only = ["azure-arm.default"]
    environment_vars = [
      "IMAGE_RESOURCE_GROUP=${var.azure_resource_group}",
      "IMAGE_GALLERY=${var.azure_image_gallery_name}",
      "LOCATION=${var.azure_region}",
      "AUX_DISK_SIZE=${var.aux_disk_size}",
      "BUILD_FAMILY=${var.image_family}",
      "IMAGE_NAME=${local.image_name}",
      "IMAGE_VERSION=${local.image_version}",
      "SUBSCRIPTION_ID=${var.azure_subscription_id}",
    ]
    script = "../scripts/split_azure_gallery_image_lun.sh"
  }

  post-processor "shell-local" {
    only = ["qemu.default"]
    inline = [
      # We've attached auxilary image manually, so we have to move it to the output directory manually.
      "mv ${local.qemu_aux_img_path} ${local.aux_output_image_path}",
      # And we don't care about primary image at all, so we can delete it.
      "rm ${local.qemu_image_path}"
    ]
  }

  post-processor "shell-local" {
    only = ["qemu.default"]
    inline = [
      # Compact and compress output image
      "if [ ${var.qemu_compress_result} = 'true' ]; then",
      "qemu-img convert -c -O qcow2 ${local.aux_output_image_path} ${local.aux_output_image_path}.compressed",
      "mv ${local.aux_output_image_path}.compressed ${local.aux_output_image_path}",
      "fi"
    ]
  }

  post-processor "shell-local" {
    only = ["qemu.default"]
    environment_vars = [
      "SOURCE_IMG=${local.aux_output_image_path}",
      "TARGET_REPOSITORY_PROJECT_ID=${var.qemu_artifact_registry_project_id}",
      "TARGET_REPOSITORY_LOCATION=${var.qemu_artifact_registry_location}",
      "TARGET_REPOSITORY_NAME=${var.qemu_artifact_registry_repository_name}",
      "TARGET_PACKAGE=${var.qemu_artifact_registry_target_package}",
      "TARGET_VERSION=${local.image_version}",
      "LOCAL_ONLY=${var.qemu_local_only}"
    ]
    script = "../scripts/qemu_upload_image_to_repository.sh"
  }

  # The script adds an entry for current builder to packer-manifest.json.
  # This process is guarded by a mutex to prevent concurrent access by parallel builds.
  post-processor "shell-local" {
    env = {
      "BUILDER_TYPE" : source.type,
      "AZURE_FINAL_ARTIFACT_ID" : local.image_version,
      "QEMU_FINAL_ARTIFACT_ID" : "${var.qemu_artifact_registry_target_package}:${local.image_version}:${local.aux_output_image_basename}"
      "BUILD_MANIFEST_PATH" : local.build_args.build_manifest_path[source.type],
      "PACKER_MANIFEST_PATH" : "./packer-build.json",
      "OUTPUT_MANIFEST_PATH" : "./packer-manifest.json",
    }
    script = "../scripts/merge_manifests.sh"
  }
}
