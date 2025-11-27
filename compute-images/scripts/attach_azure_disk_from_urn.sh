#!/bin/bash
set -euo pipefail

# This script attaches an Azure disk to a VM from a constructed URN (publisher:offer:sku:version) string.
# The Azure packer plugin does not support attaching secondary disks at all, so we have to do it manually.
# Note that this operation can take up to 5 minutes.

az disk create \
	--resource-group "${RESOURCE_GROUP}" \
	--name "${VM_NAME}"-1 \
	--location "${LOCATION}" \
	--image-reference "${SOURCE_IMAGE_PUBLISHER}":"${SOURCE_IMAGE_OFFER}":"${SOURCE_IMAGE_SKU}":latest \
	--os-type "Linux" \
	--size-gb "${AUX_DISK_SIZE}" \
	--hyper-v-generation V2 \
	--security-type standard \
	--tier P30

# Attach the disk with ReadWrite caching enabled to match the OS disk.
# It seems to help slightly with performance.
# If we run into consistency issues during our builds, we can always disable it.
az vm disk attach \
  --resource-group "${RESOURCE_GROUP}" \
  --vm-name "${VM_NAME}" \
  --name "${VM_NAME}"-1 \
  --caching None
