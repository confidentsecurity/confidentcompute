#!/bin/bash
set -euo pipefail

# This script attaches an Azure disk to a VM from a derived shared image gallery image data disk (LUN=0).
# The Azure packer plugin does not support attaching secondary disks at all, so we have to do it manually.
# Note that this operation can take up to 5 minutes.

SOURCE_IMAGE="$(az sig image-version list --resource-group "${IMAGE_RESOURCE_GROUP}" --gallery-name "${IMAGE_GALLERY}" \
	--gallery-image-definition "${BUILD_FAMILY}" --query "max_by([], &name).id" --output tsv)"

az disk create \
	--resource-group "${RESOURCE_GROUP}" \
	--name "${VM_NAME}"-1 \
	--location "${LOCATION}" \
	--gallery-image-reference "${SOURCE_IMAGE}" \
	--gallery-image-reference-lun 0 \
	--os-type "Linux" \
	--size-gb "${AUX_DISK_SIZE}" \
	--hyper-v-generation V2 \
	--security-type standard \
	--tier P30

az vm disk attach \
  --resource-group "${RESOURCE_GROUP}" \
  --vm-name "${VM_NAME}" \
  --name "${VM_NAME}"-1 \
  --caching None
