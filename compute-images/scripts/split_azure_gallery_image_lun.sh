#!/bin/bash
set -euo pipefail

# The Azure packer plugin does not support publishing a shared image gallery definition
# directly from a managed image with a data disk (LUN). Instead, we have to create a new
# managed image from the LUN=0 disk, and then publish that to the gallery (under a different image definition).

# This script assumes that the combined image definition has already been created using the `-combined` suffix.
SOURCE_IMAGE="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${IMAGE_RESOURCE_GROUP}/providers/Microsoft.Compute/galleries/${IMAGE_GALLERY}/images/${BUILD_FAMILY}-combined/versions/${IMAGE_VERSION}"

az disk create \
	--resource-group "${IMAGE_RESOURCE_GROUP}" \
	--name "${IMAGE_NAME}"-split \
	--location "${LOCATION}" \
	--gallery-image-reference "${SOURCE_IMAGE}" \
	--gallery-image-reference-lun 0 \
	--os-type "Linux" \
	--size-gb "${AUX_DISK_SIZE}" \
	--hyper-v-generation V2 \
	--security-type standard

az image create \
  --resource-group "${IMAGE_RESOURCE_GROUP}" \
  --name "${IMAGE_NAME}"-split \
  --source "${IMAGE_NAME}"-split \
  --os-type "Linux" \
  --hyper-v-generation v2 \
  --location "${LOCATION}"

# Publish the image to the build family gallery (omitting the `-combined` suffix this time).
# Copy over the image version from the combined image definition to create a 1:1 mapping.
az sig image-version create \
  --resource-group "${IMAGE_RESOURCE_GROUP}" \
  --gallery-name "${IMAGE_GALLERY}" \
  --gallery-image-definition "${BUILD_FAMILY}" \
  --gallery-image-version "${SOURCE_IMAGE##*/}" \
  --managed-image "${IMAGE_NAME}"-split \
  --replication-mode shallow \
  --storage-account-type Premium_LRS \
  --target-regions "${LOCATION}"

 az disk delete \
  --name "${IMAGE_NAME}"-split \
  --resource-group "${IMAGE_RESOURCE_GROUP}" \
  --yes \
  --no-wait
