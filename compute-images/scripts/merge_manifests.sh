#!/bin/bash
set -euo pipefail

# Use a lock file to prevent races when parallel build call our script simultaneously.
exec 200>"/tmp/merge_manifests.sh.lock"
# Wait up to 60 seconds to obtain a flock on fd 200. The lock is released when the script ends.
flock --timeout 60 200

# cd to script dir
# If the output doesn't exist we want to start with a copy of packer-manifest but with empty builds.
if [ ! -f "$OUTPUT_MANIFEST_PATH" ]; then
  jq '.builds = []' "$PACKER_MANIFEST_PATH" > "$OUTPUT_MANIFEST_PATH"
fi

# We'll build a .builds entry in a separate file
MANIFEST_ENTRY_TEMP_PATH="/tmp/${BUILDER_TYPE}-manifest-data.json"

# Get build info from packer-manifest for currently processed build.
jq --arg builder_type "$BUILDER_TYPE" '.builds | map(select(.builder_type == $builder_type)) | first' "$PACKER_MANIFEST_PATH" > "$MANIFEST_ENTRY_TEMP_PATH".0

# Add data from $BUILD_MANIFEST_PATH to custom_data in our build entry.
jq --slurpfile build_custom "$BUILD_MANIFEST_PATH" '
  .custom_data = (.custom_data // {}) + {
    build_env: ($build_custom[0].build_env // {}),
    kernel_cmdlines: ($build_custom[0].kernel_cmdlines // []),
    gpt_layout: ($build_custom[0].gpt_layout // ""),
    selinux_policy_version: ($build_custom[0].selinux_policy_version // ""),
    selinux_policy_hash: ($build_custom[0].selinux_policy_hash // "")
  }
' "$MANIFEST_ENTRY_TEMP_PATH".0 > "$MANIFEST_ENTRY_TEMP_PATH".1

# Modify other fields when it's required.
if [ "$BUILDER_TYPE" = "azure-arm" ]; then
  # Override artifact_id for Azure after the final image split so the packer manifest contains the correct image ID.
  # Note that we can do this without ruining the integrity of the manifest since the split script does not modify the image.
  # In an effort to avoid leaking our internal subscription ID and resource group names, we output the image version ONLY,
  # and treat this string as the image ID later (which is similar to how we handle this on GCP).
  jq --arg artifact "$AZURE_FINAL_ARTIFACT_ID" '.artifact_id = $artifact' "$MANIFEST_ENTRY_TEMP_PATH".1 > "$MANIFEST_ENTRY_TEMP_PATH".2
elif [ "$BUILDER_TYPE" = "qemu" ]; then
  # QEMU builder set's artifact id to "VM", but we need to store a string that identifies artifact in Artifact Registry.
  jq --arg artifact "$QEMU_FINAL_ARTIFACT_ID" '.files = null | .artifact_id = $artifact' "$MANIFEST_ENTRY_TEMP_PATH".1 > "$MANIFEST_ENTRY_TEMP_PATH".2
else
  cp "$MANIFEST_ENTRY_TEMP_PATH".1 "$MANIFEST_ENTRY_TEMP_PATH".2
fi

# Add our builds entry to the output manifest
jq --slurpfile newbuild "$MANIFEST_ENTRY_TEMP_PATH".2 '.builds += [$newbuild[0]]' "$OUTPUT_MANIFEST_PATH" > "$OUTPUT_MANIFEST_PATH".tmp
mv "$OUTPUT_MANIFEST_PATH".tmp "$OUTPUT_MANIFEST_PATH"
