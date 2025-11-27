#!/bin/bash
set -euo pipefail

artifact_registry_project_id="$1"
artifact_registry_location="$2"
artifact_registry_repository_name="$3"
artifact_registry_artifact_name="$4"
iso_path="$5"
local_only="$6"

if [ "$artifact_registry_project_id" = '<empty>' ]; then
  # Packer will invoke our external datasource even if the qemu is skipped. Let's skip the execution when default value of the projectid variable is used.
  echo -n "<empty>"
  exit 0
fi

if [ "$local_only" = 'true' ]; then
  if [ -f "$iso_path" ]; then
    echo "local_only set to true and $iso_path exists, skipping download." >&2
    echo -n "$iso_path"
    exit 0
  fi
  echo "local_only set to true and but $iso_path noesn't exists, downloading." >&2
fi

iso_path_dir="$(dirname "$(readlink -f "$iso_path")")"
iso_path_basename="$(basename "$(readlink -f "$iso_path")")"

gcloud artifacts files download \
  --project "${artifact_registry_project_id}" \
  --location "${artifact_registry_location}" \
  --repository "${artifact_registry_repository_name}" \
  --destination "${iso_path_dir}" \
  --local-filename "${iso_path_basename}" \
  --parallelism 64 \
  "${artifact_registry_artifact_name}" >&2

echo -n "$iso_path"
