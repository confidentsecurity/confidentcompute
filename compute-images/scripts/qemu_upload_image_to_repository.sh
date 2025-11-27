#!/bin/bash
set -euo pipefail

GCLOUD_COMMAND="gcloud"
if [ "${LOCAL_ONLY}" = 'true' ]; then
  echo "LOCAL_ONLY set to 'true', won't upload the artifact..." >&2
  GCLOUD_COMMAND="echo (did not run) $GCLOUD_COMMAND"
fi

$GCLOUD_COMMAND artifacts generic upload \
  --project "${TARGET_REPOSITORY_PROJECT_ID}" \
  --source="${SOURCE_IMG}" \
  --package="${TARGET_PACKAGE}" \
  --version="${TARGET_VERSION}" \
  --repository "${TARGET_REPOSITORY_NAME}" \
  --location "${TARGET_REPOSITORY_LOCATION}" >&2
