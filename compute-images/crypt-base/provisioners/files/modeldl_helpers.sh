#!/bin/bash

if ! [[ -v HARDEN_DRACUT_PANIC && -n "$HARDEN_DRACUT_PANIC" ]]; then
    echo "HARDEN_DRACUT_PANIC not set, exiting..."
    exit 1
fi
if ! [[ -v MOUNT_PREFIX && -n "$MOUNT_PREFIX" ]]; then
    echo "MOUNT_PREFIX not set, exiting..."
    exit 1
fi

ollama="${MOUNT_PREFIX}/usr/local/bin/ollama"

fetch_azure_instance_metadata() {
    metadata_key=$1
    curl -sf -H "Metadata:true" --noproxy "*" "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01" | jq -r '.tagsList[] | select(.name == "'"$metadata_key"'") | .value' || $HARDEN_DRACUT_PANIC
}

fetch_gcp_instance_metadata() {
    metadata_key=$1
    curl -sf -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$metadata_key" || $HARDEN_DRACUT_PANIC
}

fetch_qemu_instance_metadata() {
    metadata_key=$1
    curl -sf "http://10.0.2.2:8091/meta-data" | jq -r ".$metadata_key" || $HARDEN_DRACUT_PANIC
}

fetch_gcp_access_token() {
    curl -sf "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google" | jq -r '.access_token' || $HARDEN_DRACUT_PANIC
}

get_model_type() {
    access_token=$1
    bucket=$2
    model_id=$3

    mapfile -t objects < <(curl -sf -X GET \
        -H "Authorization: Bearer ${access_token}" \
        "https://storage.googleapis.com/storage/v1/b/${bucket}/o?prefix=${model_id}" | jq -r '.items[].name' || $HARDEN_DRACUT_PANIC "failed to fetch object list from GCS bucket")

    if [[ " ${objects[*]} " =~ \ ${model_id}/model\.zip\  ]]; then
        echo "vllm"
    elif [[ " ${objects[*]} " =~ \ ${model_id}/weights\  ]] && [[ " ${objects[*]} " =~ \ ${model_id}/Modelfile\  ]]; then
        echo "ollama"
    else
        $HARDEN_DRACUT_PANIC "unknown model type"
    fi
}

validate_zip_model_file() {
    file_name="$1"

    local files
    files=$(unzip -Z1 "$file_name" 2>&1 ||$HARDEN_DRACUT_PANIC "failed to open zip file: $files")

    grep -q '\.safetensors$' <<< "$files" || $HARDEN_DRACUT_PANIC "zip file does not contain any .safetensors files"
    grep -qx 'config.json' <<< "$files" || $HARDEN_DRACUT_PANIC "zip file does not contain config.json"
    grep -qx 'tokenizer_config.json' <<< "$files" || $HARDEN_DRACUT_PANIC "zip file does not contain tokenizer_config.json"
    grep -qE '^(tokenizer\.json|tokenizer\.model)$' <<< "$files" || $HARDEN_DRACUT_PANIC "zip file does not contain tokenizer.json"

    return 0
}

download_from_gcs_bucket() {
    access_token=$1
    bucket=$2
    object=$3
    dest_directory=$4

    obj_dir=$(dirname "${object}")
    mkdir -p "${dest_directory}/${obj_dir}" || $HARDEN_DRACUT_PANIC "failed to create object directory"

    # URL-encode the object name to handle forward slashes and other special characters
    encoded_object=$(printf '%s' "$object" | sed 's|/|%2F|g')

    curl -sf -X GET \
        -H "Authorization: Bearer ${access_token}" \
        -o "${dest_directory}/${object}" \
        "https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encoded_object}?alt=media" || $HARDEN_DRACUT_PANIC

    if [ -f "${dest_directory}/${object}" ]; then
        echo "${dest_directory}/${object}"
    else
        ${HARDEN_DRACUT_PANIC} "model weights don't exist at ${dest_directory}/${object}"
    fi
}

get_model_hash() {
    model_name=$1

    modelfile_header=$($ollama show "${model_name}" --modelfile | grep "FROM ${OLLAMA_MODELS}/blobs/sha256-" || $HARDEN_DRACUT_PANIC "Unable to show model digest")
    read -ra header_words <<< "${modelfile_header}"

    # Header should take form "FROM /path/to/models/blobs/sha256-<sha-256-hash>"
    if [ ${#header_words[@]} -eq 2 ]; then
        blob_path=${header_words[1]}
        blob_dir=$(dirname "${blob_path}")

        if [ "${blob_dir}" != "${OLLAMA_MODELS}/blobs" ]; then
            $HARDEN_DRACUT_PANIC "unexpected value for model blob path"
        fi


        # Calculate model hash and extend the PCR with the value
        read -ra MODEL_HASH_RESULT <<< "$(sha256sum "${blob_path}" || $HARDEN_DRACUT_PANIC "Unable to calculate model digest")"
        echo "${MODEL_HASH_RESULT[0]}"
    else
        $HARDEN_DRACUT_PANIC "failed to parse modelfile header"
    fi
}

create_model_from_file() {
    modelfile_path=$1
    file_path=$2
    model_name=$3

    # Replace {{.ModelLocation}} with the actual file path in the modelfile
    sed -i "s|{{\.ModelLocation}}|${file_path}|g" "${modelfile_path}" || $HARDEN_DRACUT_PANIC "failed to replace ModelLocation in modelfile"

    ${ollama} create "${model_name}" -f "${modelfile_path}" > /dev/null || $HARDEN_DRACUT_PANIC "failed to create model"

    # once we create the model, ollama will copy the model into a new file named "sha256-<sha256-hash-of-model>" and
    # create a new Modelfile pointing to the new model location

    # delete the old model weights file
    rm "${file_path}" || $HARDEN_DRACUT_PANIC "failed to delete old model weights file"

    model_hash=$(get_model_hash "${model_name}" || $HARDEN_DRACUT_PANIC "failed to get model hash")
    echo "${model_hash}"
}

ollama_start_server() {
    ${ollama} serve > /dev/null & ollama_pid=$! || $HARDEN_DRACUT_PANIC "Failed to start ollama server"
    ollama_url="http://127.0.0.1:11434"
    time_elapsed=0
    until curl --fail -s "$ollama_url" > /dev/null; do
        exit_status=$?
        if [ $time_elapsed -ge 200 ]; then
            echo "Curl failed after 200 attempts (exit status: ${exit_status})" >&2
            return 1
        fi
        sleep 0.1
        ((time_elapsed += 1))
    done
    echo "${ollama_pid}" || $HARDEN_DRACUT_PANIC "failed to echo PID of ollama server"
}

ollama_pull_model() {
    model_name=$1

    ${ollama} pull "${model_name}" > /dev/null || $HARDEN_DRACUT_PANIC "Unable to pull model"
    model_hash=$(get_model_hash "${model_name}" || $HARDEN_DRACUT_PANIC "failed to get model hash")
    echo "${model_hash}"
}

# azure helpers

azure_get_ad_token_exchange_token() {
    curl -sf -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=api://AzureADTokenExchange" | jq -r '.access_token' || $HARDEN_DRACUT_PANIC "failed to get Azure AD token exchange token"
}

azure_exchange_token_for_gcp_token() {
    azure_token=$1
    audience=$2
    sa_impersonation_url=$3

    sts_response=$(curl -s -X POST "https://sts.googleapis.com/v1/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "audience=$audience" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
        -d "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
        -d "scope=https://www.googleapis.com/auth/cloud-platform" \
        -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
        -d "subject_token=$azure_token")

    sts_token=$(echo "$sts_response" | jq -r '.access_token' || $HARDEN_DRACUT_PANIC "failed to exchange token with STS")
    if [[ "$sts_token" == "null" || -z "$sts_token" ]]; then
        $HARDEN_DRACUT_PANIC "Failed to exchange token with STS: $sts_response"
    fi

    impersonation_response=$(curl -s -X POST "$sa_impersonation_url" \
        -H "Authorization: Bearer $sts_token" \
        -H "Content-Type: application/json" \
        -d '{"scope": ["https://www.googleapis.com/auth/cloud-platform"]}')

    access_token=$(echo "$impersonation_response" | jq -r '.accessToken' || $HARDEN_DRACUT_PANIC "failed to impersonate service account")
    if [[ "$access_token" == "null" || -z "$access_token" ]]; then
        $HARDEN_DRACUT_PANIC "Failed to impersonate service account: $impersonation_response"
    fi

    echo "$access_token"
}
