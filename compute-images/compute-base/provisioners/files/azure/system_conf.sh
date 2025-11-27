#!/bin/bash
set -eux

fetch_azure_instance_name() {
	curl -sf -H "Metadata:true" --noproxy "*" "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01" | jq .name
}

fetch_azure_instance_metadata() {
	curl -sf -H "Metadata:true" --noproxy "*" "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01" | jq '.tagsList[] | select(.name == "'"$1"'") | .value'
}

fetch_azure_instance_ip() {
	curl -sf -H "Metadata:true" --noproxy "*" "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01" | jq '.interface[0].ipv4.ipAddress[0].privateIpAddress'
}

fetch_azure_instance_userdata() {
	curl -sf -H "Metadata:true" --noproxy "*" "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-02-01&format=text" | jq -R .
}

# The Azure metadata API returns values with double quotes, so we can just echo the values as is.
expose_var() {
	echo "$1=$2"
	echo "$1=$2" >>"$3"
}

ENV_FILE="/run/environment.d/system.conf"
mkdir -p "$(dirname "$ENV_FILE")"
touch "$ENV_FILE"
true >"$ENV_FILE"

KEYS="TEMPO_URL LOKI_URL ROUTER_URL NODE_TYPE STACK_NAME OLLAMA_NUM_PARALLEL OLLAMA_MAX_LOADED_MODELS OLLAMA_KEEP_ALIVE OLLAMA_KV_CACHE_TYPE GIT_SHA GITHUB_RUN_ID BADGE_PUBLIC_KEY INSTALL_NVIDIA MODEL_NAME MODEL_ID MODELS_BUCKET WORKLOAD_AUDIENCE SERVICE_ACCOUNT_IMPERSONATION_URL INFERENCE_ENGINE INFERENCE_ENGINE_SERVICE_NAME INFERENCE_ENGINE_PORT"

for key in $KEYS; do
	value="$(fetch_azure_instance_metadata "$key")"
	expose_var "$key" "$value" "$ENV_FILE"
done

value="$(fetch_azure_instance_name)"
expose_var "INSTANCE_NAME" "$value" "$ENV_FILE"

value="$(fetch_azure_instance_ip)"
expose_var "INSTANCE_IP" "$value" "$ENV_FILE"

value="$(fetch_azure_instance_userdata)"
expose_var "COMPUTE_IMAGE_SIGSTORE_BUNDLE" "$value" "$ENV_FILE"

expose_var "TPM_TYPE" "Azure" "$ENV_FILE"

expose_var "CLOUD" "azure" "$ENV_FILE"

xargs -d '\n' -r systemctl set-environment <"$ENV_FILE"
systemctl daemon-reexec
# The above commands will update the global env, but we still need to restart ollama to pick up the new env.
systemctl restart ollama
