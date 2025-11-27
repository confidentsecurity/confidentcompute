#!/bin/bash
set -eux

fetch_qemu_instance_metadata() {
	metadata_key=$1
	curl -sf "http://10.0.2.2:8091/meta-data" | jq -r ".$metadata_key"
}

fetch_qemu_instance_name() {
	fetch_qemu_instance_metadata "INSTANCE_ID"
}

fetch_qemu_instance_ip() {
	fetch_qemu_instance_metadata "INSTANCE_IP"
}

expose_var() {
	echo "$1=$(printf '%q' "$2")"
	echo "$1=$(printf '%q' "$2")" >>"$3"
}

ENV_FILE="/run/environment.d/system.conf"
mkdir -p "$(dirname "$ENV_FILE")"
touch "$ENV_FILE"
true >"$ENV_FILE"

KEYS="TEMPO_URL LOKI_URL ROUTER_URL NODE_TYPE STACK_NAME OLLAMA_NUM_PARALLEL OLLAMA_MAX_LOADED_MODELS OLLAMA_KEEP_ALIVE OLLAMA_KV_CACHE_TYPE GIT_SHA GITHUB_RUN_ID COMPUTE_IMAGE_SIGSTORE_BUNDLE BADGE_PUBLIC_KEY INSTALL_NVIDIA MODEL_NAME MODEL_ID MODELS_BUCKET INFERENCE_ENGINE INFERENCE_ENGINE_SERVICE_NAME INFERENCE_ENGINE_PORT"

for key in $KEYS; do
	value="$(fetch_qemu_instance_metadata "$key")"
	expose_var "$key" "$value" "$ENV_FILE"
done

value="$(fetch_qemu_instance_name)"
expose_var "INSTANCE_NAME" "$value" "$ENV_FILE"

value="$(fetch_qemu_instance_ip)"
expose_var "INSTANCE_IP" "$value" "$ENV_FILE"

expose_var "TPM_TYPE" "QEMU" "$ENV_FILE"

expose_var "CLOUD" "qemu" "$ENV_FILE"

xargs -d '\n' -r systemctl set-environment <"$ENV_FILE"
systemctl daemon-reexec
# The above commands will update the global env, but we still need to restart ollama to pick up the new env.
systemctl restart ollama
