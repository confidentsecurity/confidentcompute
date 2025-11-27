#!/bin/bash
set -eux

fetch_gcp_instance_name() {
	curl -sf -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/name" || echo ""
}

fetch_gcp_instance_metadata() {
	curl -sf -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1" || echo ""
}

fetch_gcp_instance_ip() {
	curl -sf -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip" || echo ""
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
	value="$(fetch_gcp_instance_metadata "$key")"
	expose_var "$key" "$value" "$ENV_FILE"
done

value="$(fetch_gcp_instance_name)"
expose_var "INSTANCE_NAME" "$value" "$ENV_FILE"

value="$(fetch_gcp_instance_ip)"
expose_var "INSTANCE_IP" "$value" "$ENV_FILE"

expose_var "TPM_TYPE" "GCE" "$ENV_FILE"

expose_var "CLOUD" "gcp" "$ENV_FILE"

xargs -d '\n' -r systemctl set-environment <"$ENV_FILE"
systemctl daemon-reexec
# The above commands will update the global env, but we still need to restart ollama to pick up the new env.
systemctl restart ollama
