#!/bin/bash

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "Installing vLLM"

apt-get update -y

snap install astral-uv --classic

export UV_PYTHON_INSTALL_DIR=/usr/vllm/python

# BEGIN INSTALL VLLM FOR GPU
uv venv --python 3.12 --seed /usr/vllm/vllm-env-gpu
# shellcheck source=/dev/null
source /usr/vllm/vllm-env-gpu/bin/activate
uv pip install 'setuptools>=77.0.3,<80'
export VLLM_VERSION=0.11.0
export CUDA_VERSION=129
uv pip install https://github.com/vllm-project/vllm/releases/download/v${VLLM_VERSION}/vllm-${VLLM_VERSION}+cu${CUDA_VERSION}-cp38-abi3-manylinux1_x86_64.whl --extra-index-url https://download.pytorch.org/whl/cu${CUDA_VERSION}
uv cache clean
deactivate
# END INSTALL VLLM FOR GPU

# BEGIN INSTALL VLLM FOR CPU
uv venv --python 3.12 --seed /usr/vllm/vllm-env-cpu
# shellcheck source=/dev/null
source /usr/vllm/vllm-env-cpu/bin/activate

# Explicitly install required versions of dependencies
uv pip install 'setuptools>=77.0.3,<80'
uv pip install 'cmake>=3.25.0'
uv pip install 'packaging>=24.2'
uv pip install 'intel-openmp==2024.2.1'

VLLM_SRC_DIR=/tmp/vllm_source
git clone https://github.com/vllm-project/vllm.git "$VLLM_SRC_DIR"
pushd "$VLLM_SRC_DIR"
git checkout "v${VLLM_VERSION}"
uv pip install -r requirements/cpu-build.txt --torch-backend cpu --extra-index-url https://download.pytorch.org/whl/cpu
uv pip install -r requirements/cpu.txt --torch-backend cpu --extra-index-url https://download.pytorch.org/whl/cpu
VLLM_TARGET_DEVICE=cpu uv pip install . --no-build-isolation
popd
rm -rf "$VLLM_SRC_DIR"
uv cache clean
deactivate
# END INSTALL VLLM FOR CPU

snap remove --purge astral-uv

mkdir -p /etc/systemd/system/

# Create GPU vLLM service
# TODO: separate this into a different file instead of inlining it
cat > /etc/systemd/system/vllm-gpu.service <<'EOF'
[Unit]
Description=VLLM Model Server (GPU)
After=nvidia-persistenced.service
# Only start if GPU is available
ConditionPathExists=/dev/nvidia0
After=network.target

[Service]
# root is fine because we enforce fine-grained permissions using SELinux
User=root
Group=root

# Default download path for models. This shouldn't be used in general but we need to
# put it under /tmp because the rest of the filesystem should not be writable.
Environment=HF_HOME=/tmp/hf_home
# Root dir for vLLM cache files. Needs to be under /tmp so that it's writable.
Environment=VLLM_CACHE_ROOT=/tmp/vllm_cache
# Enable the vLLM v1 API (only available when running on GPU)
Environment=VLLM_USE_V1=1
# Disable downloading models from the internet
Environment=HF_DATASETS_OFFLINE=1
Environment=TRANSFORMERS_OFFLINE=1
# Triton (pytorch) cache needs to be in a writeable directory
Environment=TRITON_CACHE_DIR=/tmp/.triton

ExecStartPre=/usr/bin/mkdir -p /tmp/hf_home /tmp/vllm_cache
ExecStart=/usr/vllm/vllm-env-gpu/bin/vllm serve --config /models/vllm/config.yaml

Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF

# Create CPU vLLM service
# TODO: separate this into a different file instead of inlining it
cat > /etc/systemd/system/vllm-cpu.service <<'EOF'
[Unit]
Description=VLLM Model Server (CPU)
# Only start if GPU is NOT available
ConditionPathExists=!/dev/nvidia0
After=network.target

[Service]
# root is fine because we enforce fine-grained permissions using SELinux
User=root
Group=root

# Default download path for models. This shouldn't be used in general but we need to
# put it under /tmp because the rest of the filesystem should not be writable.
Environment=HF_HOME=/tmp/hf_home
# Root dir for vLLM cache files. Needs to be under /tmp so that it's writable.
Environment=VLLM_CACHE_ROOT=/tmp/vllm_cache
Environment=VLLM_CPU_KVCACHE_SPACE=1
# Disable downloading models from the internet
Environment=HF_DATASETS_OFFLINE=1
Environment=TRANSFORMERS_OFFLINE=1
# Triton (pytorch) cache needs to be in a writeable directory
Environment=TRITON_CACHE_DIR=/tmp/.triton

ExecStartPre=/usr/bin/mkdir -p /tmp/hf_home /tmp/vllm_cache
ExecStart=/usr/vllm/vllm-env-cpu/bin/vllm serve --config /models/vllm/config.yaml

Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF

# vLLM is not a drop in replacement for ollama because it won't start up without a model and GPUs in ready state.
# Moreover / always returns 404, /health should be used instead and it returns 200 OK only when the model is correctly loaded.

systemctl daemon-reload
