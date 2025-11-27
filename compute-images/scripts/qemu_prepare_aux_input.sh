#!/bin/bash

set -xeuo pipefail

build_name="$1"
input_path="$2"
output_name="$3"
output_size="$4"

if [ "$input_path" = "<empty>" ]; then
  # Packer will invoke our external datasource even if the qemu is skipped. Let's skip the execution when default value of the projectid variable is used.
  echo -n "<empty>"
  exit 0
fi

TEMP_DIR=$(mktemp -d "/tmp/${build_name}.XXXXX")
output_path="${TEMP_DIR}/${output_name}"

# create input copy and convert it to qcow2
qemu-img convert -O "qcow2" "$input_path" "$output_path" >&2
# resize qcow2 image to requested size (this is an operation on metadata)
qemu-img resize -f qcow2 "$output_path" "$output_size" >&2
echo -n "$output_path"
