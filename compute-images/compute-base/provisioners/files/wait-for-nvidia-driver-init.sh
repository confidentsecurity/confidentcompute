#!/bin/bash

echo "Listing GPUs":
lspci_output="$(lspci -d 10de: | { grep '3D' || true ; })"
echo "$lspci_output"
gpu_count="$(echo "$lspci_output" | sed '/^\s*$/d' | wc -l)"
echo "GPU Count: $gpu_count"

initialized_lines=0

echo "Waiting for GPU driver initialization..."

while [[ "$initialized_lines" -lt "$gpu_count" ]]; do
	dmesg_output="$(dmesg | { grep 'Initialized nvidia-drm' || true ; })"
	echo "dmesg output:"
	echo "$dmesg_output"
	initialized_lines="$(echo "$dmesg_output" | sed '/^\s*$/d' | wc -l)"
	echo "#Lines: $initialized_lines"
	sleep 5
done

echo "Initialized $initialized_lines out of $gpu_count GPUs, exiting."
