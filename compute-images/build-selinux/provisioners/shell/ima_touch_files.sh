#!/bin/bash

echo "ima/evm signing files"
find / -path /proc -prune -o -fstype xfs -type f -uid 0 -exec head -n 1 '{}' \; >/dev/null
