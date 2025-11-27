#!/bin/bash
set -xeuo pipefail
systemctl stop unattended-upgrades
systemctl disable unattended-upgrades
systemctl mask unattended-upgrades
