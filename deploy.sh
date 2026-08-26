#!/bin/sh
# Deploy the stack on the VM: pull latest repo, build the orchestrator image
# (openchamber image is pre-built on the host), recreate changed services.
# Run by the deploy.timer systemd unit; safe to run manually.
set -eu

cd /opt/brain-worq

git fetch origin main
git reset --hard origin/main

docker compose build orchestrator
docker compose up -d --remove-orphans
