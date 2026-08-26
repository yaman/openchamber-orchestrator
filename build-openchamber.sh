#!/bin/sh
# Rebuild the per-user openchamber image on the VM with the local patch
# applied. The patch fixes first-load model availability (fresh browser:
# initializeApp bails when no project directory is resolvable, so providers
# never load until a reload). Run manually on the VM:
#   sudo /opt/brain-worq/build-openchamber.sh
set -eu

SRC=/opt/openchamber-src/src
PATCH=/opt/brain-worq/patches/openchamber-fix.patch
TAG=openchamber:1.20.0

if [ ! -d "$SRC/.git" ]; then
  echo "source checkout missing at $SRC" >&2
  exit 1
fi

cd "$SRC"
git checkout -- .
git apply "$PATCH"
docker build -t "$TAG" .
echo "built $TAG with patch applied"
