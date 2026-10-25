#!/usr/bin/env bash
# Usage: sudo bash bootstrap.sh https://github.com/OWNER/REPO.git COMMIT_OR_TAG
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run with sudo'; exit 1; }
REPO_URL="${1:-}"; REPO_REF="${2:-}"
[[ "$REPO_URL" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?$ ]] || { echo 'Pass a GitHub HTTPS repository URL'; exit 1; }
[[ "$REPO_REF" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || { echo 'Pass a reviewed tag or commit'; exit 1; }
apt-get update
apt-get install -y git ca-certificates
WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "$WORK_DIR"' EXIT
git clone --no-checkout -- "$REPO_URL" "$WORK_DIR/repo"
git -C "$WORK_DIR/repo" checkout --detach "$REPO_REF"
bash "$WORK_DIR/repo/install.sh"
