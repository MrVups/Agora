#!/usr/bin/env bash
# Bootstrap installer for Sub-Aggregator.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/MrVups/Agora/main/install.sh | sudo bash
#
# This script intentionally stays small: the real installation logic lives in
# panel-manager.sh so there is only one installer to maintain.

set -euo pipefail

GH_REPO="${SUB_AGG_GH_REPO:-MrVups/Agora}"
RAW_BASE="https://raw.githubusercontent.com/${GH_REPO}/main"
INSTALL_DIR="/opt/sub_aggregator"
MANAGER_PATH="${INSTALL_DIR}/panel-manager.sh"

if [ "${EUID}" -ne 0 ]; then
  echo "This installer must be run as root (use sudo)." >&2
  exit 1
fi

mkdir -p "${INSTALL_DIR}"

echo "==> Downloading installer from GitHub: ${GH_REPO}"
curl -fsSL "${RAW_BASE}/panel-manager.sh" -o "${MANAGER_PATH}.tmp"
chmod 700 "${MANAGER_PATH}.tmp"
mv "${MANAGER_PATH}.tmp" "${MANAGER_PATH}"

echo "==> Starting full installation (prebuilt GitHub binary)"
SUB_AGG_GH_REPO="${GH_REPO}" \
SUB_AGG_INSTALL_MODE="full" \
SUB_AGG_BINARY_METHOD="prebuilt" \
exec bash "${MANAGER_PATH}"
