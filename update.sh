#!/bin/bash
set -euo pipefail

REPO_BASE="https://raw.githubusercontent.com/capzsmodzs/capzsmodzs/main"
MENU_ARCHIVE_URL="${REPO_BASE}/menu/menu.zip"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

if [[ $EUID -ne 0 ]]; then
    echo "This updater must be run as root." >&2
    exit 1
fi

ensure_package() {
    local pkg=$1
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        apt-get update >/dev/null 2>&1
        apt-get install -y "$pkg" >/dev/null 2>&1
    fi
}

if ! command -v unzip >/dev/null 2>&1; then
    ensure_package unzip
fi

if ! command -v wget >/dev/null 2>&1; then
    ensure_package wget
fi

update_menu() {
    echo "Downloading menu package ..."
    wget -qO "${TMP_DIR}/menu.zip" "${MENU_ARCHIVE_URL}"
    unzip -q "${TMP_DIR}/menu.zip" -d "${TMP_DIR}/menu"
    install -m 755 "${TMP_DIR}/menu"/* /usr/local/sbin/
}

update_menu

echo "Menu scripts updated successfully."
if command -v menu >/dev/null 2>&1; then
    read -rp "Press [Enter] to return to menu ..." _
    menu
fi
