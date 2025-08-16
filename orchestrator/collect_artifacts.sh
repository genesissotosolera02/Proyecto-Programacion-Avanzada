#!/bin/bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ART_DIR="$ROOT_DIR/artifacts"
DATE_DIR="$ART_DIR/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$DATE_DIR"

# Mover todo lo relevante que esté en artifacts raíz
shopt -s nullglob
mv "$ART_DIR"/*.txt "$DATE_DIR"/ 2>/dev/null || true
mv "$ART_DIR"/*.log "$DATE_DIR"/ 2>/dev/null || true
cp -r "$ART_DIR/logs" "$DATE_DIR"/ 2>/dev/null || true

echo "[*] Artefactos agrupados en $DATE_DIR"
