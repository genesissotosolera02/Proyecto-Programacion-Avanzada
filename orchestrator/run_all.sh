#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ART_DIR="$ROOT_DIR/artifacts"
mkdir -p "$ART_DIR"

echo "[*] 1/4 Activando Blue Team"
bash "$ROOT_DIR/orchestrator/run_blue.sh"

echo "[*] 2/4 Lanzando Red Team"
bash "$ROOT_DIR/orchestrator/run_red.sh"

echo "[*] 3/4 Recolectando artefactos"
bash "$ROOT_DIR/orchestrator/collect_artifacts.sh"

echo "[*] 4/4 Verificando resultados"
bash "$ROOT_DIR/orchestrator/verify.sh"

echo "[+] Listo. Evidencias en $ART_DIR"
