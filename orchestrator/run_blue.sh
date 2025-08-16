#!/bin/bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ART_DIR="$ROOT_DIR/artifacts"
mkdir -p "$ART_DIR" "$ART_DIR/logs"

echo "[BLUE] Aplicando hardening (si existe)"
if [ -f "$ROOT_DIR/firewall_hardening.sh" ]; then
  sudo bash "$ROOT_DIR/firewall_hardening.sh" | tee "$ART_DIR/hardening.out"
else
  echo "[WARN] No se encontró firewall_hardening.sh en $ROOT_DIR"
fi

echo "[BLUE] Iniciando AlertLogger como servicio de fondo"
# Ejecuta AlertLogger y deja un socket simple de comunicación via adapter
nohup python3 "$ROOT_DIR/orchestrator/event_adapter.py" > "$ART_DIR/logs/adapter.out" 2>&1 &
echo $! > "$ART_DIR/adapter.pid"

echo "[BLUE] Ejecutando auditoría del sistema"
if [ -f "$ROOT_DIR/os_audit.py" ]; then
  python3 "$ROOT_DIR/os_audit.py" || true
  # Mover log generado por os_audit.py si existe
  if [ -f "$ROOT_DIR/os_audit.log" ]; then
    mv "$ROOT_DIR/os_audit.log" "$ART_DIR/os_audit.log"
  fi
else
  echo "[WARN] os_audit.py no encontrado"
fi

echo "[BLUE] Listo"
