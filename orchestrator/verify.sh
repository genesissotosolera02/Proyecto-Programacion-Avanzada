#!/bin/bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ART_DIR="$ROOT_DIR/artifacts"
LOG_FILE="$ART_DIR/logs/security_alerts.log"

echo "[VERIFY] 1) Firewall (ufw) estado"
sudo ufw status verbose | tee "$ART_DIR/ufw_status.txt" || true

echo "[VERIFY] 2) Reglas iptables (DROP por AlertLogger)"
sudo iptables -S | tee "$ART_DIR/iptables_rules.txt" || true
if sudo iptables -S | grep -q " -j DROP" ; then
  echo "[OK] Hay reglas DROP"
else
  echo "[WARN] No se observan reglas DROP nuevas"
fi

echo "[VERIFY] 3) Logs del adapter y alertas"
if [ -f "$ART_DIR/logs/adapter.out" ]; then
  tail -n 50 "$ART_DIR/logs/adapter.out" > "$ART_DIR/adapter_tail.txt"
fi
if [ -f "$ART_DIR/logs/security_alerts.log" ]; then
  tail -n 100 "$ART_DIR/logs/security_alerts.log" > "$ART_DIR/alerts_tail.txt"
else
  echo "[WARN] Aún no hay security_alerts.log"
fi

echo "[VERIFY] 4) Auditoría del sistema (os_audit.log)"
if [ -f "$ART_DIR/os_audit.log" ]; then
  echo "[OK] Auditoría presente"
else
  echo "[WARN] os_audit.log no encontrado"
fi

echo "[VERIFY] Done"
