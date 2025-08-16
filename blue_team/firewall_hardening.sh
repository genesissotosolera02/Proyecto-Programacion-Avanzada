#!/bin/bash

echo "Iniciando configuración segura del firewall..."

# Verificar si se tiene acceso de root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Este script debe ejecutarse como root."
  exit 1
fi

# Verificar si UFW está instalado
if command -v ufw >/dev/null 2>&1; then
  echo "[*] UFW detectado. Aplicando reglas..."

  ufw default deny incoming
  ufw default allow outgoing

  ufw allow 22/tcp     # SSH
  ufw allow 80/tcp     # HTTP
  ufw allow 443/tcp    # HTTPS

  # Opcional: rate-limiting para SSH
  ufw limit 22/tcp comment 'Limitar intentos SSH'

  # Activar logging (nivel bajo)
  ufw logging on

  ufw enable
  echo "[+] Configuración de UFW aplicada correctamente."

else
  echo "[*] UFW no encontrado. Aplicando reglas con iptables..."

  # Política por defecto
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT

  # Permitir tráfico local
  iptables -A INPUT -i lo -j ACCEPT

  # Permitir tráfico establecido
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  # Permitir puertos necesarios
  iptables -A INPUT -p tcp --dport 22 -m connlimit --connlimit-above 3 --connlimit-mask 32 -j REJECT
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  iptables -A INPUT -p tcp --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT

  # Reglas defensivas básicas (anti-scan)
  iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
  iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
  iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
  iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

  # Logging de paquetes rechazados
  iptables -A INPUT -m limit --limit 3/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4

  echo "[+] Configuración con iptables aplicada correctamente."
fi

echo "[*] Reglas de firewall aplicadas."
