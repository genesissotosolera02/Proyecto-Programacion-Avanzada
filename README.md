# Proyecto Final – Laboratorio Red Team vs Blue Team

## Propósito
Este proyecto implementa un **laboratorio práctico de ciberseguridad** en un entorno controlado, simulando ataques y defensas entre dos roles:  
- **Red Team**: responsables de ejecutar ataques y pruebas de intrusión.  
- **Blue Team**: responsables de proteger, monitorear y responder a incidentes.  

El objetivo es **evaluar técnicas ofensivas y defensivas**, recolectar evidencias y analizar la eficacia de las medidas de seguridad aplicadas.

---

## Roles y Herramientas

### Red Team (Ofensiva)
- **scanner.py** → Escaneo de puertos y servicios con Nmap.  
- **packet_attack.py** → Ataques de red (SYN Flood, ARP spoofing, DNS spoofing, HTTP sniffing).  
- **ssh_brute.py** → Ataque de fuerza bruta sobre SSH usando diccionario.  

### Blue Team (Defensiva)
- **firewall_hardening.sh** → Configuración de reglas de firewall (UFW/Iptables).  
- **sniffer_defense.py** → Sniffer para detectar escaneos y pings sospechosos.  
- **alert_logger.py** → Sistema de logging y respuesta automática (bloqueo de IPs maliciosas).  
- **os_audit.py** → Auditoría del sistema (usuarios, servicios, puertos y archivos críticos).  

### Orquestación
- **orchestrator/run_all.sh** → Ejecuta el flujo completo (Blue → Red → Recolección → Verificación).  
- **orchestrator/event_adapter.py** → Conecta la salida de `sniffer_defense.py` con `alert_logger.py` para activar respuestas automáticas.  

---

## Requisitos

- **Python 3.8+**  
- Librerías Python:  
  - `scapy`  
  - `paramiko`  
- **Herramientas de red**:  
  - `nmap`  
  - `tcpdump` (opcional, para análisis de paquetes)  
- **Firewall**:  
  - `ufw` y `iptables` habilitados en la VM Blue  
- **Azure CLI** (si se despliega en Azure)  

---

## Instrucciones de Ejecución

### 1. Preparar entorno
- Crear dos VMs en Azure (Ubuntu LTS recomendado):
  - **VM Blue**: Defensiva, con firewall y scripts de protección.  
  - **VM Red**: Ofensiva, con Nmap y scripts de ataque.  
- Configurar variables en `orchestrator/run_red.sh`:
  ```bash
  TARGET_IP=IP_DE_TU_VM_BLUE
  SSH_USER=usuario_prueba
  WORDLIST=rockyou.txt
  ```

### 2. Ejecución manual (opcional)
Ejecutar scripts individuales:

#### Blue Team
```bash
sudo bash firewall_hardening.sh
python3 sniffer_defense.py
python3 alert_logger.py
python3 os_audit.py
```

#### Red Team
```bash
python3 scanner.py <IP_BLUE>
python3 packet_attack.py
python3 ssh_brute.py
```

### 3. Ejecución automática (recomendado)
Ejecutar todo el flujo con el orquestador:
```bash
bash orchestrator/run_all.sh
```

---

## Criterios de Éxito

### Éxito del Red Team
- **scanner.py** → Detecta puertos y servicios en VM Blue.  
- **packet_attack.py** → Envía paquetes falsos o maliciosos, generando alertas.  
- **ssh_brute.py** → Registra intentos de acceso fallidos en los logs de VM Blue.  

### Éxito del Blue Team
- **firewall_hardening.sh** → Solo puertos necesarios abiertos, políticas restrictivas activas.  
- **sniffer_defense.py** → Detecta escaneos y ataques, imprime alertas.  
- **alert_logger.py** → Registra incidentes y **bloquea IPs atacantes** en iptables.  
- **os_audit.py** → Genera un reporte en `os_audit.log` con información del sistema.  

### Éxito de la Orquestación
- Todos los artefactos se recopilan en la carpeta `artifacts/` (logs, reportes, capturas).  
- `verify.sh` confirma la existencia de reglas de firewall, logs de alertas y auditoría del sistema.  

---

## Estructura del Proyecto
```
proyecto_final/
├── red_team/
│   ├── scanner.py
│   ├── packet_attack.py
│   └── ssh_brute.py
├── blue_team/
│   ├── firewall_hardening.sh
│   ├── sniffer_defense.py
│   ├── alert_logger.py
│   └── os_audit.py
├── orchestrator/
│   ├── run_all.sh
│   ├── run_blue.sh
│   ├── run_red.sh
│   ├── collect_artifacts.sh
│   ├── verify.sh
│   └── event_adapter.py
└── artifacts/
    └── (logs, reportes y capturas)
```

---

## Evaluación y Evidencias
- Logs de **AlertLogger** mostrando detección y bloqueo de IPs maliciosas.  
- Reporte `os_audit.log` con auditoría completa del sistema.  
- Resultados de escaneo (`reporte_scan_xxx.txt`) y ataques en `artifacts/`.  
- Reglas de firewall en `ufw status` y `iptables -S`.  
- Capturas de pantalla de ejecución (para la presentación).  

---