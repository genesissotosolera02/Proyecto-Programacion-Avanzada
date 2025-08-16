#alert_logger

import logging
import json
import os
import subprocess
import time
from datetime import datetime
from collections import defaultdict
import threading
import queue
import smtplib
from email.mime.text import MIMEText

class AlertLogger:
    """Recibe eventos de otros módulos como os_audit y sniffer_defense y toma acciones automáticas"""
    
    def __init__(self):
        # Configuración básica
        self.log_file = "logs/security_alerts.log"
        self.blocked_ips_file = "logs/blocked_ips.txt"
        self.blocked_ips = set()
        self.attempt_counter = defaultdict(int)  # IP -> número de intentos
        
        # Umbrales de bloqueo (cuántos eventos antes de bloquear)
        self.thresholds = {
            "LOW": 10,      # 10 eventos LOW = bloquear
            "MEDIUM": 5,    # 5 eventos MEDIUM = bloquear
            "HIGH": 3,      # 3 eventos HIGH = bloquear
            "CRITICAL": 1   # 1 evento CRITICAL = bloquear inmediato
        }
        
        # Cola para procesar eventos
        self.event_queue = queue.Queue()
        self.running = False
        
        # Configurar logging
        self._setup_logging()
        
        # Cargar IPs previamente bloqueadas
        self._load_blocked_ips()
            
    def _setup_logging(self):
        """Configurar sistema de logs"""
        # Crear directorio de logs
        os.makedirs("logs", exist_ok=True)
        
        # Configurar logger
        self.logger = logging.getLogger('AlertLogger')
        self.logger.setLevel(logging.INFO)
        
        # Handler para archivo
        handler = logging.FileHandler(self.log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def _load_blocked_ips(self):
        """Cargar IPs ya bloqueadas"""
        try:
            if os.path.exists(self.blocked_ips_file):
                with open(self.blocked_ips_file, 'r') as f:
                    self.blocked_ips = set(line.strip() for line in f if line.strip())
                print(f"Cargadas {len(self.blocked_ips)} IPs bloqueadas")
        except Exception as e:
            print(f"Error cargando IPs: {e}")
    
    def _save_blocked_ips(self):
        """Guardar IPs bloqueadas en archivo"""
        try:
            with open(self.blocked_ips_file, 'w') as f:
                for ip in self.blocked_ips:
                    f.write(f"{ip}\n")
        except Exception as e:
            print(f"Error guardando IPs: {e}")
    
    def start(self):
        """Iniciar procesador de eventos"""
        self.running = True
        # Iniciar hilo para procesar eventos
        self.processor_thread = threading.Thread(target=self._process_events)
        self.processor_thread.daemon = True
        self.processor_thread.start()
    
    def stop(self):
        """Detener procesador"""
        self.running = False
        print("AlertLogger detenido")
    
    
    def log_event_simple(self, event_type: str, source_ip: str, target_port: int = 0,
                        severity: str = "MEDIUM", description: str = "",
                        source_module: str = "manual"):
        """os_audit y sniffer_deffense reportan eventos aquí"""
        # Crear evento
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "source_ip": source_ip,
            "target_port": target_port,
            "severity": severity,
            "description": description,
            "source_module": source_module
        }
        
        # Agregar a cola para procesamiento
        self.event_queue.put(event)
        
        # Mostrar eventos importantes inmediatamente
        if severity in ["HIGH", "CRITICAL"]:
            print(f"[{severity}] {description}")
    
    
    def _process_events(self):
        """Procesar eventos de la cola """
        while self.running:
            try:
                # Obtener evento de la cola
                event = self.event_queue.get(timeout=1)
                
                # Registrar en logs
                self._log_event(event)
                
                # Evaluar si bloquear IP
                self._evaluate_blocking(event)
                
                # Enviar notificación si es crítico
                if event["severity"] == "CRITICAL":
                    self._send_notification(event)
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error procesando evento: {e}")
    
    def _log_event(self, event):
        """Registrar evento en archivo de log"""
        # Escribir al archivo de log
        self.logger.info(f"SECURITY_EVENT: {json.dumps(event)}")
        
        # Mostrar en consola eventos importantes
        if event["severity"] in ["MEDIUM", "HIGH", "CRITICAL"]:
            print(f"{event['event_type']} desde {event['source_ip']}")
    
    def _evaluate_blocking(self, event):
        """Evaluar si se debe bloquear una IP"""
        source_ip = event["source_ip"]
        severity = event["severity"]
        
        # No bloquear IPs locales
        if source_ip.startswith(("127.", "192.168.", "10.", "172.")):
            return
        
        # No bloquear si ya está bloqueada
        if source_ip in self.blocked_ips:
            return
        
        # Incrementar contador de intentos
        self.attempt_counter[source_ip] += 1
        
        # Obtener escala según severidad
        threshold = self.thresholds.get(severity, 5)
        
        # Se decide si bloquear
        if self.attempt_counter[source_ip] >= threshold:
            self._block_ip(source_ip, f"{event['event_type']}_{severity}")
            self.attempt_counter[source_ip] = 0  # Reset contador
    
    def _block_ip(self, ip: str, reason: str):
        """Bloquear IP usando iptables"""
        try:
            print(f"Bloqueando IP: {ip}")
            
            # Ejecutar comando iptables
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Agregar a lista de bloqueadas
                self.blocked_ips.add(ip)
                self._save_blocked_ips()
                
                # Logs y notificación
                self.logger.warning(f"IP {ip} BLOQUEADA debido a: {reason}")
                print(f"IP {ip} bloqueada")
                
                # Enviar notificación de bloqueo
                self._send_block_notification(ip, reason)
                
            else:
                print(f"Error bloqueando IP {ip}: {result.stderr}")
                
        except Exception as e:
            print(f"Error ejecutando iptables: {e}")
    
    def _send_notification(self, event):
        """Enviar notificación por consola"""
        print("=" * 50)
        print("ALERTA CRÍTICA DE SEGURIDAD")
        print(f"Tipo: {event['event_type']}")
        print(f"IP: {event['source_ip']}")
        print(f"Descripción: {event['description']}")
        print(f"Timestamp: {event['timestamp']}")
        print("=" * 50)
        
    
    def _send_block_notification(self, ip: str, reason: str):
        """Notificación específica para bloqueos"""
        print("IP BLOQUEADA")
        print(f"   IP: {ip}")
        print(f"   Razón: {reason}")
        print(f"   Total IPs bloqueadas: {len(self.blocked_ips)}")
    
    
    def get_blocked_ips(self):
        """Obtener lista de IPs bloqueadas"""
        return list(self.blocked_ips)
    
    def manual_block_ip(self, ip: str, reason: str = "MANUAL"):
        """Bloquear IP manualmente"""
        self._block_ip(ip, reason)
    
    def unblock_ip(self, ip: str):
        """Desbloquear IP manualmente"""
        try:
            cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.blocked_ips.discard(ip)
                self._save_blocked_ips()
                print(f"IP {ip} desbloqueada")
            else:
                print(f"Error desbloqueando {ip}")
                
        except Exception as e:
            print(f"Error: {e}")
    
    def generate_report(self):
        """Generar reporte de actividad"""
        try:
            print("\nREPORTE DE SEGURIDAD")
            print("=" * 30)
            
            # Contar eventos de hoy
            today = datetime.now().strftime('%Y-%m-%d')
            event_count = 0
            
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    for line in f:
                        if today in line and 'SECURITY_EVENT' in line:
                            event_count += 1
            
            print(f"Eventos de hoy: {event_count}")
            print(f"IPs bloqueadas: {len(self.blocked_ips)}")
            
            if self.blocked_ips:
                print("\nIPs bloqueadas:")
                for ip in sorted(self.blocked_ips):
                    print(f"  • {ip}")
                        
        except Exception as e:
            print(f"Error generando reporte: {e}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='AlertLogger - Sistema de Alertas')
    parser.add_argument('--test', action='store_true', help='Ejecutar pruebas')
    parser.add_argument('--report', action='store_true', help='Generar reporte')
    parser.add_argument('--unblock', type=str, help='Desbloquear IP específica')
    
    args = parser.parse_args()
    
    logger = AlertLogger()
    
    if args.test:
        # Ejecutar pruebas
        logger.start()
        
        print("Ejecutando pruebas...")
        
        # Simular eventos
        logger.log_event_simple("PORT_SCAN", "192.168.1.100", 22, "HIGH", "Test: Escaneo SSH")
        logger.log_event_simple("PORT_SCAN", "192.168.1.100", 80, "HIGH", "Test: Escaneo HTTP")
        logger.log_event_simple("BRUTE_FORCE", "10.0.0.50", 22, "CRITICAL", "Test: Fuerza bruta")
        
        time.sleep(2)
        logger.stop()
        
        print("Pruebas completadas")
        
    elif args.report:
        logger.generate_report()
        
    elif args.unblock:
        logger.unblock_ip(args.unblock)
        
    else:
        # Ejecutar como servicio
        logger.start()
        
        try:
            print("AlertLogger funcionando. Presiona Ctrl+C para detener")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.stop()
            print("AlertLogger detenido")