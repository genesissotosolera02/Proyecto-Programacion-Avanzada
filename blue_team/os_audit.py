# os_audit.py
import os
import subprocess
import platform
import logging
 
try:
    from alert_logger import AlertLogger
    alert_logger = AlertLogger()
    alert_logger.start()
except:
    alert_logger = None
 
logging.basicConfig(filename='os_audit.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
 
def run_command(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, universal_newlines=True)
        return output.strip()
    except subprocess.CalledProcessError:
        return "[ERROR] No se pudo ejecutar el comando."
 
def list_users_and_groups():
    logging.info("=== Usuarios y Grupos ===")
    logging.info(run_command("cat /etc/passwd"))
    logging.info(run_command("cat /etc/group"))
   
    if alert_logger: alert_logger.log_event_simple("OS_AUDIT_USERS", "127.0.0.1", 0, "LOW", "Auditoría de usuarios completada", "os_audit")
 
def recent_logins():
    logging.info("=== Accesos recientes ===")
    logging.info(run_command("last -a | head -n 10"))
   
    if alert_logger: alert_logger.log_event_simple("OS_AUDIT_LOGINS", "127.0.0.1", 0, "LOW", "Auditoría de logins completada", "os_audit")
 
def open_ports():
    logging.info("=== Puertos abiertos (netstat/ss) ===")
    if os.path.exists("/bin/ss") or os.path.exists("/usr/bin/ss"):
        logging.info(run_command("ss -tuln"))
    else:
        logging.info(run_command("netstat -tuln"))
   
    if alert_logger: alert_logger.log_event_simple("OS_AUDIT_PORTS", "127.0.0.1", 0, "LOW", "Auditoría de puertos completada", "os_audit")
 
def running_services():
    logging.info("=== Servicios en ejecución ===")
    if os.path.exists("/bin/systemctl") or os.path.exists("/usr/bin/systemctl"):
        logging.info(run_command("systemctl list-units --type=service --state=running"))
    else:
        logging.info(run_command("ps aux"))
   
    if alert_logger: alert_logger.log_event_simple("OS_AUDIT_SERVICES", "127.0.0.1", 0, "LOW", "Auditoría de servicios completada", "os_audit")
 
def check_config_files():
    logging.info("=== Archivos de configuración clave ===")
    archivos = {
        "SSH Config": "/etc/ssh/sshd_config",
        "Sudoers": "/etc/sudoers",
        "Crontab": "/etc/crontab"
    }
    for nombre, ruta in archivos.items():
        logging.info(f"--- {nombre} ({ruta}) ---")
        if os.path.exists(ruta):
            with open(ruta, 'r') as file:
                contenido = file.read()
                logging.info(contenido)
        else:
            logging.warning(f"[!] Archivo no encontrado: {ruta}")
   
    if alert_logger: alert_logger.log_event_simple("OS_AUDIT_CONFIG", "127.0.0.1", 0, "LOW", "Auditoría de configuración completada", "os_audit")
 
def system_info():
    logging.info("=== Información del sistema ===")
    logging.info(f"Sistema operativo: {platform.system()} {platform.release()}")
    logging.info(f"Distribución: {' '.join(platform.linux_distribution()) if hasattr(platform, 'linux_distribution') else run_command('lsb_release -a')}")
    logging.info(f"Arquitectura: {platform.machine()}")
 
def main():
    print("[*] Iniciando auditoría básica del sistema...")
    system_info()
    list_users_and_groups()
    recent_logins()
    open_ports()
    running_services()
    check_config_files()
    print("[*] Auditoría completada. Resultados en os_audit.log")
   
    if alert_logger: alert_logger.log_event_simple("OS_AUDIT_COMPLETED", "127.0.0.1", 0, "LOW", "Auditoría del sistema completada", "os_audit")
 
if __name__ == "__main__":
    try:
        main()
    finally:
         
        if alert_logger: alert_logger.stop()