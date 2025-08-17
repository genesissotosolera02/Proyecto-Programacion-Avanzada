# sniffer_defense.py
 
from scapy.all import sniff, IP, TCP, ICMP
 
try:
    from alert_logger import AlertLogger
    alert_logger = AlertLogger()
    alert_logger.start()
except:
    alert_logger = None
 
# Puertos comunes en escaneos
PUERTOS_CRITICOS = {21, 22, 23, 25, 80, 443, 3306, 3389, 8080}
 
def analizar_paquete(pkt):
    if IP in pkt:
        ip_origen = pkt[IP].src
 
        # Detectar el ping
        if ICMP in pkt:
            print(f"[!] Ping detectado desde {ip_origen}")
           
            if alert_logger: alert_logger.log_event_simple("PING_DETECTION", ip_origen, 0, "LOW", f"Ping desde {ip_origen}", "sniffer_defense")
 
        # Detectar escaneo de los puertos críticos
        if TCP in pkt and pkt[TCP].dport in PUERTOS_CRITICOS:
            print(f"[!] Escaneo hacia puerto {pkt[TCP].dport} desde {ip_origen}")
           
            if alert_logger: alert_logger.log_event_simple("PORT_SCAN", ip_origen, pkt[TCP].dport, "HIGH", f"Escaneo puerto {pkt[TCP].dport}", "sniffer_defense")
 
def main():
    print("Sniffer básico de defensa activo. Ctrl+C para salir.")
   
    try:
        sniff(prn=analizar_paquete, store=0)
    except KeyboardInterrupt:
        print("\nSniffer detenido")
        if alert_logger: alert_logger.stop()
 
if __name__ == "__main__":
    main()