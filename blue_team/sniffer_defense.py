from scapy.all import sniff, IP, TCP, ICMP

# Puertos comunes en escaneos
PUERTOS_CRITICOS = {21, 22, 23, 25, 80, 443, 3306, 3389, 8080}

def analizar_paquete(pkt):
    if IP in pkt:
        ip_origen = pkt[IP].src

        # Detectar el ping
        if ICMP in pkt:
            print(f"[!] Ping detectado desde {ip_origen}")

        # Detectar escaneo de los puertos crticos
        if TCP in pkt and pkt[TCP].dport in PUERTOS_CRITICOS:
            print(f"[!] Escaneo hacia puerto {pkt[TCP].dport} desde {ip_origen}")

def main():
    print("Sniffer básico de defensa activo. Ctrl+C para salir.")
    sniff(prn=analizar_paquete, store=0)

if __name__ == "__main__":
    main()
