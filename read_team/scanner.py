import nmap 
import datetime

#Puertos generalmente abiertos en servidores
puertos_permitidos = [22, 80, 443]

#Sirve para iniciar el escaneo de los puertos
def scan_objetivo(host):
    scan = nmap.PortScanner()
    print(f"[+] Iniciando el escaneo a {host} (puertos 1-1024)")
    
    #Escaneo completos con parametros 
    scan.scan(hosts=host, ports='1-1024', arguments='-sS -sV -A -T1 -Pn')
    
    scaneo = []
    # Scaneo completo de los puertos con ip - estado y puertos
    for ip in scan.all_hosts():
        estado = scan[ip].state()
        print(f"Host: {ip} - Estado: {estado}")
        
        scaneo.append(f"Host: {ip} - Estado: {estado}")
        
        for p in scan[ip].all_protocols():
            puertos = scan[ip][p].keys()
            for port in sorted(puertos):
                servicio = scan[ip][p][port]
                linea = f"puerto: {port}\tEstado: {servicio['state']}\tServicio: {servicio['name']}"
                print(linea)
                scaneo.append(linea + "\n")
                
                if port not in puertos_permitidos:
                    alerta = f"Puerto {port} innecesario"
                    print(alerta)
                    scaneo.append(alerta + "\n")
    
    scaneo_guardar(host, scaneo)
    
"""
con esta funcion guardamos el scaneo que obtenemos 

"""
def scaneo_guardar(host, contenido):
    fecha = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    file = f"reporte_scan_{host}_{fecha}.txt"
    
    with open(file, "w") as f:
        f.writelines(contenido)
        print(f"Scaneo guardado en {file}")
        
#Ejecutador principal del script
if __name__ == "__main__":  
    objetivo = input("Ingrese la Ip o dominio: ")
    scan_objetivo(objetivo)