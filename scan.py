from abc import ABC, abstractmethod
from utils import *
import socket
import sys
from ip import Ip
import time
from scapy.all import sr1, IP, TCP, UDP

class Scan(ABC):

    DEFAULT_PORTS = ["22", "80"] # default se l'utente non specifica le porte da scansionare
    PORTS_DATA = "./ports.lists.json"

    def __init__(self):
        self.ports_info = {}
        self.ip_list = []

    @abstractmethod
    def scan_port(self, ip, port):
        pass

    def get_ports(self, ports=DEFAULT_PORTS):
        data = json_data(Scan.PORTS_DATA)
        for port in ports:
            self.ports_info[int(port)] = data[port][0]["description"]

    def request_ports(self):
        stringa = input("\nPorts: ") # Richiesta di porte da scannerizzare
        if len(stringa) == 0:
            self.get_ports()
        elif stringa.lower() == "all":
            self.get_all_ports()
        else:
            result = stringa.split(",")
            self.get_ports(result)

    def get_all_ports(self):
        data = json_data(Scan.PORTS_DATA)
        for key in data.keys():
            self.ports_info[int(key)] = data[key][0]["description"]

    def run(self):
        start = time.time()
        threadpool_exec(self.append_port, self.ports_info.keys()) # richiama iterativamente append_port per ogni chiave nel dizionario
        rtt = (time.time() - start)
        print(f"\nScanning completed in {rtt:.2f} seconds")
        self.show_results()
    
    def append_port(self, port): 
        for ip in self.ip_list:
            if self.scan_port(ip, port): # se scan_port restituisce True la porta viene aggiunta alla lista di porte aperte
                ip.open_ports.append(port)
    
    # Metodo che printa le informazioni sulle porte aperte
    def show_results(self): 
        for i in range(0, len(self.ip_list)):
            print(f"\nIp: {self.ip_list[i].remote_host}")
            if self.ip_list[i].open_ports:
                self.ip_list[i].open_ports.sort()
                for port in self.ip_list[i].open_ports:
                    print(f"{str(port)} : {self.ports_info[port]}")
            else:
                print("Nessuna porta aperta!")
    
    # Metodo che richiede gli indirizzi Ip da scannerizzare
    def add_ip(self):
        stringa = get_host_ip(input("(CIDR format supported) Insert Ip or Domain: "))
        network = ipaddress.IPv4Network(stringa)
        for el in list(network.hosts()):
            self.ip_list.append(Ip(str(el))) #aggiungo ad ip_list ogni ip del network come oggetto Ip

    # Metodo che richiede le informazioni principali per lo scan
    def start(self):
        self.request_ports()
        self.add_ip()
        try:
            input("\nLo Scanner è pronto (ENTER per iniziare la scansione)\n")
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit()
        self.run()


# Classe figlia che definisce l'analisi TCP delle porte
class Tcp(Scan):

    def __init__(self):
        super().__init__()

    # Metodo che se non specificata nessuna porta, scansiona ogni porta
    def get_all_ports(self):
        data = json_data(Scan.PORTS_DATA)
        for key in data.keys():
            if(data[key][0]["tcp"]):
                self.ports_info[int(key)] = data[key][0]["description"]

    # passiamo un ip invece che un dominio per questione di sicurezza
    def scan_port(self, ip, port):
        pkt = IP(dst=ip.remote_host)/TCP(dport=port, flags='S')
        response = sr1(pkt, timeout=1, verbose=0)
        print(f"Scanning {ip.remote_host} : {port}")
        if response and response.haslayer(TCP):
            if response[TCP].flags == 'SA':  # SYN-ACK ricevuto -> porta aperta
                return True
            elif response[TCP].flags == 'RA':  # RST-ACK ricevuto -> porta chiusa
                return False
        return False
        
            
# Classe figlia che definisce l'analisi UDP delle porte          
class Udp(Scan):

    def __init__(self):
        super().__init__()
    
    def get_all_ports(self):
        data = json_data(Scan.PORTS_DATA)
        for key in data.keys():
            if(data[key][0]["udp"]):
                self.ports_info[int(key)] = data[key][0]["description"]

    def scan_port(self, ip, port):
        udp_packet = IP(dst=ip.remote_host) / UDP(dport=port)
        try:
            # Invio del pacchetto e attesa di una risposta
            response = sr1(udp_packet, timeout=1, verbose=False)
            print(f"Scanning {ip.remote_host} : {port}")
            # Analisi della risposta
            if response is None:
                # Nessuna risposta: la porta potrebbe essere aperta (UDP è connectionless)
                return True
            else:
                return False
        except Exception as e:
            print(f"Errore durante la scansione della porta {port}: {e}")
            return False



    
