from abc import ABC, abstractmethod
from utils import *
import sys
from ip import Ip
import time
from scapy.all import sr1, IP, TCP, UDP
from rich.table import Table

class Scan(ABC):

    DEFAULT_PORTS = ["22", "80"] # default se l'utente non specifica le porte da scansionare
    PORTS_DATA = "./ports.lists.json"
    progress = 1

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
        while True:
            try:
                console.print("\nPorte:", style="italic", end="")
                stringa = input("") # Richiesta di porte da scannerizzare
                if len(stringa) == 0:
                    self.get_ports()
                    break
                elif stringa.lower() == "all":
                    self.get_all_ports()
                    break
                else:
                    result = stringa.split(",")
                    self.get_ports(result)
                    break
            except KeyError:
                console.print("Formato di porte sbagliato", style="bold red")

    def get_all_ports(self):
        data = json_data(Scan.PORTS_DATA)
        for key in data.keys():
            self.ports_info[int(key)] = data[key][0]["description"]

    def run(self):
        start = time.time()
        threadpool_exec(self.append_port, self.ports_info.keys()) # richiama iterativamente append_port per ogni chiave nel dizionario
        rtt = (time.time() - start)
        console.print(f"\nScansione completata in [bold blue]{rtt:.2f} secondi[/bold blue]") # mostra la durata della scansione
        self.show_results()
    
    def append_port(self, port):
        self.display_loading()
        for ip in self.ip_list:
            if self.scan_port(ip, port): # se scan_port restituisce True la porta viene aggiunta alla lista di porte aperte
                ip.open_ports.append(port)
    
    # crea un display che visualizza il progresso della scansione
    def display_loading(self):
        bar_max_len = 48
        bar_i_len = bar_max_len * self.progress // len(self.ports_info.keys())
        bar = "#"*bar_i_len + "-"*(bar_max_len-bar_i_len)
        bar_p = "%.1f" % (self.progress / len(self.ports_info.keys()) * 100)
        self.progress+=1
        console.print(f"|{bar}| {bar_p}%", end="\r", style="bold green")
    
    # Metodo che printa le informazioni sulle porte aperte
    def show_results(self): 
        for i in range(0, len(self.ip_list)):
            console.print(f"\nTabella delle porte aperte per l' Ip: [bold blue]{self.ip_list[i].remote_host}[/bold blue]", style="bold")
            if self.ip_list[i].open_ports:
                table = Table(box=None)
                table.add_column("Porta", style="cyan")
                table.add_column("Descrizione", style="white")
                self.ip_list[i].open_ports.sort()
                for port in self.ip_list[i].open_ports:
                    table.add_row(str(port), self.ports_info[port])
                console.print(table)
            else:
                console.print("Nessuna porta aperta!", style="bold red")
    
    # Metodo che richiede gli indirizzi Ip da scannerizzare
    def add_ip(self):
        console.print("Inserisci un Ip o un dominio: ", style="italic", end="")
        stringa = get_host_ip(input(""))
        network = ipaddress.IPv4Network(stringa)
        for el in list(network.hosts()):
            self.ip_list.append(Ip(str(el))) #aggiungo ad ip_list ogni ip del network come oggetto Ip

    # Metodo che richiede le informazioni principali per lo scan
    def start(self):
        self.request_ports()
        self.add_ip()
        try:
            console.print("\nLo Scanner è pronto (ENTER per iniziare la scansione)", style="blink italic")
            input("")
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
            response = sr1(udp_packet, timeout=0.5, verbose=False)
            #console.print(f"Scanning [bold blue]{ip.remote_host}[/bold blue] : [italic green]{port}[/italic green]")
            # Analisi della risposta
            if response is None:
                return True
            else:
                return False
        except Exception as e:
            console.print(f"Errore durante la scansione della porta {port}: {e}", style="bold red")
            return False



    
