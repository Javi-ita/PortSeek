from abc import ABC, abstractmethod
from utils import *
import socket
import sys
from ip import Ip

class Scan(ABC):

    PORTS_DATA = "./ports.lists.json"

    def __init__(self):
        self.ports_info = {}
        self.ip_list = []

    @abstractmethod
    def scan_port(self, port):
        pass

    def get_ports(self):
        data = json_data(Scan.PORTS_DATA)
        self.ports_info = {int(k) : v[0]["description"] for (k,v) in data.items()}

    def run(self):
        threadpool_exec(self.append_port, self.ports_info.keys())
        self.show_results()
    
    def append_port(self, port):
        for ip in self.ip_list:
            if self.scan_port(ip, port):
                ip.open_ports.append(port)
    
    def show_results(self):
        print("\nOpen ports")
        for i in range(0, len(self.ip_list)):
            for port in self.ip_list[i].open_ports:
                print(f"{str(port)} : {self.ports_info[port]}")
    
    def add_ip(self):
        stringa = get_host_ip(input("(CIDR format supported) Insert Ip or Domain: "))
        network = ipaddress.IPv4Network(stringa)
        for el in list(network.hosts()):
            self.ip_list.append(Ip(str(el))) #aggiungo ad ip_list ogni ip del network come oggetto Ip

    def start(self):
        self.get_ports()
        self.add_ip()
        try:
            input("\nScanner is ready. Press ENTER to run the scanner")
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit()
        self.run()


class Tcp(Scan):

    def __init__(self):
        super().__init__()

    def get_ports(self):
        data = json_data(Scan.PORTS_DATA)
        for key in data.keys():
            if(data[key][0]["tcp"]):
                self.ports_info[int(key)] = data[key][0]["description"]

    # passiamo un ip invece che un dominio per questione di sicurezza

    def scan_port(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # specifico famiglia e tipologia TCP
        sock.settimeout(1)
        status = sock.connect_ex((ip.remote_host, port)) # restituisce 0 se stabilisce connessione --> porta aperta
        print(f"Scanning {ip.remote_host} : {port}")
        sock.close() # necessario chiudere la connessione
        return True if status == 0 else False
            
class Udp(Scan):

    def __init__(self):
        super().__init__()
    
    def get_ports(self):
        data = json_data(Scan.PORTS_DATA)
        for key in data.keys():
            if(data[key][0]["udp"]):
                self.ports_info[int(key)] = data[key][0]["description"]

    def scan_port(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # specifico famiglia e tipologia UDP
        sock.settimeout(1)
        try:
            sock.sendto(b'', (ip.remote_host, port))
            print(f"Scanning {ip.remote_host} : {port}")
            sock.close() # Se non viene sollevata un'eccezione, la porta è probabilmente aperta
            return True
        except socket.timeout:
            sock.close()
            return False
        
if __name__ == "__main__":
    i = initialize()
    if i == "TCP":
        scanner = Tcp()
        scanner.start()
    elif i == "UDP":
        scanner = Udp()
        scanner.start()


    
