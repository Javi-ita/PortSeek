import ipaddress
from utils import *
import socket
from scan import Scan
from ip import Ip

class Range(Scan):

    # porte scansionate di default se l'utente non le specifica
    DEFAULT_PORTS = ["22", "80"]

    def __init__(self):
        super().__init__()

    def get_ports(self):
        data = json_data(Scan.PORTS_DATA)
        for port in self.DEFAULT_PORTS:
            self.ports_info[int(port)] = data[port][0]["description"]

    def get_ports(self, ports):
        data = json_data(Scan.PORTS_DATA)
        for port in ports:
            self.ports_info[int(port)] = data[port][0]["description"]

    def request_ports(self):
        stringa = input("\nInserire le porte che si desidera scansionare (intervallate da virgola): \n")
        if len(stringa) == 0:
            self.get_ports()
        else:
            result = stringa.split(",")
            self.get_ports(result)

    def add_ip(self):
        stringa = input("Inserire in formato CIDR il range di ip che si desidera scansionare: \n")
        network = ipaddress.IPv4Network(stringa)
        for el in list(network.hosts()):
            self.ip_list.append(Ip(str(el))) #aggiungo ad ip_list ogni ip del network come oggetto Ip

    def scan_port(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # specifico famiglia e tipologia TCP
        sock.settimeout(0.5)
        status = sock.connect_ex((ip.remote_host, port)) # restituisce 0 se stabilisce connessione --> porta aperta
        print(f"Scanning {ip.remote_host} : {port}")
        sock.close() # necessario chiudere la connessione
        return True if status == 0 else False
    
    def start(self):
        self.request_ports()
        self.add_ip()
        try:
            input("\nScanner is ready. Press ENTER to run the scanner")
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit()
        self.run()


if __name__ == "__main__":
    range = Range()
    range.start()




    
