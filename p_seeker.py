import socket
from utils import *
import sys

class PScanner:

    PORTS_DATA = "./ports.lists.json"

    def __init__(self):
        self.open_ports = []
        self.ports_info = {}
        self.remote_host = ""
    

    def get_ports(self):
        data = json_data(PScanner.PORTS_DATA)
        for key in data.keys():
            if(data[key][0]["tcp"]):
                self.ports_info[int(key)] = data[key][0]["description"]


    # passiamo un ip invece che un dominio per questione di sicurezza

    def scan_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # specifico famiglia e tipologia TCP
        sock.settimeout(1)
        status = sock.connect_ex((self.remote_host, port)) # restituisce 0 se stabilisce connessione --> porta aperta
        print(f"Scanning {self.remote_host} : {port}")
        if status == 0:
            self.open_ports.append(port)
        sock.close() # necessario chiudere la connessione


    
    def show_results(self):
        print("\nOpen ports")
        for port in self.open_ports:
            print(f"{str(port)} : {self.ports_info[port]}")
        
    def run(self):
        threadpool_exec(self.scan_port, self.ports_info.keys())
        self.show_results()
    
    def start(self):
        print("\n------------  PORT SEEKER  ------------\n")
        self.get_ports()
        self.remote_host = ask_domain()
        try:
            input("\nScanner is ready. Press ENTER to run the scanner")
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit()
        self.run()
        

if __name__ == "__main__":
    scanner = PScanner()
    scanner.start()




