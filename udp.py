from utils import *
import socket

class Udp:

    PORTS_DATA = "./ports.lists.json"

    def __init__(self):
        self.open_ports = []
        self.ports_info = {}
        self.remote_host = ""
    
    def get_ports(self):
        data = json_data(Udp.PORTS_DATA)
        for key in data.keys():
            if(data[key][0]["udp"]):
                self.ports_info[int(key)] = data[key][0]["description"]

    def scan_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # specifico famiglia e tipologia TCP
        sock.settimeout(1)
        try:
            sock.sendto(b'', (self.remote_host, port))
            print(f"Scanning {self.remote_host} : {port}")
            sock.close() # Se non viene sollevata un'eccezione, la porta è probabilmente aperta
            return True
        except socket.timeout:
            sock.close()
            return False
    
    def append_port(self, port):
        if self.scan_port(port):
            self.open_ports.append(port)
    
    def show_results(self):
        print("\nOpen ports")
        for port in self.open_ports:
            print(f"{str(port)} : {self.ports_info[port]}")

    def run(self):
        threadpool_exec(self.append_port, self.ports_info.keys())
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
    scanner = Udp()
    scanner.start()

