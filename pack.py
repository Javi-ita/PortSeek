from utils import *
from scan import *
from scapy.all import IP, ICMP, TCP, UDP, DNS, DNSQR, sr1, Raw
import time

class Pack:

    def __init__(self):
        self.packet = None
        self.payload = ""
        self.remote_host = ""

    def set_remote_host(self):
        self.remote_host = get_host_ip(input("Inserisci Ip o un Dominio: "))

    
class ICMP_Pack(Pack):

    def __init__(self):
        super().__init__()
        self.response = None

    def create_packet(self):
        # Creazione del pacchetto ICMP Echo Request
        self.packet = IP(dst=self.remote_host) / ICMP()
        
    def send_packet(self):
        
        # Invio del pacchetto e ricezione della risposta
        self.response = sr1(self.packet, timeout=1, verbose=False)
        start_time = time.time()
        print(f"Ping in corso verso {self.remote_host}...")

        # Controllo della risposta
        if self.response[ICMP].type == 0:
            print(f"Echo Reply ricevuta da {self.response.src}: TTL={self.response[IP].ttl}") # TTL = Time To Live
            rtt = (time.time() - start_time)
            print(f"RTT: {rtt:.2f} s")
        elif self.response[ICMP].type == 3:
            print(f"Destinazione {self.response.src} non raggiungibile.\n")
            if self.response[ICMP].code == 0:
                print(f"Network non raggiungibile")
            elif self.response[ICMP].code == 1:
                print(f"Host non raggiungibile")
            elif self.response[ICMP].code == 3:
                print(f"Porta non raggiungibile")
        elif self.response[ICMP].type == 11:
            print(f"Limite di tempo TTL superato...")
        else:
            print(f"Nessuna risposta ricevuta da {self.remote_host}")

    def get_info(self):
        if self.response[ICMP].type == 0:
            print("\nInformazioni sul pacchetto ricevuto")
            print(f"Numero di sequenza ricevuto: {self.response[ICMP].seq}")
            if Raw in self.response:
                received_payload = self.response[Raw].load
                print(f"Payload ricevuto: {received_payload.decode()}")
            else:
                print("Payload non presente")
        else:
            print("Nessuna informazione disponibile\n")

    def start(self):
        self.set_remote_host()
        self.create_packet()
        self.send_packet()
        self.get_info()
        
class HTTP(Pack):

    def __init__(self):
        super().__init__()
        self.response = None
    
    def set_payload(self, payload=None):
        if not payload:
            self.payload = f"GET / HTTP/1.1\r\nHost: {self.remote_host}\r\n\r\n"
        else:
            self.payload = payload

    def create_packet(self):
        # Creazione del pacchetto ICMP Echo Request
        self.packet = IP(dst=self.remote_host) / TCP(dport=80, flags="S", seq=1000) / Raw(load=self.payload)
        self.response = sr1(self.packet, timeout=2, verbose=False)

    def show_response(self):
        if self.response.haslayer(TCP) and self.response.haslayer(Raw):
            try:
                payload = self.response[Raw].load.decode('utf-8', errors='ignore')
                
                # Verifica se il payload sembra contenere un messaggio HTTP
                if "HTTP" in payload or "GET" in payload or "POST" in payload:
                    print("=" * 50)
                    print(f"Pacchetto da: {self.response[IP].src} a: {self.response[IP].dst}")
                    
                    lines = payload.split("\r\n")
                    print(lines[0])
                    headers = {}
                    for line in lines[1:]:
                        if ": " in line:
                            key, value = line.split(": ", 1)
                            headers[key] = value
                        elif line == "": 
                            break
                    
                    print("Header HTTP:")
                    for key, value in headers.items():
                        print(f"{key}: {value}")
                    
                    if "\r\n\r\n" in payload:
                        body = payload.split("\r\n\r\n", 1)[1]
                        if body.strip():
                            print(f"Corpo della richiesta/risposta HTTP:\n{body.strip()}")
                    print("=" * 50)
            except Exception as e:
                print(f"Errore nel processamento del pacchetto: {e}")
        else:
            print(f"Risposta grezza ricevuta: {self.response.show(dump=True)}")

    def start(self):
        self.set_remote_host()
        self.set_payload()
        self.create_packet()
        self.show_response()

class DNS_pack(Pack):

    def __init__(self):
        super().__init__()
        self.response = None

    def create_packet(self):
        packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=self.remote_host, qtype="A"))
        self.response = sr(packet, timeout=2, verbose=False)

    def show_respone(self):
        if self.response.haslayer(DNS):
            print(f"Risultato per {self.remote_host}:")
            for i in range(self.response[DNS].ancount):
                r = self.response[DNS].an[i]
                print(f"  {r.rrname.decode()} -> {r.rdata}")
        else:
            print("Nessuna risposta dal server DNS 8.8.8.8.")

    def start(self):
        self.set_remote_host()
        self.create_packet()
        self.show_respone()

        
        

    


    



    
    
