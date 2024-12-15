from utils import *
from scan import *
from scapy.all import IP, ICMP, TCP, UDP, DNS, DNSQR, sr, sr1, Raw
import time

class Pack:

    def __init__(self):
        self.packet = None
        self.payload = ""
        self.remote_host = ""
        self.response = None

    def set_remote_host(self):
            self.remote_host = get_host_ip(input("Inserisci Ip o un Dominio: "))
        


class ICMP_Pack(Pack):

    def __init__(self):
        super().__init__()

    # Creazione del pacchetto ICMP
    def create_packet(self):
        self.packet = IP(dst=self.remote_host) / ICMP()
        
    def send_packet(self):
        # Invio del pacchetto e ricezione della risposta
        self.response = sr1(self.packet, timeout=1, verbose=False)
        start_time = time.time()
        console.print(f"Ping in corso verso [bold blue]{self.remote_host}[/bold blue]")

        # Controllo della risposta
        if self.response[ICMP].type == 0:
            console.print(f"Echo Reply ricevuta da [bold blue]{self.response.src}[/bold blue]: TTL={self.response[IP].ttl}") # TTL = Time To Live
            rtt = (time.time() - start_time)
            print(f"RTT: {rtt:.2f} s")
        elif self.response[ICMP].type == 3:
            console.print(f"Destinazione [bold blue]{self.response.src}[/bold blue] non raggiungibile.", style="red")
            if self.response[ICMP].code == 0:
                console.print(f"Network non raggiungibile", style="red")
            elif self.response[ICMP].code == 1:
                console.print(f"Host non raggiungibile", style="red")
            elif self.response[ICMP].code == 3:
                console.print(f"Porta non raggiungibile", style="red")
        elif self.response[ICMP].type == 11:
            console.print(f"Limite di tempo TTL superato...", style="red")
        else:
            console.print(f"Nessuna risposta ricevuta da [bold blue]{self.remote_host}[/bold blue]")

    # informazioni sulla risposta ricevuta
    def get_info(self):
        if self.response[ICMP].type == 0:
            console.print("\nInformazioni sul pacchetto ricevuto")
            console.print(f"Numero di sequenza: [bold blue]{self.response[ICMP].seq}[/bold blue]", style="italic")
            if Raw in self.response:
                received_payload = self.response[Raw].load
                console.print(f"Payload ricevuto: {received_payload.decode()}", style="italic")
            else:
                console.print("Payload non presente", style="italic bold #808080")
        else:
            console.print("Nessuna informazione disponibile\n", style="italic bold #808080")

    def start(self):
        self.set_remote_host()
        self.create_packet()
        self.send_packet()
        self.get_info()
        
class HTTP(Pack):

    def __init__(self):
        super().__init__()
    
    def set_payload(self, payload=None):
        if not payload:
            self.payload = f"GET / HTTP/1.1\r\nHost: {self.remote_host}\r\n\r\n"
        else:
            self.payload = payload

    # creazione di un pacchetto con protocollo TCP
    def create_packet(self):
        self.packet = IP(dst=self.remote_host) / TCP(dport=80, flags="S", seq=1000) / Raw(load=self.payload)
        self.response = sr1(self.packet, timeout=2, verbose=False)

    # mostra risultato della risposta al pacchetto
    def show_response(self):
        if self.response.haslayer(TCP) and self.response.haslayer(Raw):
            try:
                payload = self.response[Raw].load.decode('utf-8', errors='ignore')
                
                # Verifica se il payload sembra contenere un messaggio HTTP
                if "HTTP" in payload or "GET" in payload or "POST" in payload:
                    console.print(f"Pacchetto da: [bold blue]{self.response[IP].src}[/bold blue] a: [bold blue]{self.response[IP].dst}[/bold blue]")
                    lines = payload.split("\r\n")
                    print(lines[0])
                    headers = {}
                    for line in lines[1:]:
                        if ": " in line:
                            key, value = line.split(": ", 1)
                            headers[key] = value
                        elif line == "": 
                            break
                    
                    console.print("Header HTTP:", style="italic bold")
                    for key, value in headers.items():
                        console.print(f"[green]{key}[/green]: {value}")
                    
                    if "\r\n\r\n" in payload:
                        body = payload.split("\r\n\r\n", 1)[1]
                        if body.strip():
                            print(f"Corpo della richiesta/risposta HTTP:\n{body.strip()}")
            except Exception as e:
                console.print(f"Errore nel processamento del pacchetto: {e}", style="bold red")
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

    # crea un pacchetto con protocollo UDP
    def create_packet(self):
        self.packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=self.remote_host, qtype="A"))
        

    def show_response(self):
        start_time = time.time()
        self.response = sr(self.packet, timeout=2, verbose=False)
        # Controlla che la risposta contenga pacchetti validi
        if not self.response or len(self.response[0]) == 0:
            console.print("[INFO] Nessuna risposta ricevuta o errore nella comunicazione.", style="bold red")
            return None

        answered_packets = self.response[0] 
        parsed_data = [] 
        
        for sent, received in answered_packets:
            if DNS in received:
                dns_layer = received[DNS]
                record = {
                    "dominio": dns_layer.qd.qname.decode() if dns_layer.qdcount > 0 else None,
                    "tipo_richiesta": dns_layer.qd.qtype if dns_layer.qdcount > 0 else None,
                    "risposte": []
                }
                if dns_layer.ancount > 0:
                    for i in range(dns_layer.ancount):
                        answer = dns_layer.an[i]
                        record["risposte"].append({
                            "nome": answer.rrname.decode(),
                            "tipo": answer.type,
                            "dati": answer.rdata
                        })
                parsed_data.append(record)
        if parsed_data:
            for entry in parsed_data:
                console.print(f"[bold blue]Dominio[/bold blue]: {entry['dominio']}")
                console.print(f"[bold blue]Tipo Richiesta[/bold blue]: {entry['tipo_richiesta']}")
                if entry['risposte']:
                    print("Risposte:")
                    for response in entry['risposte']:
                        print(f" - Nome: {response['nome']}, Tipo: {response['tipo']}, Dati: {response['dati']}")
                else:
                    print("Nessuna risposta.")
            rtt = (time.time() - start_time)
            console.print(f"RTT: {rtt:.2f} s", style="italic bold")
        else:
            console.print("[INFO] Nessuna risposta DNS valida trovata.", style="italic bold #808080")

    def start(self):
        self.set_remote_host()
        self.create_packet()
        self.show_response()

        
        

    


    



    
    
