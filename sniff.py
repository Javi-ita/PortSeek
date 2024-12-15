from scapy.all import IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, DNSRR, sniff
from utils import *

#metodo che processa il pacchetto ricevuto dal local host in base al protocollo 
def process_packet(packet):
    if packet.haslayer(IP):
        console.print(f"\nPacchetto ricevuto da [bold blue]{packet[IP].src}[/bold blue] a [bold blue]{packet[IP].dst}[/bold blue]")
        
        if packet.haslayer(TCP):
            console.print("Protocollo: [bold cyan]TCP[/bold cyan]")
            console.print(f"Porta Sorgente: [bold blue]{packet[TCP].sport}[/bold blue], Porta Destinazione: [bold blue]{packet[TCP].dport}[/bold blue]")
            print(f"Flags TCP: {packet[TCP].flags}")
            if packet.haslayer(Raw):
                console.print(f"Payload: {packet[Raw].load.hex()}", style="italic")
        
        elif packet.haslayer(UDP):
            console.print("Protocollo: [bold cyan]UDP[/bold cyan]")
            console.print(f"Porta Sorgente: [bold blue]{packet[UDP].sport}[/bold blue], Porta Destinazione: [bold blue]{packet[UDP].dport}[/bold blue]")
            if packet.haslayer(DNS):
                console.print("Richiesta DNS rilevata", style="green italic")
                if packet[DNS].qr == 0:  
                    console.print(f"Query DNS per: {packet[DNSQR].qname.hex()}", style="italic")
                elif packet[DNS].qr == 1:  
                    console.print(f"Risposta DNS: {packet[DNSRR].rdata}", style="italic")
        elif packet.haslayer(ICMP):
            console.print("Protocollo: [bold cyan]ICMP[/bold cyan]")
            console.print(f"Tipo: [bold blue]{packet[ICMP].type}[/bold blue], Codice: [bold blue]{packet[ICMP].code}[/bold blue]")
        
        else:
            console.print("Protocollo sconosciuto o non gestito.", style="bold red")
    else:
        console.print("Pacchetto non ricevuto.", style="bold red")

# metodo che richiede all'utente il numero, la durata e il filtro dello sniff
def define_sniff():
    console.print("\nInserire impostazioni dello sniff in formato ('count' 'timeout' 'filter'): ", style="italic", end="")
    stringa = input("")
    if len(stringa) == 0:
        return None
    while(True):
        try:
            ls = stringa.split(maxsplit=2)
            ls[0] = int(ls[0])
            ls[1] = int(ls[1])
            return ls
        except Exception:
            console.print("Formato dell'input sbagliato", style="bold red")
            console.print("\nInserire impostazioni dello sniff in formato ('count' 'timeout' 'filter'): ", style="italic", end="")
            stringa = input("")



def start_sniff(count=10, timeout=10, msg="tcp"):
    sniff(count=count, timeout=timeout, filter=msg, prn=process_packet)
