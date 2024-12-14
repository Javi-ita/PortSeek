from scan import *
from pack import *
from utils import *
import sys
from sniff import *
import pyfiglet
from rich.table import Table

OPTIONS = ["Scan Ip", "Crea Pacchetto", "Sniff", "Exit"]

# metodo che inizializza il menù di avvio
def initialize():
    console.print(pyfiglet.figlet_format(" PORTSEEK "), style="bold magenta")
    console.print("#"*8 + "  Port Scanner Multifunzionale  " + "#"*8, style="bold magenta")
    console.print("\nProject by Tobia Grimaldi, Matteo Quarta, Davide Padovano.", style="italic #808080")
    console.print("(Version 1.0)", style="italic #808080")

# metodo che richiede il protocollo da usare nella scansione
def scan():
    while True:
        console.print("Scan(tcp/udp): ", end="", style="bold white")
        stringa = input().lower()
        if stringa in ["tcp", "udp"]:
            return "TCP" if stringa == "tcp" else "UDP"
        console.print("Invalid choice. Please choose 'tcp' or 'udp'.", style="red bold")

def sel_mode(key):
    if key == "1":
        i = scan()
        if i == "TCP":
            scanner = Tcp()
            scanner.start()
        elif i == "UDP":
            scanner = Udp()
            scanner.start()
    elif key == "2":
        i = sel_packet()
        if i == "ICMP":
            icmp_pack = ICMP_Pack()
            icmp_pack.start()
        elif i == "HTTP":
            http_pack = HTTP()
            http_pack.start()
        elif i == "DNS":
            dns_pack = DNS_pack()
            dns_pack.start()
    elif key == "3":
        param = define_sniff()
        if param:
            start_sniff(count=param[0], timeout=param[1], msg=param[2])
        else:
            start_sniff()
    elif key == "4":
        console.print("Exiting...\n", style="blink")
        sys.exit()
    else:
        console.print("Invalid choice. Please choose a valid option.", style="red bold")

def sel_packet():
    while True:
        console.print("Seleziona il pacchetto (ICMP/HTTP/DNS): ", end="", style="bold white")
        stringa = input().upper()
        if stringa in ["ICMP", "HTTP", "DNS"]:
            return stringa
        console.print("Invalid choice. Please choose 'ICMP', 'HTTP', or 'DNS'.", style="bold red")

def create_table():
    table = Table(box=None)
    table.add_column("", no_wrap=True)
    table.add_column("", no_wrap=True)
    for i in range(1, len(OPTIONS)+1):
        table.add_row(f"[bold]{i}[/bold]", OPTIONS[i-1])
    return table

"""def help():
    console.print("[bold blue] Scan Ip[/bold blue]: permette di scansionare le porte di uno o più Ip" +
                   " specificati dall'utente con protocollo TCP e UDP", style="italic white")
    console.print("[bold blue] Crea Pacchetto[/bold blue]: crea un pacchetto e visualizza la risposta", style="italic white")
    console.print("[bold blue] Sniff[/bold blue]: permette di sniffare i pacchetti ricevuti e inviati dal localhost" +
                  "e printarne le informazioni", style="italic white")
    console.print("Per specificare un range di IP utilizzare formato CIDR")"""

#metodo con il ciclo di esecuzione del programma
def menu():
    initialize()
    table = create_table()
    while True:
        try:
            console.print(table)
            key = input(" ")
            sel_mode(key)
        except KeyboardInterrupt:
            console.print("\nExiting...", style="blink")
            sys.exit()

if __name__ == "__main__":
    menu()

