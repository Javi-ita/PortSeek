from scan import *
from pack import *
from utils import *
import sys

def initialize():
    print("\n-------------PORT SEEKER--------------\n")
    print("\nProject by Tobia Grimaldi, Matteo Quarta, Davide Padovano.")
    print("Type 'help' for information about the accepted input.")
    print("(Version 1.0)")

def scan():
    stringa = input("Scan(tcp/udp): ")
    while(stringa.lower() not in ["tcp","udp"]):
        print("Scelta non valida")
        stringa = input("Scan(tcp/udp): ")
    return "TCP" if stringa == "tcp" else "UDP"

def sel_packet():
    stringa = input("Seleziona il pacchetto (ICMP/HTTP/DNS): ")
    while(stringa.upper() not in ["ICMP","HTTP","DNS"]):
        print("Scelta non valida")
        stringa = input("Seleziona il pacchetto (ICMP/HTTP/DNS): ")
    return stringa.upper()

def menu():
    initialize()
    while(True):
        print("\n1. Scan IP.")
        print("2. Create Packet.")
        print("3. Exit.")
        num = input("")
        if num == "1":
            i = scan()
            if i == "TCP":
                scanner = Tcp()
                scanner.start()
            elif i == "UDP":
                scanner = Udp()
                scanner.start()
        if num == "2":
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
        if num == "3":
            print("\nExiting...")
            sys.exit()

if __name__ == "__main__":
    menu()

