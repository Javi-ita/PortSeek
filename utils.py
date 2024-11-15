import json
from multiprocessing.pool import ThreadPool
import os
import signal
import sys
import socket
import ipaddress

def json_data(filename):
    with open(filename, "r") as file:
        data = json.load(file)
    return data #restituisce il contenuto del dizionario nel file json

def threadpool_exec(function, iterable):
    thread_num = os.cpu_count()
    with ThreadPool(thread_num) as pool:
        pool.map(function, iterable) # chiamata alla funzione per ogni elemento dell'iterabile


def get_host_ip(target):
    try:
        if(is_cidr_notation(target)):
            return target
        ip_address = socket.gethostbyname(target)
    except socket.gaierror as e: 
        print(f"Errore: {e}")
        sys.exit()
    else:
        return ip_address
    
def is_cidr_notation(ip_string):
    try:
        ip_network = ipaddress.ip_network(ip_string)
        return True
    except ValueError:
        return False

def initialize():
    print("\n------------  PORT SEEKER  ------------\n")
    print("Scan TCP - 1")
    print("Scan UDP - 2")
    stringa = input("")
    while(int(stringa) not in [1,2]):
        print("Scelta non valida")
        stringa = input("")
    if stringa == "1":
        return "TCP"
    elif stringa ==  "2":
        return "UDP"
