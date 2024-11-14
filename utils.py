import json
from multiprocessing.pool import ThreadPool
import os
import signal
import sys
import socket

def json_data(filename):
    with open(filename, "r") as file:
        data = json.load(file)
    return data #restituisce il contenuto del dizionario nel file json

def threadpool_exec(function, iterable):
    thread_num = os.cpu_count()
    print(f"Number of workers {thread_num}\n")
    with ThreadPool(thread_num) as pool:
        pool.map(function, iterable) # la funzione viene applicata per ogni elemento dell'iterabili
        def sigint_handler(sig, frame):
            print("Caught SIGINT, exiting gracefully...")
            sys.exit(0)
        signal.signal(signal.SIGINT, sigint_handler)

def get_host_ip(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror as e: 
        print(f"Errore: {e}")
        sys.exit()
    else:
        return ip_address

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
