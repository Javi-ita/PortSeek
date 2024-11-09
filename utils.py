import json
from multiprocessing.pool import ThreadPool
import os
import signal
import sys
import socket


PORTS_DATA = "./ports.lists.json"


def sigint_handler(sig, frame):
    global should_stop
    print("Caught SIGINT, exiting gracefully...")
    should_stop = True
    # Add your cleanup code here
    sys.exit(0)

def json_data(filename):
    with open(filename, "r") as file:
        data = json.load(file)
    return data #restituisce il contenuto del dizionario nel file json

def threadpool_exec(function, iterable):
    thread_num = os.cpu_count()
    print(f"Number of workers {thread_num}\n")
    with ThreadPool(thread_num) as pool:  
        signal.signal(signal.SIGINT, sigint_handler)
        pool.map(function, iterable) # la funzione viene applicata per ogni elemento dell'iterabili

def get_host_ip(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror as e: 
        print(f"Errore: {e}")
        sys.exit()
    else:
        return ip_address
    
def ask_domain():
    target = input("Inserisci il dominio o l'indirizzo IP: ")
    return get_host_ip(target)
