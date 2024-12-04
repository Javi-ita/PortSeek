import json
from multiprocessing.pool import ThreadPool
import os
import sys
import socket
import ipaddress

# Estrae dati dal file json
def json_data(filename):
    with open(filename, "r") as file:
        data = json.load(file)
    return data #restituisce il contenuto del dizionario nel file json

# Metodo che crea il ThreadPool e esegue iterativamente una funzione passata come parametro
def threadpool_exec(function, iterable):
    thread_num = os.cpu_count()
    with ThreadPool(thread_num) as pool:
        pool.map(function, iterable) # chiamata alla funzione per ogni elemento dell'iterabile

# Metodo che restituisce un singolo Ip o un intero Range
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
    
#Metodo che verifica se la stringa passata come parametro è in formato CIDR o meno
def is_cidr_notation(ip_string):
    try:
        ip_network = ipaddress.ip_network(ip_string)
        return True
    except ValueError:
        return False

