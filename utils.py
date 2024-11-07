import json
from multiprocessing.pool import ThreadPool
import os

PORTS_DATA = "./ports.lists.json"

def json_data(filename):
    with open(filename, "r") as file:
        data = json.load(file)
    return data #restituisce il contenuto del dizionario nel file json

def threadpool_exec(function, iterable, itrb_len):
    thread_num = os.cpu_count()
    print(f"Number of workers {thread_num}\n")
    with ThreadPool(thread_num) as pool:
        try:
            pool.map(function, iterable) # la funzione viene applicata per ogni elemento dell'iterabile
        except KeyboardInterrupt:
            pool.terminate()
            print("Threadpool interrupted")
