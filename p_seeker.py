import socket
import json


OPEN_PORTS = []
PORTS_DATA = "./ports.lists.json"

def json_data(filename):
    with open(filename, "r") as file:
        data = json.load(file)
    return data #restituisce il contenuto del dizionario nel file json

def get_ports():
    data = json_data(PORTS_DATA)
    return {int(k) : v[0]["description"] for (k,v) in data.items()} #dizionario secondario che associa interi alle chiavi

# passiamo un ip invece che un dominio per questione di sicurezza

def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # specifico famiglia e tipologia TCP
    sock.settimeout(1)
    status = sock.connect_ex((ip, port)) # restituisce 0 se stabilisce connessione --> porta aperta
    if status == 0:
        OPEN_PORTS.append(port)
    sock.close() # necessario chiudere la connessione

def get_host_ip(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror as e: 
        print(f"Errore: {e}")
    else:
        return ip_address
    
if __name__ == "__main__":
    target = input("Inserisci il dominio o l'indirizzo IP: ")
    ip = get_host_ip(target)
    ports_data = get_ports()
    for port in ports_data.keys(): #port sarebbe un numero e non una stringa come nel file json
        try:
            print(f"Scanning {ip} : {port}")
            scan_port(ip, port)
        except KeyboardInterrupt:
            print("\nScansione interrotta")
            break
    
    print("Open ports")
    for port in OPEN_PORTS:
        print(str(port), ports_data[port])





