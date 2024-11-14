from utils import *

class Ip:

    def __init__(self):
        self.open_ports = []
        self.remote_host = ""

    def __init__(self, remote_host):
        self.remote_host = remote_host
        self.open_ports = []

    def ask_domain(self):
        target = input("Inserisci il dominio o l'indirizzo IP: ")
        self.remote_host = get_host_ip(target)

    