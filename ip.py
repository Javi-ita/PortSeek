from utils import *

class Ip:

    def __init__(self, remote_host):
        self.remote_host = remote_host
        self.open_ports = []
    