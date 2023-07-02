from scapy.all import getmacbyip

class Host(object):
    def __init__(self, ip, os, num):
        self.num = num
        self.ip = ip
        self.mac = getmacbyip(ip)
        self.os = os
        self.block = False
        self.limit = False

    def __eq__(self, other):
        return self.ip == other.ip

    def __hash__(self):
        return hash((self.ip, self.mac))

    def get_status(self):
        if self.block or self.limit:
            if self.limit:
                return '[bold yellow]Limited[/]'
            else:
                return '[bold red]blocked[/]'
        
        else:
            return '[green]Free[/]'