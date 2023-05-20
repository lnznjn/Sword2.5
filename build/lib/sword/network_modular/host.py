from scapy.all import getmacbyip

class Host(object):
    def __init__(self, ip, os):
        self.ip = ip
        self.mac = getmacbyip(ip)
        self.os = os
        self.spoof = False

    def __eq__(self, other):
        return self.ip == other.ip

    def __hash__(self):
        return hash((self.ip, self.mac))

    def get_status(self):
        if self.spoof:
            return '[bold red]Spoof[/]'

        else:
            return '[green]Free[/]'
