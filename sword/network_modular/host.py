from scapy.all import getmacbyip

class Host(object):
    def __init__(self, ip, os, num):
        self.num = num
        self.ip = ip
        self.mac = getmacbyip(ip)
        self.os = os
        self.block = False

    def __eq__(self, other):
        return self.ip == other.ip

    def __hash__(self):
        return hash((self.ip, self.mac))

    def get_status(self):
        if self.block:
            return '[bold red]blocked[/]'

        else:
            return '[green]Free[/]'