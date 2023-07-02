from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, Ether

'''
TODO: DNS_spoof
'''

# DNS_pkg = Ether()/IP()/UDP()/DNS(id,
#   qr,
#   opcode,
#   rd,
#   qd=DNSQR(qnname=dns_name),
#   verbose=False)

class DNS_SPOOF(object):
    def __init__(self) -> None:
        ...

    def _DNS_pkg_handler(packge):
        pass