from scapy.all import *

'''
TODO: DNS_spoof
'''

# DNS_pkg = IP()/UDP()/DNS(id,
# qr,
# opcode,
# rd,
# qd=DNSQR(qnname=dns_name),
# verbose=False)

class DNS_SPOOF(object):
    def __init__(self) -> None:
        DNS_pkg = IP()/UDP()/DNS()

    def __DNS_pkg_handler(packge):
        pass