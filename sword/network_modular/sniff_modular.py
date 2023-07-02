import sys

from scapy.all import *
path = sys.argv[0].replace('bin/sword.py', 'sword/')
sys.path.append(path)
from sword.utils.output import info, error
from sword.network_modular.get_network_info_modular import get_ifaces

class SniffPkt(object):
    def __init__(self) -> None:
        self.interface = get_ifaces()

    '''Only packets information will be printed out,
    but not be saved.'''
    def simple_sniff(self, filter=None):
        def _pkt_handler(pkt) -> None:
            info(pkt.summary())

        info('[bold yellow]\'Ctrl + c\'[/] to stop.')
        try:
            sniff(prn=_pkt_handler, iface=self.interface, filter=filter)
            info('Sniff over.')

        except Scapy_Exception as e:
            error(e)
            return

    '''The packets information will be printed out
    and saved as pcap.'''
    def save_sniff(self, filter=None, pcap_name='infomation') -> None:
        info('[bold yellow]\'Ctrl + c\'[/] to stop.')
        try:
            pkt_list = sniff(prn=lambda pkt: info(pkt.summary()), iface=self.interface, filter=filter)
            wrpcap(r'pcap/' + pcap_name + '.pcap', pkt_list)
            info('Sniff over.')

        except Scapy_Exception as e:
            error(e)

if __name__ == '__main__':
    sp = SniffPkt(interface='wlan0')
    sp.simple_sniff(host='192.168.2.13') 