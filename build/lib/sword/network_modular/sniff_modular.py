import sys

from scapy.all import *
path = sys.argv[0].replace('bin/sword.py', 'sword/')
sys.path.append(path)
from sword.utils.output import info, error

class SniffPkt(object):
    def __init__(self, interface) -> None:
        self.interface = interface

    '''Only packets information will be printed out,
    but not be saved.'''
    def simple_sniff(self, host=None, filter=None):
        def _pkt_handler(pkt) -> None:
            info(pkt.summary())

        '''When host is not None,
        used to sniff the packets of the attacked computer.'''
        if host != None:
            if filter == None:
                filter = f'host {host}'

            else:
                filter += f'and host {host}'

        else:
            pass
            
        info('[bold yellow]\'Ctrl + c\'[/] to stop.')
        try:
            sniff(prn=_pkt_handler, iface=self.interface, filter=filter)

        except Scapy_Exception as e:
            error(e)

        except KeyboardInterrupt:
            info('Sniff over.')

    '''The packets information will be printed out
    and saved as pcap.'''
    def save_sniff(self, host=None, filter=None, pcap_name='infomation.pcap') -> None:
        def _pkt_handler(pkt) -> None:
            wrpcap(pcap_name, pkt)
            info(pkt.summary())

        if host != None:
            if filter == None:
                filter = f'host {host}'

            else:
                filter += f'and host {host}'

        else:
            pass
            
        info('[bold yellow]\'Ctrl + c\'[/] to stop.')
        try:
            sniff(prn=_pkt_handler, iface=self.interface, filter=filter)

        except Scapy_Exception as e:
            error(e)

        except KeyboardInterrupt:
            info('Sniff over.')

if __name__ == '__main__':
    sp = SniffPkt(interface='wlan0')
    sp.simple_sniff(host='192.168.2.13') 