import sys, os
import logging
from concurrent.futures import ThreadPoolExecutor

import nmap
from tqdm import tqdm
from rich.console import Console
from scapy.all import IP, ICMP, sr1

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from sword.utils.output import error, info
from get_network_info_modular import get_local_host
from host import Host

class Scanner(object):
    def __init__(self) -> None:
        local_network_segment = get_local_host()
        self.timeout = 2.5
        self.max_worker = 100
        self.worker = 2
        
        logging.getLogger('scapy').setLevel(logging.ERROR)
        self.nm = nmap.PortScanner()
        
        if local_network_segment == None:
            exit()

        ip = local_network_segment.split('.')
        self.hosts = f'{ip[0]}.{ip[1]}.{ip[2]}.$'

    def _sweep(self, ip):
        packet = IP(dst=ip)/ICMP()
        answer = sr1(packet, verbose=0, timeout=self.timeout)

        if answer is not None:
            return ip
        
    def _judge(self, ip) -> dict:
        host: dict = self.nm.scan(hosts=ip, arguments='-O -Pn')
        return host, ip

    '''
    only scan ip,
    very quick.
    '''
    def scan_host(self) -> list:
        hosts = []
        iprange = [self.hosts.replace('$', str(i)) for i in range(256)]
        
        with ThreadPoolExecutor(max_workers=self.max_worker) as executor:
            iterator = tqdm(
                iterable=executor.map(self._sweep, iprange),
                total=len(iprange),
                ncols=45,
                bar_format="{percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt}"
            )

            try:
                for host in iterator:
                    if host is not None:
                        hosts.append(host)

            except KeyboardInterrupt:
                iterator.close()
                info('Scaner stopped.')

            return hosts

    '''
    scan ip and judge os,
    need more time.
    '''
    def scan_host_and_judge_os(self) -> list:
        alive_hosts = self.scan_host()
        hosts = list()

        info('Judging...')
        num = 0
        with ThreadPoolExecutor(max_workers=self.worker) as executor:
            iterator = tqdm(
                iterable=executor.map(self._judge, alive_hosts),
                total=len(alive_hosts),
                ncols=45,
                bar_format="{percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt}"
            )

            try:   
                for host, ip in iterator:
                    if ip in host['scan'] and host['scan'][ip]['osmatch']:
                        h = Host(ip, host['scan'][ip]['osmatch'][0]['name'], str(num))

                    else:
                        h = Host(ip, 'Unknow', str(num))

                    hosts.append(h)
                    num += 1

            except KeyboardInterrupt:
                iterator.close()
                info('Scaner stopped.')
        '''
        for host in alive_hosts:
            result = self.nm.scan(hosts=host, arguments='-O -Pn')

            if result['scan'] and result['scan'][host]['osmatch']:
                h = Host(host, result['scan'][host]['osmatch'][0]['name'], str(num))

            else:
                h = Host(host, 'Unknow', str(num))
            
            hosts.append(h)
            num += 1
        '''

        return hosts

#----------------------------------------=[text code]=-----------------------------------------------------

if __name__ == '__main__':
    console = Console()

    '''
    get network segment.
    '''
    sn = Scanner()

    '''
    select scan mode.
    '''
    info = sn.scan_host_and_judge_os()
    for i in info:
        print(i.os)
        print(i.ip)
        print(i.num)