import nmap
from rich.console import Console

from sword.utils.output import error
from sword.network_modular.get_network_info_modular import get_local_host

import sys
import os
import socket

class Scanner(object):
    def __init__(self) -> None:
        self.nm = nmap.PortScanner()
        local_network_segment = get_local_host()
        if local_network_segment == None:
            exit()

        ip = local_network_segment.split('.')
        self.hosts = f'{ip[0]}.{ip[1]}.{ip[2]}.0/24'

    '''
    only scan ip,
    very quick.
    '''
    def scan_host(self) -> list:
        rev = self.nm.scan(hosts=self.hosts, arguments='-sP')
        hosts = list()
        for i in rev['scan']:
            hosts.append(i)

        return hosts

    '''
    scan ip and judge os,
    need more time.
    '''
    def scan_host_and_judge_os(self) -> dict:
        alive_hosts = self.scan_host()
        info = dict()
        for host in alive_hosts:
            result = self.nm.scan(hosts=host, arguments='-O -Pn')

            if result['scan']:
                if result['scan'][host]['osmatch']:
                    info.setdefault(host, result['scan'][host]['osmatch'][0]['name'])

            else:
                info.setdefault(host, 'Unknow')

        return info

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
    console.print(
        '\n[bold yellow][?][/] only scan ip (quick) or scan ip and judge os (need more time).')
    console.print('\t[1] only scan ip.')
    console.print('\t[2] scan ip and judge os.\n')
    choice = console.input('([bold blue]Sword[/])>>> ')

    if str(choice) == '1':  #first scan mode.
        console.print('\n')
        with console.status('[bold blue]Working...[/]', spinner='line'):
            rev = sn.scan_ip()
        for i in range(0, len(rev)-1):
            console.print(f'[bold green][+][/] {rev[i]}')

        sys.exit(1)

    elif str(choice) == '2':  #second scan mode.
        console.print('\n')
        with console.status('[bold blue]Working...[/]', spinner='line'):
            rev = sn.scan_ip_and_judge_os()
        for host in rev:
            console.print(f'[bold green][+][/] {host} - {rev[host]}')

        sys.exit(1)

    else:
        console.print(f'[bold red][-][/] unknow \'{str(choice)}\'')
        sys.exit(1)
