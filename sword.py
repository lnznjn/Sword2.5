import json
import re
import collections

from rich import pretty
from rich.console import Console

console = Console()
pretty.install()

with console.status('[bold blue]Loading...[/]', spinner='line'):
    from sword.utils.interpreter import BaseInterpreter
    from sword.utils.output import *
    from sword.utils.parser import Command_Parser

    from sword.network_modular.arp_spoof_modular import *
    from sword.network_modular.scan_modular import *
    from sword.network_modular.sniff_modular import *
    from sword.network_modular.host import Host

class SwordInterpreter(BaseInterpreter):
    def __init__(self):
        if os.path.exists('./pcap/') != True:
            os.mkdir('./pcap/')
        super().__init__()

#---------------------------------------------------------------------------------------------------------------

        #help
        self.parser.add_subparser(
            name='help',
            type=Command_Parser.Subparser_Type.NO_PMT_SUBP,
            handle=self._print_help
            )

        #quit
        self.parser.add_subparser(
            name='quit',
            type=Command_Parser.Subparser_Type.NO_PMT_SUBP,
            handle=self._quit
        )
        
        #scan
        self.parser.add_subparser(
            name='scan',
            type=Command_Parser.Subparser_Type.NO_PMT_SUBP,
            handle=self._scan_handle
        )

        #hosts
        self.parser.add_subparser(
            name='hosts',
            type=Command_Parser.Subparser_Type.NO_PMT_SUBP,
            handle=self._hosts_handle
        )

        #block
        self.parser.add_subparser(
            name='block',
            type=Command_Parser.Subparser_Type.ESS_PMT_SUBP,
            handle=self._block_handle
        )
        self.parser.add_flag(
            name='target_ip',
            type=Command_Parser.Flag_Type.PARAMETERIZED_FLAG,
            id='-t'
        )

        #free
        self.parser.add_subparser(
            name='free',
            type=Command_Parser.Subparser_Type.ESS_PMT_SUBP,
            handle=self._free_handle
        )

        #sniff
        self.parser.add_subparser(
            name='sniff',
            type=Command_Parser.Subparser_Type.NON_ESS_PMT_SUBP,
            handle=self._sniff_handle
        )
        self.parser.add_flag(
            name='filter',
            type=Command_Parser.Flag_Type.PARAMETERIZED_FLAG,
            id='-f'
        )
        self.parser.add_flag(
            name='save',
            type=Command_Parser.Flag_Type.COMMON_FLAG,
            id='-s'
        )
        self.parser.add_flag(
            name='name',
            type=Command_Parser.Flag_Type.PARAMETERIZED_FLAG,
            id='-n'
        )

        '''monitor
        self.parser.add_subparser(
            name='monitor',
            type=Command_Parser.Subparser_Type.ESS_PMT_SUBP,
            handle=self._monitor_handle
        )'''

#-----------------------------------------------------------------------------------------------------------------

        with open('help.json', 'r') as f:
            self.help_info = json.load(f)

        f.close()
        
        self.information = dict()
        self._hosts_list = list()

        self._arpspoof = Arp_Spoof()
        self._arpspoof.start()

    @property
    def prompt(self):
        return '[\033[1mSWORD]\033[1;33m>>>\033[0m '

    def _quit(self):
        self._arpspoof.stop()
        exit()

#------------------------------------------[handles]-----------------------------------------------------------------------

    def _print_help(self):
        ct = Create_help_table()
        ct.set_help_content(self.help_info)
        ct.show_table()

    def _scan_handle(self):
        scanner = Scanner()
        text('Judging os need more time.', end='')
        choice = input('\033[33;1m[>]\033[0m If judge os. <Y/n> ')

        if choice in ('n', 'N'):
            #with console.status('[bold blue]Scanning...[/]', spinner='line'):
            try:
                result = scanner.scan_host()
            
            except KeyboardInterrupt:
                info('Stopped.')
                return
            
            info(f'{len(result)} hosts discovered.')
            info('Scan done.')
            
            for num in range(0, len(result)):
                host = Host(result[num], 'Unknow', str(num))
                self._hosts_list.append(host)

        else:
            #with console.status('[bold blue]Scanning...[/]', spinner='line'):
            try:
                result = scanner.scan_host_and_judge_os()
            
            except KeyboardInterrupt:
                info('Stopped.')
                return
            
            self._hosts_list = result
            info(f'{len(result)} hosts is discovered.')
            info('Scan done.')

    def _hosts_handle(self):
        if not len(self._hosts_list):
            text('No hosts')
            return
        tb = Create_host_table()
        self._info_handle()
        tb.set_hosts_content(self.information)
        tb.show_table()

    def _block_handle(self, result: dict):
        host = self._get_ip(result)
        if host is None:
            return
        self._arpspoof.add(host)
        info(f'{host.ip} blocked.')

    def _free_handle(self, result: dict):
        host = self._get_ip(result)
        if host is None:
            return
        self._arpspoof.remove(host)
        info(f'{host.ip} freed.')

    def _sniff_handle(self, result: dict = None):
        sniffer = SniffPkt()
        filter_ = None
        pcap_file_name = None
        if result is None:
            sniffer.simple_sniff()
        
        else:            
            if 'filter' in result:
                if result['filter'] is not None:
                    filter_ = result['filter']
                else:
                    error('-f flag need argument.')
                    return

            if 'name' in result and 'save' not in result:
                error('you need -s while you use -n.')
                return
            
            if 'save' in result:
                if 'name' in result:
                    if result['name'] is not None:
                        pcap_file_name = result['name']
                    else:
                        error('-n flag need argument.')
                        return
                
                else:
                    error('need a name for the file.')
                    return
                sniffer.save_sniff(filter_, pcap_file_name)
            else:
                sniffer.simple_sniff(filter_)
    
    def _info_handle(self):
            informat = dict()
            
            for host in self._hosts_list:
                informat.setdefault(
                    host.num,
                    {'host': host.ip, 'os':host.os, 'status': host.get_status()})

            self.information = informat.copy()
            del informat

#----------------------------------------------------------------------------------------------------------------

    def _get_ip(self, result: dict):
        is_ip = False
        is_found = False
        if 'target_ip' in result:
            if result['target_ip'] is not None:
                ips_list = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', result['target_ip'])
                if len(ips_list):
                    is_ip = True
                    for ip in ips_list:
                        
                        for host in self._hosts_list:                            
                            if host.ip == ip:
                                is_found = True
                                return host
                                #self._arpspoof.add(host)
                                #info(f'{ip} blocked')
                                #break

                #Find ip by num.
                elif not is_ip:
                    num_list = result['target_ip'].split(',')
                    for num in num_list:
                        
                        for host in self._hosts_list:
                            if host.num == num:
                                is_found = True
                                return host
                                #self._arpspoof.add(host)
                                #info(f'{num} blocked')
                                #break

                        if not is_found:
                            text(f'{num} did not find.')
                
                else:
                    error(r"'-t' flag need argument.")

            else:
                error(r"'-t' flag need argument.")

        else:
            error(r"This subparse need '-t' flag.")
        return None

if __name__ =='__main__':
    if os.geteuid() != 0:
        text
        ('Sword must running in root.')
        info('Exiting...')
        exit()
    si = SwordInterpreter()
    si.start()