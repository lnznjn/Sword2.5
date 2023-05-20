from ossaudiodev import control_names
from rich.table import Table
from rich.console import Console

console = Console()
table = Table()

def info(content, end='\n'):
    console.print(f'[bold blue][INFO][/] {content}{end}')

def error(content, end='\n'):
    console.print(f'[bold red][ERROR][/] {content}{end}')

def text(content, end='\n'):
    console.print(f'[bold yellow][TEXT][/] {content}{end}')

class Create_host_table(object):
    def __init__(self) -> None:
        self.table = Table()
        columns = ['num', 'host', 'os', 'status']
        for column in columns:
            self.table.add_column(f'[bold blue]{column}[/]')

    def set_hosts_content(self, info):
        for num in info:
            self.table.add_row(
                num,
                info[num]['host'],
                '[bold blue]' + info[num]['os'] + '[/]',
                info[num]['status']
            )
    def show_table(self):
            console.print(self.table)
            console.print()
    
class Create_help_table(object):
    def __init__(self) -> None:
        self.table = Table()
        columns = ['command', 'explain']
        for column in columns:
            self.table.add_column(f'[bold blue]{column}[/]')
    
    def set_help_content(self, help: dict):
        for command in help:
            self.table.add_row(
                command,
                help[command]
            )
            
    def show_table(self):
            console.print(self.table)
            console.print()

if __name__ == '__main__':
    from time import ctime, sleep
    '''
    just a test.
    '''
    content = 'text'
    info(content)
    error(content)
    text(content)

    host_table = Create_host_table()
    help_table = Create_help_table()
    info = {'1': {'host': '192.168.2.1',
                'os': 'unknow',
                'status': 'free'
                },
            
            '2': {'host': '192.168.2.9',
                'os': 'window7',
                'status': 'free'
                },
            
            '3': {'host': '192.168.2.13',
                'os': 'linux',
            'status': 'free'
                }
            }

    help_info = {
            'help, h, ?': 'Get help.',
            'ifconfig': 'View network information.',
            'clear, clr': 'Clear screen.',
            'exit, quit, q': 'Exit.',
            'scan': 'Scan hosts.',
            'sniff': 'Sniff packets, it can be used with \'arpsf\'. (Or use \'monitor\') sniff <filter BPF>',
            'arpsf': 'ARP spoof. arpsf <target ip>'
        }
    host_table.set_hosts_content(info)
    host_table.show_table()
    help_table.set_help_content(help_info)
    help_table.show_table()


