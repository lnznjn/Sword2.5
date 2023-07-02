import readline
import atexit
import os, sys
from rich.console import Console
from sword.utils.parser import Command_Parser
from sword.utils.banner import banner
from sword.utils.output import info, error
from sword.network_modular.get_network_info_modular import *

console = Console()

class BaseInterpreter(object):
    def __init__(self):
        self.parser = Command_Parser()
        
        self.history_file = os.path.expanduser('~/.history')
        self.history_length = 100
        self.help = '''[yellow]help, h, ?[/]: Get help.'''
        self._setup()

    '''
    readline setup.
    '''
    def _setup(self):
        #--=[*]=--
        readline.parse_and_bind('set enable-keypad on')
        readline.parse_and_bind('tab: complete')
        #--=[*]=--
        if not os.path.exists(self.history_file):
            with open(self.history_file, 'a+') as history:
                history.close

        readline.read_history_file(self.history_file)
        readline.set_history_length(self.history_length)
        atexit.register(readline.write_history_file, self.history_file)

    @property
    def prompt(self):
        return '>>> '

    def start(self):
        banner()
        console.print()
        info('local_ip -> ' + get_local_host(), end='')
        info('interface -> ' + get_ifaces(), end='')
        info('gateway_ip -> ' + get_gateway(), end='')
        console.print()
        while True:
            try:
                command = input(self.prompt)
                
                if not command:
                    continue
                self.parser.parser(command.split())
            
            except KeyboardInterrupt:
                self._quit()

            except EOFError:
                self._quit()
    def _quit(self):
        exit()
    
if __name__ == '__main__':
    interpreter = BaseInterpreter()
    interpreter.start()