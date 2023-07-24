import os
from typing import Any

from prompt_toolkit import prompt
from prompt_toolkit.styles import Style
from prompt_toolkit.history import FileHistory
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

class SwordInput(object):
    def __init__(self):
        self.HISTORY_FILE = os.path.dirname(__file__).replace('sword/utils', '.history')
        
        #/home/kiyotaka/Project/python_projects/sword/sword/utils
        if not os.path.exists(self.HISTORY_FILE):
            with open(self.HISTORY_FILE, 'w') as f:
                f.close()
        
        self.prompt_style = Style.from_dict({
            'blue': 'ansiblue',
            'bblue': 'ansiblue bold',
            'white': 'ansiwhite'
        })

        self.prompt_message = [
            ('class:white', '┌──'),
            ('class:bblue', '##'),
            ('class:white', '('),
            ('class:blue', 'SWORD'),
            ('class:white', ')'),
            ('class:bblue', '##'),
            ('', '\n'),
            ('class:white', '└─'),
            ('class:blue', '$'),
            ('', ' ')
        ]

        self.completer = NestedCompleter.from_nested_dict({
            'block': {
                '-t': None
            },
            'limit': {
                '-t': None
            },
            'free': {
                '-t': None
            },
            'sniff': {
                '-f': None,
                '-s': None
            },
            'scan': None,
            'hosts': None,
            'help': None,
            'exit': None,
            'quit': None
        })

    def __call__(self):
        return prompt(
            self.prompt_message,
            history=FileHistory(self.HISTORY_FILE),
            auto_suggest=AutoSuggestFromHistory(),
            style=self.prompt_style,
            completer=self.completer,
            complete_in_thread=True
        )

class BaseInput(object):
    def __call__(self, message=None, style=None) -> str:
        return prompt(message=message, style=style, complete_in_thread=True)

if __name__ == '__main__':
    sinput = SwordInput()

    while True:
        command = sinput()
        if command in ('exit', 'quit'):
            break
        print(command)
