from rich.console import Console

import os

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

title = f'''[blue]
███████ ██     ██  ██████  ██████  ██████     -=[ [bold white]Author:[/] [bold yellow]Kiyotaka Ayanokoji[/]  
██      ██     ██ ██    ██ ██   ██ ██   ██    -=[ 
███████ ██  █  ██ ██    ██ ██████  ██   ██    -=[ [bold white]Version:[/] [u yellow]2.6[/]
     ██ ██ ███ ██ ██    ██ ██   ██ ██   ██    -=[
███████  ███ ███   ██████  ██   ██ ██████     -=[ [bold white]Part:[/] [green]{path}[/]
[/]'''

con = Console()

def rule(func):
    def wrapper():
        os.system('clear')
        con.rule('[bold blue]BANNER[/]')
        func()
        con.rule('[bold blue]BANNER[/]')
    return wrapper

@rule
def banner():
    con.print(title)

if __name__ == '__main__':
    banner()