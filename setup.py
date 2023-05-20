from setuptools import find_packages, setup
from rich.console import Console
console = Console()

with console.status('[bold yellow]Loading...[/]', spinner='line'):
    setup(
        name='sword',
        version='2.5',
        packages=find_packages()
    )
    