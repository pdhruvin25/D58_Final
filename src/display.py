from rich.console import Console
from rich.table import Table

class Display:
    def __init__(self):
        self.console = Console()

    def show_banner(self):
        self.console.print("[bold blue]Welcome to Packet Sniffer[/bold blue]")

    def process_packet(self, packet):
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Source")
        table.add_column("Destination")
        table.add_column("Protocol")
        table.add_column("Info")

        # Example of parsed packet display
        table.add_row("192.168.1.1", "192.168.1.2", "TCP", "Example Info")
        self.console.print(table)
