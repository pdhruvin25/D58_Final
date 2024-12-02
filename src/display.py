import time
from datetime import datetime

from rich.console import Console
from rich.table import Table
from scapy.all import IP, TCP, UDP


class Display:
    def __init__(self):
        self.console = Console()
        self.output_file = "packet_sniffer_output.txt"
        self.initialize_output_file()

    def show_banner(self):
        """Display a banner message when the sniffer starts."""
        self.console.print("[bold blue]Welcome to Packet Sniffer[/bold blue]")

    def initialize_output_file(self):
        """Prepare the output file with a header."""
        with open(self.output_file, "w") as f:
            f.write("Packet Sniffer Output\n")
            f.write(f"Started on: {datetime.now()}\n")
            f.write("=" * 50 + "\n")
            f.write(f"{'Source':<20}{'Destination':<20}{'Protocol':<10}{'Info'}\n")
            f.write("=" * 50 + "\n")

    def save_to_file(self, src, dest, protocol, info):
        """Append packet details to the output file."""
        with open(self.output_file, "a") as f:
            f.write(f"{src:<20}{dest:<20}{protocol:<10}{info}\n")

    def show_statistics(self, stats):
        """Display overall packet statistics."""
        self.console.print("[bold green]Packet Statistics:[/bold green]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Protocol")
        table.add_column("Count")

        for protocol, count in stats.items():
            table.add_row(protocol, str(count))

        self.console.print(table)

    def process_packet(self, packet):
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Source")
        table.add_column("Destination")
        table.add_column("Protocol")
        table.add_column("Info")

        src_ip = packet[IP].src if packet.haslayer(IP) else 'N/A'
        dest_ip = packet[IP].dst if packet.haslayer(IP) else 'N/A'

        if packet.haslayer(TCP):
            protocol = 'TCP'
            src_port = packet[TCP].sport
            dest_port = packet[TCP].dport
            info = f"{src_port} -> {dest_port}"
        elif packet.haslayer(UDP):
            protocol = 'UDP'
            src_port = packet[UDP].sport
            dest_port = packet[UDP].dport
            info = f"{src_port} -> {dest_port}"
        else:
            protocol = 'Other'
            info = packet.summary()

        table.add_row(src_ip, dest_ip, protocol, info)
        self.console.print(table)

        # Save to file
        self.save_to_file(src_ip, dest_ip, protocol, info)
