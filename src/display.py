from rich.console import Console
from rich.table import Table
from datetime import datetime
import time

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

    def save_to_file(self, src, dest, protocol, info, latency=None):
        """Append packet details to the output file."""
        with open(self.output_file, "a") as f:
            latency_str = f" | Latency: {latency:.6f}s" if latency else ""
            f.write(f"{src:<20}{dest:<20}{protocol:<10}{info}{latency_str}\n")

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
        table.add_column("Latency")

        src_ip = packet['IP'].src if packet.haslayer('IP') else 'N/A'
        dest_ip = packet['IP'].dst if packet.haslayer('IP') else 'N/A'

        if packet.haslayer('TCP'):
            protocol = 'TCP'
            src_port = packet['TCP'].sport
            dest_port = packet['TCP'].dport
            payload = bytes(packet['TCP'].payload).decode('utf-8', errors='ignore')

            if src_port == 80 or dest_port == 80:  # HTTP traffic
                method = None
                if payload.startswith(("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")):
                    method = payload.split(" ")[0]
                info = f"HTTP {method}" if method else "HTTP Traffic"
            else:
                info = f"{src_port} -> {dest_port}"
        elif packet.haslayer('UDP'):
            protocol = 'UDP'
            src_port = packet['UDP'].sport
            dest_port = packet['UDP'].dport
            info = f"{src_port} -> {dest_port}"
        else:
            protocol = 'Other'
            info = packet.summary()

        latency = getattr(packet, 'latency', 'N/A')
        latency_str = f"{latency:.6f}s" if isinstance(latency, float) else latency

        table.add_row(src_ip, dest_ip, protocol, info, latency_str)
        self.console.print(table)

        # Save to file
        self.save_to_file(src_ip, dest_ip, protocol, info, latency if isinstance(latency, float) else None)

        # Add delay before processing the next packet
        time.sleep(0.1)  # Adjust the delay time as needed


