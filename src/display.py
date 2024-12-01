from rich.console import Console
from rich.table import Table
from scapy.all import IP, TCP, UDP

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

        if isinstance(packet, dict):
            # Raw socket packet
            eth = packet.get('eth', {})
            ip = packet.get('ip', {})
            transport = packet.get('tcp', packet.get('udp', {}))
            src_ip = ip.get('src_ip', 'N/A')
            dest_ip = ip.get('dest_ip', 'N/A')
            if 'tcp' in packet:
                protocol = 'TCP'
                src_port = transport.get('src_port', 'N/A')
                dest_port = transport.get('dest_port', 'N/A')
                info = f"{src_port} -> {dest_port}"
            elif 'udp' in packet:
                protocol = 'UDP'
                src_port = transport.get('src_port', 'N/A')
                dest_port = transport.get('dest_port', 'N/A')
                info = f"{src_port} -> {dest_port}"
            else:
                protocol = 'Other'
                info = ''
            table.add_row(src_ip, dest_ip, protocol, info)
        else:
            # Scapy packet
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
                info = ''
            table.add_row(src_ip, dest_ip, protocol, info)

        self.console.print(table)
