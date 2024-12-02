import os
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR
from rich.console import Console
from rich.table import Table
from datetime import datetime


class Display:
    def __init__(self):
        self.console = Console()
        self.output_file = "packet_sniffer_output.txt"
        self.initialize_output_file()

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

    def show_banner(self):
        self.console.print("[bold blue]Welcome to Packet Sniffer[/bold blue]")

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
            payload = bytes(packet[TCP].payload).decode('utf-8', errors='ignore')
            if "HTTP" in payload:
                info = f"HTTP Payload: {payload.splitlines()[0]}"
            else:
                info = f"{src_port} -> {dest_port}"
        elif packet.haslayer(UDP):
            protocol = 'UDP'
            src_port = packet[UDP].sport
            dest_port = packet[UDP].dport
            info = f"{src_port} -> {dest_port}"
        elif packet.haslayer(ICMP):
            protocol = 'ICMP'
            info = f"Type {packet[ICMP].type}, Code {packet[ICMP].code}"
        elif packet.haslayer(DNS):
            protocol = 'DNS'
            if packet.haslayer(DNSQR):  # DNS Query
                query_name = packet[DNSQR].qname.decode('utf-8') if packet[DNSQR].qname else 'N/A'
                info = f"Query: {query_name}"
            elif packet.haslayer(DNSRR):  # DNS Response
                response_name = packet[DNSRR].rrname.decode('utf-8') if packet[DNSRR].rrname else 'N/A'
                info = f"Response: {response_name}"
            else:
                info = "DNS Packet"
        else:
            protocol = 'Other'
            info = packet.summary()

        table.add_row(src_ip, dest_ip, protocol, info)
        self.console.print(table)

        # Save to file
        self.save_to_file(src_ip, dest_ip, protocol, info)