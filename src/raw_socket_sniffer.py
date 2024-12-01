import socket
from src.packet_parser import PacketParser

class RawSocketSniffer:
    def __init__(self, filter_rule=None):
        self.filter_rule = filter_rule  # Placeholder for actual filter handling

    def start(self, packet_handler):
        print("[INFO] Starting Raw Socket Sniffer...")
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        while True:
            raw_data, _ = sock.recvfrom(65535)
            parsed_packet = self.parse_packet(raw_data)
            if parsed_packet:
                packet_handler(parsed_packet)

    def parse_packet(self, raw_data):
        eth_header = PacketParser.parse_ethernet_header(raw_data)
        if eth_header['protocol'] == 8:  # IP protocol
            ip_header = PacketParser.parse_ip_header(raw_data)
            if ip_header['protocol'] == 6:  # TCP
                tcp_header = PacketParser.parse_tcp_header(raw_data, ip_header['header_length'])
                return {'eth': eth_header, 'ip': ip_header, 'tcp': tcp_header}
            elif ip_header['protocol'] == 17:  # UDP
                udp_header = PacketParser.parse_udp_header(raw_data, ip_header['header_length'])
                return {'eth': eth_header, 'ip': ip_header, 'udp': udp_header}
            else:
                return {'eth': eth_header, 'ip': ip_header}
        else:
            return {'eth': eth_header}
