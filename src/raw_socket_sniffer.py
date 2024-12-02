import socket
import platform
from src.packet_parser import PacketParser

class RawSocketSniffer:
    def __init__(self, filter_rule=None):
        self.filter_rule = filter_rule  # Placeholder for actual filter handling
        self.sniffing = False

    def start(self, packet_handler, pause_event, stop_event):
        print("[INFO] Starting Raw Socket Sniffer...")
        self.sniffing = True

        if platform.system().lower() == 'windows':
            pass
        else:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

        sock.settimeout(1)

        try:
            while not stop_event.is_set():
                if not pause_event.is_set():
                    try:
                        raw_data, addr = sock.recvfrom(65535)
                        parsed_packet = self.parse_packet(raw_data)
                        if parsed_packet:
                            packet_handler(parsed_packet)
                    except socket.timeout:
                        pass
                else:
                    pause_event.wait(1)
        except KeyboardInterrupt:
            print("\n[INFO] KeyboardInterrupt detected in sniffer thread.")
        finally:
            if platform.system().lower() == 'windows':
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
            self.sniffing = False
            print("[INFO] Exiting Raw Socket Sniffer...")

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

    def stop(self):
        # This method can be used to perform any cleanup if necessary
        pass