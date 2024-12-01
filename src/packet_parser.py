import struct
import socket

class PacketParser:
    @staticmethod
    def parse_ethernet_header(data):
        dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
        return {
            'dest_mac': PacketParser.format_mac(dest_mac),
            'src_mac': PacketParser.format_mac(src_mac),
            'protocol': socket.htons(proto)
        }

    @staticmethod
    def parse_ip_header(data):
        ip_header_raw = data[14:34]
        ip_header = struct.unpack('!BBHHHBBH4s4s', ip_header_raw)
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0xF) * 4
        ttl = ip_header[5]
        proto = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        return {
            'version': version,
            'ihl': ihl,
            'ttl': ttl,
            'protocol': proto,
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'header_length': ihl
        }

    @staticmethod
    def parse_tcp_header(data, iph_length):
        tcp_start = 14 + iph_length
        tcp_header_raw = data[tcp_start:tcp_start+20]
        tcp_header = struct.unpack('!HHLLBBHHH', tcp_header_raw)
        src_port = tcp_header[0]
        dest_port = tcp_header[1]
        sequence = tcp_header[2]
        acknowledgement = tcp_header[3]
        offset_reserved = tcp_header[4]
        tcp_header_length = (offset_reserved >> 4) * 4
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'sequence': sequence,
            'acknowledgement': acknowledgement,
            'header_length': tcp_header_length
        }

    @staticmethod
    def parse_udp_header(data, iph_length):
        udp_start = 14 + iph_length
        udp_header_raw = data[udp_start:udp_start+8]
        udp_header = struct.unpack('!HHHH', udp_header_raw)
        src_port = udp_header[0]
        dest_port = udp_header[1]
        length = udp_header[2]
        checksum = udp_header[3]
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'length': length,
            'checksum': checksum
        }

    @staticmethod
    def format_mac(mac):
        return ':'.join(map('{:02x}'.format, mac))
