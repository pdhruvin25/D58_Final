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
    def format_mac(mac):
        return ':'.join(map('{:02x}'.format, mac))
