from scapy.all import sniff

class Sniffer:
    def __init__(self, filter_rule=None):
        self.filter_rule = filter_rule

    def start(self, packet_handler):
        print("[INFO] Starting Scapy Sniffer...")
        sniff(filter=self.filter_rule, prn=packet_handler, store=False)
