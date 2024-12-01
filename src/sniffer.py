from scapy.all import sniff

class Sniffer:
    def __init__(self, filter_rule=None):
        self.filter_rule = filter_rule
        self.sniffing = False

    def start(self, packet_handler, pause_event, stop_event):
        print("[INFO] Starting Scapy Sniffer...")
        self.sniffing = True

        def sniff_packets():
            while not stop_event.is_set():
                if not pause_event.is_set():
                    sniff(filter=self.filter_rule, prn=packet_handler, store=False, timeout=1)
                else:
                    # Paused, wait until pause_event is cleared or stop_event is set
                    pause_event.wait(1)
            print("[INFO] Exiting Scapy Sniffer...")

        sniff_packets()
        self.sniffing = False

    def stop(self):
        # This method can be used to perform any cleanup if necessary
        pass
