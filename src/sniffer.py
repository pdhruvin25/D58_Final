from scapy.all import AsyncSniffer

class Sniffer:
    def __init__(self, filter_rule=None):
        self.filter_rule = filter_rule
        self.sniffer = None

    def start(self, packet_handler, pause_event, stop_event):
        print("[INFO] Starting Scapy Sniffer...")

        def packet_callback(packet):
            if not pause_event.is_set():  # Process packets only if not paused
                packet_handler(packet)

        # Create an asynchronous sniffer
        self.sniffer = AsyncSniffer(filter=self.filter_rule, prn=packet_callback, store=False)
        self.sniffer.start()

        # Monitor stop_event to stop the sniffer
        while not stop_event.is_set():
            pause_event.wait(1)  # Pause the loop until pause_event is cleared

        print("[INFO] Exiting Scapy Sniffer...")
        self.stop()

    def stop(self):
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
            print("[INFO] Sniffer stopped.")