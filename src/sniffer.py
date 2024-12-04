import time

from scapy.all import AsyncSniffer


class Sniffer:
    def __init__(self, filter_rule=None):
        """
        Initialize object to keep track of filter, sniffer, packet statistics 
        and request-response timings.
        """
        self.filter_rule = filter_rule
        self.sniffer = None
        self.packet_stats = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'DNS': 0,
            'Other': 0,
            'Total': 0,
        }
        self.request_timestamps = {}

    def start(self, packet_handler, pause_event, stop_event):
        """
        Start the packet sniffer and handle each packet with a callback function.
        """
        print("[INFO] Starting Scapy Sniffer...")

        def packet_callback(packet):
            """
            Callback function to handle each packet.
            """
            if not pause_event.is_set():
                self.track_statistics(packet)
                self.track_request_response(packet)
                packet_handler(packet)

        self.sniffer = AsyncSniffer(filter=self.filter_rule, prn=packet_callback, store=False)
        self.sniffer.start()

        while not stop_event.is_set():
            pause_event.wait(1)

        print("[INFO] Exiting Scapy Sniffer...")
        self.stop()

    def stop(self):
        """
        Stop the packet sniffer if it's still running.
        """
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()

    def track_statistics(self, packet):
        """
        Update protocol-specific statistics.
        """
        self.packet_stats['Total'] += 1
        if packet.haslayer('TCP'):
            self.packet_stats['TCP'] += 1
        elif packet.haslayer('UDP'):
            self.packet_stats['UDP'] += 1
        elif packet.haslayer('ICMP'):
            self.packet_stats['ICMP'] += 1
        elif packet.haslayer('DNS'):
            self.packet_stats['DNS'] += 1
        else:
            self.packet_stats['Other'] += 1

    def track_request_response(self, packet):
        """
        Track timing for request-response pairs and calculate latency.
        """
        if packet.haslayer('TCP') or packet.haslayer('UDP'):
            src = packet['IP'].src if packet.haslayer('IP') else packet['IPv6'].src
            dst = packet['IP'].dst if packet.haslayer('IP') else packet['IPv6'].dst
            sport = packet['TCP'].sport if packet.haslayer('TCP') else packet['UDP'].sport
            dport = packet['TCP'].dport if packet.haslayer('TCP') else packet['UDP'].dport

            key = (src, dst, sport, dport)
            check = (dst, src, dport, sport) # check with flipped src and dst

            if check not in self.request_timestamps:
                # If it's a request, store the timestamp and save details
                self.request_timestamps[key] = self.request_timestamps.get(key, []) + [time.time()]
                
                # Clean up old requests (assuming timeout after 2 seconds)
                n = len(self.request_timestamps[key])
                if self.request_timestamps[key][-1] - self.request_timestamps[key][n//2] > 2:
                    self.request_timestamps[key] = self.request_timestamps[key][(n//2)+1:]
            else:
                # If it's a response, calculate latency and update packet
                request_time = self.request_timestamps[check].pop(0)
                if self.request_timestamps[check] == []:
                    self.request_timestamps.pop(check)
                response_time = time.time()
                latency = response_time - request_time
                packet.latency = latency
                print(f"[INFO] Latency: {latency:.6f} seconds for {key}")
