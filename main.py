import argparse
import platform
from src.sniffer import Sniffer
from src.raw_socket_sniffer import RawSocketSniffer
from src.display import Display

def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer Tool")
    parser.add_argument('--mode', choices=['scapy', 'raw'], default='scapy',
                        help="Choose sniffer mode: Scapy or Raw Sockets")
    parser.add_argument('--filter', type=str, default=None,
                        help="Apply a packet filter (e.g., 'tcp port 80')")
    args = parser.parse_args()

    display = Display()

    os_type = platform.system().lower()
    if os_type == 'windows':
        if args.mode == 'raw':
            print("[WARNING] Raw socket mode is not supported on Windows. Switching to Scapy mode.")
        sniffer = Sniffer(filter_rule=args.filter)
    else:
        if args.mode == 'scapy':
            sniffer = Sniffer(filter_rule=args.filter)
        else:
            sniffer = RawSocketSniffer(filter_rule=args.filter)

    display.show_banner()
    sniffer.start(display.process_packet)

if __name__ == "__main__":
    main()
