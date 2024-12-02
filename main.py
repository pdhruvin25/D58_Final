import argparse
import threading
import platform
from src.sniffer import Sniffer
from src.raw_socket_sniffer import RawSocketSniffer
from src.display import Display
import keyboard


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

    # Create events for controlling the sniffer
    pause_event = threading.Event()
    stop_event = threading.Event()
    pause_event.clear()
    stop_event.clear()

    try:
        sniffer_thread = threading.Thread(target=sniffer.start, args=(display.process_packet, pause_event, stop_event))
        sniffer_thread.start()
        input_thread = threading.Thread(target=handle_user_input, args=(pause_event, stop_event))
        input_thread.start()

        while sniffer_thread.is_alive() and input_thread.is_alive():
            sniffer_thread.join(timeout=1)
            input_thread.join(timeout=1)

    except KeyboardInterrupt:
        print("\n[INFO] KeyboardInterrupt detected. Stopping sniffer...")
        stop_event.set()
        pause_event.set()
        sniffer.stop()
    finally:
        sniffer_thread.join()
        input_thread.join()
        display.show_statistics(sniffer.packet_stats)
        print("[INFO] Sniffer stopped.")

def handle_user_input(pause_event, stop_event):
    print("[INFO] Press 'p' to pause, 'r' to resume, 'q' to quit.")
    while not stop_event.is_set():
        try:
            if keyboard.is_pressed('p'):
                if not pause_event.is_set():
                    pause_event.set()
                    print("[INFO] Sniffer paused.")
            elif keyboard.is_pressed('r'):
                if pause_event.is_set():
                    pause_event.clear()
                    print("[INFO] Sniffer resumed.")
            elif keyboard.is_pressed('q'):
                stop_event.set()
                print("[INFO] Stopping sniffer...")
                break
        except KeyboardInterrupt:
            stop_event.set()
            print("\n[INFO] KeyboardInterrupt detected. Exiting...")
            break

if __name__ == "__main__":
    main()