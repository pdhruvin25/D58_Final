import argparse
import threading

import keyboard

from src.display import Display
from src.sniffer import Sniffer


def main():
    # Handle command line arguments
    parser = argparse.ArgumentParser(description="Packet Sniffer Tool")
    parser.add_argument('--filter', type=str, default=None,
                        help="Apply a BPF-style packet filter (e.g., 'tcp port 80')")
    parser.add_argument('--src-ip', type=str, default=None,
                        help="Filter packets by source IP address.")
    parser.add_argument('--dest-ip', type=str, default=None,
                        help="Filter packets by destination IP address.")
    args = parser.parse_args()

    # Build filter rule with additional IP filters
    filter_rule = args.filter
    if args.src_ip:
        filter_rule = f"{filter_rule} and src {args.src_ip}" if filter_rule else f"src {args.src_ip}"
    if args.dest_ip:
        filter_rule = f"{filter_rule} and dst {args.dest_ip}" if filter_rule else f"dst {args.dest_ip}"

    # Store options in an object for easy access while displaying
    filter_options = {
        "Packet Filter": args.filter,
        "Source IP": args.src_ip,
        "Destination IP": args.dest_ip,
    }

    # Initialize display and sniffer object
    display = Display(filter_options=filter_options)
    sniffer = Sniffer(filter_rule=filter_rule)
    display.show_banner()

    # Initialize threading events (pause and stop)
    pause_event = threading.Event()
    stop_event = threading.Event()
    pause_event.clear()
    stop_event.clear()

    try:
        # Start packet sniffer thread
        sniffer_thread = threading.Thread(target=sniffer.start, args=(display.process_packet, pause_event, stop_event))
        sniffer_thread.start()
        # Start user input thread
        input_thread = threading.Thread(target=handle_user_input, args=(pause_event, stop_event))
        input_thread.start()

        # Wait for both threads to finish
        while sniffer_thread.is_alive() and input_thread.is_alive():
            sniffer_thread.join(timeout=1)
            input_thread.join(timeout=1)

    except KeyboardInterrupt:
        # Stop sniffer if KeyboardInterrupt is detected
        print("\n[INFO] KeyboardInterrupt detected. Stopping sniffer...")
        stop_event.set()
        pause_event.set()
        sniffer.stop()
    finally:
        # Once threads are done, display statistics and stop sniffer
        sniffer_thread.join()
        input_thread.join()
        display.show_statistics(sniffer.packet_stats)
        print("[INFO] Sniffer stopped.")

# Handle user input to pause, resume, or stop the sniffer
def handle_user_input(pause_event, stop_event):
    print("[INFO] Press 'p' to pause, 'r' to resume, 'q' to quit.")
    while not stop_event.is_set():
        try:
            # Pause if 'p' is pressed
            if keyboard.is_pressed('p'):
                if not pause_event.is_set():
                    pause_event.set()
                    print("[INFO] Sniffer paused.")
            # Resume if 'r' is pressed
            elif keyboard.is_pressed('r'):
                if pause_event.is_set():
                    pause_event.clear()
                    print("[INFO] Sniffer resumed.")
            # Stop if 'q' is pressed
            elif keyboard.is_pressed('q'):
                stop_event.set()
                print("[INFO] Stopping sniffer...")
                break
        except KeyboardInterrupt:
            # Stop if KeyboardInterrupt is detected
            stop_event.set()
            print("\n[INFO] KeyboardInterrupt detected. Exiting...")
            break

# Run if executed directly
if __name__ == "__main__":
    main()
