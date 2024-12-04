# D58_Final
The final project of CSCD58

## Authors
- Dhruvin Patel
- Vedat Goktepe
- Sohil Chanana

## Project Description and Goals
The Packet Sniffer project is a lightweight and interactive command-line tool designed to monitor network traffic in real time. It leverages the Scapy library to capture and analyze network packets, providing detailed insights into traffic patterns, protocol usage, and request-response latencies. 

### Goals
- Create a robust, user-friendly packet sniffer that supports customizable filters.
- Provide real-time statistics and analysis of captured packets.
- Offer users a detailed view of their network traffic while supporting advanced features like pausing, resuming, and stopping the capture.

---

## Team Member Contributions
**Dhruvin**:
  - Designed the `main.py` file for command-line argument parsing and threading to manage packet capturing and user inputs.
  - Implemented user interaction for pausing, resuming, and stopping the sniffer.

**Vedat**:  
  - Developed the `sniffer.py` module to handle the core packet-sniffing functionality using Scapy's `AsyncSniffer`.
  - Implemented logging utilities in `utils.py` for debugging and event tracking.

**Sohil**:
  - Created the `display.py` module for rich-text visualization of packets using the Rich library.
  - Added methods for protocol statistics and request-response latency tracking.

---

## How to Run and Test the Implementation
### 1. **Setup Environment**:
- Install the required libraries contained in `requirements.txt`:
  - `scapy`, `rich`, and `keyboard`.
- Use Python 3.8+.

  ```bash
  pip install scapy rich keyboard
  ```
### 2. **Run the Program**:
- Execute main.py with optional arguments for filters:
  ```bash
  python main.py --filter "tcp port 80" --src-ip "192.168.1.1" --dest-ip "192.168.1.2"
  ```

### 3. **User Controls**:
- Press p to pause the sniffer.
- Press r to resume capturing packets.
- Press q to quit the application.

### 4. **Output**:
- The captured packets and statistics will be displayed in the console and saved in packet_sniffer_output.txt.

## Implementation Details and Documentation

### 1. Main Script (main.py):
- Handles user inputs, manages threading, and orchestrates the sniffer and display components.

### 2. Sniffer Module (sniffer.py):
- Captures packets using Scapy's AsyncSniffer.
- Tracks protocol statistics (TCP, UDP, ICMP, etc.) and measures request-response latencies.

### 3. Display Module (display.py):
- Visualizes packets and statistics using rich tables.
- Logs data to a text file for later review.

### 4. Utils Module (utils.py):
- Provides utilities such as a logging setup for debugging and tracking events.

## Analysis and Discussion

- Strengths:
  - Real-time packet capturing with customizable filters enhances usability.
  - Integrated latency tracking for performance analysis.
  - Rich visualizations for improved user interaction.

- Limitations:
  - Relies on Scapy, which might not be optimal for high-performance networks.
  - Limited IPv6 support in packet tracking.

- Potential Enhancements:
  - Add support for saving output in JSON/CSV format for advanced analysis.
  - Implement GUI-based visualization.

## Concluding Remarks and Lessons Learned

The Packet Sniffer project taught us valuable lessons in threading, real-time processing, and visualization.

### Lessons Learned:
- Design modular and maintainable code for scalability.
- Optimize real-time packet processing and reduce latency.
- Handle multi-threaded interactions for responsive user input.