# D58_Final
The final project of CSCD58

## Authors
- Dhruvin Patel
- Vedat Goktepe
- Sohil Chanana

## Project Description and Goals
The Packet Sniffer project is a lightweight and interactive command-line tool designed to monitor network traffic in real time. It leverages the Scapy library to capture and analyze network packets, providing detailed insights into traffic patterns, protocol usage, and request-response latencies. 

### Goals
- Create a packet sniffer that supports customizable filters.
- Provide real-time statistics and analysis of captured packets.
- Offer users a detailed view of their network traffic while supporting advanced features like pausing, resuming, and stopping the capture along with optional filtering.

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
  pip install -r ./requirements.txt
  ```
### 2. **Run the Program**:
- Execute main.py with optional arguments for filters (example):
  ```bash
  python ./main.py --filter "tcp port 80" --src-ip "192.168.1.1" --dest-ip "192.168.1.2"
  ```

### 3. **User Controls**:
- Press Enter to start the sniffer.
- Press p to pause the sniffer.
- Press r to resume capturing packets.
- Press q to quit the application.

### 4. **Output**:
- The captured packets and statistics will be displayed in the console and saved in packet_sniffer_output.txt.

## Implementation Details and Documentation

### 1. Main Script (main.py):
- Handles user inputs, manages threading, and handles the sniffer and display components.

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
  - Integrated latency tracking for performance analysis along with pakcet size.
  - Rich visualizations for improved user interaction including a pause, resume and stop feature.

- Limitations:
  - Relies on Scapy, which might not be optimal for complex networks.
  - Limited IPv6 support in packet tracking.

- Potential Enhancements:
  - Add support for saving output in JSON/CSV format for advanced analysis.
  - Implement GUI visualization.

## Concluding Remarks and Lessons Learned

The Packet Sniffer project taught us valuable lessons in threading, real-time processing, and visualization. By tackling these challenges, this project not only demonstrated the principles of modular software engineering but also provided practical experience in developing a sophisticated networking tool.

### Lessons Learned:
- Building the Packet Sniffer Tool shed light on the importance of designing modular and maintainable code. By breaking the application into distinct components such as Display and Sniffer, we created a structure that not only simplifies debugging but also facilitates the addition of new features. For instance, implementing additional filtering options or expanding the packet analysis functionality can be done with minimal disruption to the existing codebase. This modular design ensures the tool can evolve as networking requirements become more complex.
- Developing the tool provided hands-on experience in handling low-level packet data. Reading raw network packets, parsing them into meaningful information, and presenting this data in a visually appealing format taught valuable skills in network protocol analysis. Implementing counters and statistics for packet types, sizes, and other attributes offered a deeper understanding of packet anatomy. It also emphasized the need for accuracy and clarity when processing and displaying technical data, as these features are crucial for a networking tool.
- One of the most valuable lessons was managing multi-threaded interactions to provide a responsive user experience. By separating the packet capturing and user input handling into different threads, the application maintained real-time performance without blocking the main execution flow. This experience highlighted the challenges of thread synchronization, such as coordinating pause and resume functionality using threading events. Implementing a robust and responsive interaction model for users not only improved the tool’s usability but also demonstrated the power of concurrency in real-world applications.
- The inclusion of Berkeley Packet Filter (BPF)-style syntax for dynamic packet filtering was an essential feature of the tool. Implementing this taught the significance of flexibility in filtering mechanisms, allowing users to refine their searches in real time using parameters like source IP, destination IP, or specific protocols (e.g., TCP/UDP). Integrating multiple filter rules seamlessly demonstrated the importance of combining user input validation with efficient backend logic to handle complex filtering scenarios.
- Providing intuitive feedback to users, such as messages indicating the tool’s status (e.g., "Sniffer paused," "Resuming sniffer"), improved the user experience significantly. This feature ensured users were constantly aware of the tool’s state and could control its operation confidently. Balancing real-time feedback with minimal disruption to the core functionality was a practical lesson in the design.
- Developing this tool deepened the understanding of fundamental networking concepts, such as packet capture mechanisms, protocol structures, and data transmission workflows. Parsing raw packet data offered hands-on exposure to protocols like TCP, UDP, and ICMP, while designing filters emphasized the importance of control in network traffic analysis. These lessons are invaluable for diagnosing and resolving networking issues in real life scenarios.