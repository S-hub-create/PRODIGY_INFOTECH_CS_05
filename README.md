# Packet Sniffer using Python

# Network Packet Analyzer

A network packet analyzer, also known as a packet sniffer, is a tool used to capture, analyze, and decode data packets traveling across a network. It helps network administrators and security professionals monitor network traffic, troubleshoot issues, and detect malicious activities. Popular network packet analyzers include Wireshark, tcpdump, and NetworkMiner.

## How It Works

### Packet Capture
Network packet analyzers capture data packets in real-time by placing the network interface into promiscuous mode. This allows the analyzer to intercept and log all traffic passing over the network, regardless of its intended destination. The captured packets are then stored for further analysis.

### Packet Analysis
Once the packets are captured, the analyzer decodes and inspects the contents of each packet. This involves examining the packet headers and payloads to extract useful information such as source and destination IP addresses, protocol types, and data content. The analyzer can also reassemble fragmented packets to provide a complete view of the transmitted data.

### Data Visualization
Network packet analyzers often include features for visualizing the captured data. This can involve generating graphs, charts, and tables to represent network traffic patterns, identify anomalies, and highlight potential security threats. These visualizations help users quickly understand the network's behavior and pinpoint issues.

## How It Helps in Security

### Packet Capture and Analysis
Network packet analyzers capture data packets in real-time, allowing users to inspect the contents of each packet. This detailed analysis helps identify network performance issues, such as latency and packet loss, and detect anomalies that may indicate security threats. By examining packet headers and payloads, users can gain insights into the source and destination of traffic, protocols used, and potential vulnerabilities.

### Enhanced Network Security
By providing visibility into network traffic, packet analyzers help detect and prevent cyberattacks. They can identify suspicious activities, such as unauthorized access attempts, data exfiltration, and malware communication. Network administrators can use this information to implement security measures, such as blocking malicious IP addresses, updating firewall rules, and improving intrusion detection systems. Overall, network packet analyzers play a crucial role in maintaining the security and integrity of networked systems.

## Steps for execution

### Install python on any linux based system like "Kali Linux".
### To install python on kali linux use command
1. sudo apt update
2. sudo apt install python3 -scapy
### Open a text editor to create the script file. Use 'nano' or any other text editor available in Kali Linux
3. nano packet_sniffer.py
### write Caesar Cipher program code in text editor.
### Save the file 
4. Press 'CTRL+O' to save.
5. Hit 'Enter' to confirm the file name.
6. Press 'CTRL+X' to exit the editor.
### Run the code/script
7. sudo python3 packet_sniffer.py
### Use the program
8. Enter number of packets to be captured
9. The packets will be captured.
10. Each packet captured displays information like Protocol used, Source Ip, Destination IP, Source Port and Destination port.
### This is how Network Packet Analyzer works. 
