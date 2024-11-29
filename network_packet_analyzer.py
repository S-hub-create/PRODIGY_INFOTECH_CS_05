from scapy.all import sniff, IP, TCP, UDP, Raw

# Counter for the total packets captured
packet_count = 0

def packet_callback(packet):
    global packet_count
    packet_count += 1
    
    # Print packet count details
    print(f"Captured Packets: {packet_count}")
    print("-" * 50)
    
    # Extract IP details
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
    
    # Extract protocol details
    if TCP in packet:
        print("Protocol: TCP")
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
    elif UDP in packet:
        print("Protocol: UDP")
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")
    else:
        print("Protocol: Other")
    
    # Extract payload data
    if Raw in packet:
        print("Payload:")
        print(packet[Raw].load.decode(errors="ignore"))
    
    # Stop sniffing after reaching the user-defined number of packets
    if packet_count >= total_packets:
        print("Captured the desired number of packets. Stopping...")
        return True  # Stops the sniffing

# Start sniffing packets
def start_sniffer(num_packets=10):
    global total_packets
    total_packets = num_packets
    print(f"Starting packet sniffer... (Capturing {total_packets} packets)")
    sniff(prn=packet_callback, store=False, count=num_packets)

if __name__ == "__main__":
    try:
        num_packets = int(input("Enter the number of packets to capture: "))
        start_sniffer(num_packets)
    except KeyboardInterrupt:
        print("\nPacket sniffer stopped.")
