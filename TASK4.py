def packet_callback(packet):
    """Callback function to process captured packets."""

    print(f"Packet captured at {packet.time}")

    # Get basic packet details
    source_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else None
    dest_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else None
    protocol = packet.proto if packet.haslayer(scapy.IP) else None

    # Get the payload data if present
    payload = packet.payload if packet.haslayer(scapy.Raw) else None

    # Print details of the packet
    print(f"Source IP: {source_ip}")
    print(f"Destination IP: {dest_ip}")

    if protocol:
        print(f"Protocol: {scapy.getprotobynumber(protocol)}")  # Convert protocol number to name
    else:
        print("Protocol: N/A")

    if payload:
        print(f"Payload: {bytes(payload)}")  # Show raw payload (bytes)
    print("-" * 50)


def start_sniffer(interface="eth0", packet_count=10):
    """Starts the packet sniffer on a given interface for a specified packet count."""

    print(f"Starting packet sniffer on {interface}...")

    # Capture the packets using Scapy
    scapy.sniff(iface=interface, prn=packet_callback, count=packet_count, store=0)


if __name__ == "__main__":
    # Specify the network interface to listen on
    network_interface = "eth0"  # Replace with your actual network interface (e.g., "wlan0" for Wi-Fi)

    # Start sniffing for 10 packets (you can increase this number as needed)
    start_sniffer(interface=network_interface, packet_count=10)
