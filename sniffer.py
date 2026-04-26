from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def process_packet(packet):
    print("\n==============================")
    print("New Packet Captured")

    if packet.haslayer(IP):
        ip = packet[IP]
        print("Source IP      :", ip.src)
        print("Destination IP :", ip.dst)
        print("Protocol No    :", ip.proto)

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print("Protocol Type  : TCP")
        print("Source Port    :", tcp.sport)
        print("Destination Port:", tcp.dport)

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print("Protocol Type  : UDP")
        print("Source Port    :", udp.sport)
        print("Destination Port:", udp.dport)

    elif packet.haslayer(ICMP):
        print("Protocol Type  : ICMP")

    if packet.haslayer(Raw):
        payload = packet[Raw].load
        print("Payload (preview):", payload[:60])

def main():
    print("Network Sniffer Running...")
    print("Waiting for packets... Press Ctrl+C to stop\n")

    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()