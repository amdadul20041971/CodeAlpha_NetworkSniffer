from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

TARGET_IP = input("Enter IP to filter: ")

def process_packet(packet):

    if packet.haslayer(IP):
        ip = packet[IP]

        # filter logic
        if ip.src == TARGET_IP or ip.dst == TARGET_IP:

            print("\n" + "="*50)
            print("FILTERED PACKET")
            print("="*50)

            # IP INFO
            print("Source IP      :", ip.src)
            print("Destination IP :", ip.dst)

            # PROTOCOL INFO
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                print("Protocol       : TCP")
                print("Source Port    :", tcp.sport)
                print("Destination Port:", tcp.dport)

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                print("Protocol       : UDP")
                print("Source Port    :", udp.sport)
                print("Destination Port:", udp.dport)

            elif packet.haslayer(ICMP):
                print("Protocol       : ICMP")

            else:
                print("Protocol       :", ip.proto)

            # PAYLOAD
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                print("Payload        :", payload[:60])
            else:
                print("Payload        : No readable data")

print("Sniffer started... waiting for packets")
sniff(prn=process_packet, store=False)