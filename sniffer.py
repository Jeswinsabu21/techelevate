from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        proto_name = {6: 'TCP', 17: 'UDP'}.get(proto, 'Other')

        print(f"\n[+] Packet: {proto_name}")
        print(f"    Source IP: {ip_src}")
        print(f"    Dest IP:   {ip_dst}")

        # Check if it's TCP or UDP to extract ports
        if proto == 6 and TCP in packet:
            print(f"    Src Port:  {packet[TCP].sport}")
            print(f"    Dst Port:  {packet[TCP].dport}")
        elif proto == 17 and UDP in packet:
            print(f"    Src Port:  {packet[UDP].sport}")
            print(f"    Dst Port:  {packet[UDP].dport}")

# Start sniffing (you might need sudo/root access)
print("Starting packet capture... (Press Ctrl+C to stop)")
sniff(prn=packet_callback, store=0)
