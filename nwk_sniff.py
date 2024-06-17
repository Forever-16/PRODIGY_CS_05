from scapy.all import sniff, IP, TCP, UDP

def pckt(packet):
    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst
        protocol = packet[IP].proto
        print(f"IP: {source} ---> {destination} ; protocol({protocol})")
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"  TCP: {src_port} ---> {dst_port} ")

        if UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"  UDP: {src_port} ---> {dst_port} ")
        
        if packet[IP].payload:
            try:
                payload = bytes(packet[IP].payload).decode(encoding='utf-8', errors='ignore')
                print(f"  Payload: {payload}")
            except UnicodeDecodeError:
                print("  Payload: (binary data)")

print("Starting packet sniffing on Ethernet interface...")
sniff(iface="{02E6E112-821C-4E4E-B30E-8C4A724AE80F}", prn=pckt, store=0)