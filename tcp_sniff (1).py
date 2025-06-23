from scapy.all import sniff, TCP, IP
def process_packet(packet):
    """
    Callback function to process each sniffed packet.
    Filters and displays TCP packets in the specified format.
    """
    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport

        print(f"[+] TCP Packet: {src_ip}:{src_port} ==>> {dst_ip}:{dst_port}")

def main():
 
    print("[*] Starting TCP packet sniffer... Press Ctrl + C to stop.")
    
    try:
        # Sniff packets indefinitely, filtering for TCP
        sniff(filter="tcp", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopping packet sniffer.")

if __name__ == "__main__":
    main()
