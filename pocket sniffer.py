from scapy.all import sniff, IP, TCP, UDP, Raw

def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        # Identify protocol
        protocol = {6: "TCP", 17: "UDP"}.get(proto, "Other")

        print(f"\n📦 Packet Captured:")
        print(f"   ➤ Source IP      : {src_ip}")
        print(f"   ➤ Destination IP : {dst_ip}")
        print(f"   ➤ Protocol       : {protocol}")

        # Display payload if available
        if Raw in packet:
            payload = packet[Raw].load
            try:
                print(f"   ➤ Payload        : {payload.decode(errors='ignore')}")
            except:
                print(f"   ➤ Payload        : <Binary Data>")

def main():
    print("=== 🧪 Pocket Sniffer Tool (Educational Use Only) ===")
    print("⏳ Capturing packets... Press Ctrl+C to stop.\n")
    sniff(prn=analyze_packet, store=False)

if __name__ == "__main__":
    main()