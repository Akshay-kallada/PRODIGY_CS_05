from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    # Check if IP layer exists
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        # Protocol mapping
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        proto_name = proto_map.get(proto, str(proto))

        print(f"\n[+] Packet: {proto_name}")
        print(f"    Source IP:      {src_ip}")
        print(f"    Destination IP: {dst_ip}")

        if Raw in packet:
            payload = packet[Raw].load
            try:
                print("    Payload:")
                print(payload.decode('utf-8', errors='replace'))
            except:
                print("    Payload: <binary data>")
        else:
            print("    No Payload.")

def start_sniffer(interface=None):
    print(f"[*] Starting packet sniffer on interface: {interface or 'default'}")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Educational Packet Sniffer Tool")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g., eth0, wlan0)")
    args = parser.parse_args()

    try:
        start_sniffer(interface=args.interface)
    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped by user.")
    except PermissionError:
        print("[!] You need to run this script as root/admin.")