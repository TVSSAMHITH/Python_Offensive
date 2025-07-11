from scapy.all import *
import argparse
def packet_capture(packet):
    print("\n" + "=" * 60)
    print(f"[Packet Captured at {time.strftime('%H:%M:%S')}]")
    print("-" * 60)

    layer_index = 0
    layer = packet

    try:
        while layer:
            print(f"[Layer {layer_index}] {layer.name}")
            for field_name, field_value in layer.fields.items():
                print(f"   ├─ {field_name}: {field_value}")
            if layer.payload:
                layer = layer.payload
                layer_index += 1
            else:
                break
    except Exception as e:
        print(f"[!] Error parsing packet: {e}")
    print("=" * 60)


if __name__=="__main__":
    try:
        parser = argparse.ArgumentParser(description="Simple Packet Sniffer")

        parser.add_argument('--iface', type=str, help='Network interface to sniff on', required=False,default=conf.iface)
        parser.add_argument('--count', type=int, help='Number of packets to capture (0 = infinite)', default=0)
        parser.add_argument('--filter', type=str, help='BPF filter expression (e.g., "tcp", "udp port 53")', required=False,default="tcp")
        args = parser.parse_args()
        sniff(prn=packet_capture,iface=args.iface,count=args.count,filter=args.filter)
    except:
        print("[+] Use python sniffer.py --help to usage[+]")



