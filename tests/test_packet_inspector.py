from app.firewall.packet_inspector import PacketInspector


def main():
    interface = "enp0s8"

    inspector = PacketInspector(interface=interface)

    print("=" * 60)
    print("Firewall Project - Packet Inspector Test")
    print("=" * 60)

    print(f"\n[+] Listening on interface: {interface}")
    print("[+] Filtering traffic from Kali: 192.168.50.10")
    print("[+] Waiting for 5 packets...\n")

    packets = inspector.capture(
        packet_count=5,
        packet_filter="src host 192.168.50.10"
    )

    for index, packet in enumerate(packets, start=1):
        metadata = inspector.inspect_packet(packet)

        if metadata is None:
            continue

        print(f"Packet {index}")
        print(f"Source IP       : {metadata['source_ip']}")
        print(f"Source Port     : {metadata['source_port']}")
        print(f"Destination IP  : {metadata['destination_ip']}")
        print(f"Destination Port: {metadata['destination_port']}")
        print(f"Protocol        : {metadata['protocol']}")
        print(f"Packet Size     : {metadata['packet_size']}")
        print(f"Interface       : {metadata['interface']}")
        print("-" * 60)


if __name__ == "__main__":
    main()