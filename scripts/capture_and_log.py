from app.firewall.packet_inspector import PacketInspector
from app.logging.event_service import FirewallEventService


def main():
    interface = "enp0s8"

    inspector = PacketInspector(interface=interface)
    event_service = FirewallEventService()

    print("=" * 60)
    print("Firewall Project - Packet Capture & Event Logging")
    print("=" * 60)

    print(f"\n[+] Monitoring interface: {interface}")
    print("[+] Capturing 10 IP packets...")
    print("[+] Press Ctrl+C to stop.\n")

    packets = inspector.capture(packet_count=10)

    for packet in packets:
        metadata = inspector.inspect_packet(packet)

        if metadata is None:
            continue

        event_service.record_packet(
            metadata,
            action="observed"
        )

        print(
            f"{metadata['source_ip']}:{metadata['source_port']} "
            f"→ "
            f"{metadata['destination_ip']}:{metadata['destination_port']} "
            f"{metadata['protocol']} "
            f"({metadata['packet_size']} bytes)"
        )

    print("\n[+] Capture completed.")
    print("[+] Events written to SQLite.")


if __name__ == "__main__":
    main()