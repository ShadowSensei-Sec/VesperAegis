from app.logging.event_service import FirewallEventService


def main():
    service = FirewallEventService()

    print("=" * 60)
    print("Firewall Project - Event Service Test")
    print("=" * 60)

    print("\n[+] Recording firewall event...")

    service.record_packet_event(
        source_ip="192.168.50.10",
        source_port=54321,
        destination_ip="192.168.50.20",
        destination_port=23,
        protocol="tcp",
        interface="enp0s8",
        action="deny",
        rule_id=1,
        rule_name="Block Telnet",
        packets=1,
        bytes_count=60,
    )

    print("[+] Event recorded successfully.")

    print("\n[+] Test completed successfully.")


if __name__ == "__main__":
    main()