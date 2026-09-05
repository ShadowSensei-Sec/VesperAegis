from app.logging.logger import FirewallLogger


def main():
    logger = FirewallLogger()

    print("=" * 60)
    print("Firewall Project - Logger Test")
    print("=" * 60)

    print("\n[+] Writing test firewall event...")

    logger.log_event(
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

    print("[+] Event written successfully.")

    print("\n[+] Reading firewall events...\n")

    events = logger.get_events()

    for event in events:
        print(event)


if __name__ == "__main__":
    main()