from app.traffic.statistics import TrafficStatistics


def main():
    statistics = TrafficStatistics()

    print("=" * 60)
    print("Firewall Project - Traffic Statistics")
    print("=" * 60)

    data = statistics.get_forward_statistics()

    print("\n[+] Forwarding Statistics\n")

    print(f"Total Packets    : {data['total_packets']}")
    print(f"Total Bytes      : {data['total_bytes']}")
    print(f"Accepted Packets : {data['accepted_packets']}")
    print(f"Dropped Packets  : {data['dropped_packets']}")

    print("\n[+] Rule Statistics\n")

    for rule in data["rules"]:
        print(
            f"{rule['action']:>6} | "
            f"Packets: {rule['packets']:<6} | "
            f"Bytes: {rule['bytes']}"
        )


if __name__ == "__main__":
    main()