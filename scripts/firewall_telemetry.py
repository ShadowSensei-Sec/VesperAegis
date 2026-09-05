from app.firewall.nftables import NftablesManager


def main():
    firewall = NftablesManager()

    print("=" * 60)
    print("Firewall Project - Firewall Telemetry")
    print("=" * 60)

    print("\n[+] Reading nftables rule counters...\n")

    counters = firewall.get_rule_counters()

    if not counters:
        print("[!] No counters found.")
        return

    for index, counter in enumerate(counters, start=1):
        print(f"Rule {index}")
        print(f"Action  : {counter['action']}")
        print(f"Packets : {counter['packets']}")
        print(f"Bytes   : {counter['bytes']}")
        print(f"Rule    : {counter['rule']}")
        print("-" * 60)


if __name__ == "__main__":
    main()