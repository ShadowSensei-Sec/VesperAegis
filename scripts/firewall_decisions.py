from app.firewall.nftables import NftablesManager


def main():
    firewall = NftablesManager()

    print("=" * 60)
    print("Firewall Project - nftables Decision Telemetry")
    print("=" * 60)

    rules = firewall.get_forward_rule_details()

    if not rules:
        print("\n[!] No forwarding rules found.")
        return

    print("\n[+] Current FORWARD rules:\n")

    for rule in rules:
        print(f"Handle  : {rule['handle']}")
        print(f"Action  : {rule['action']}")
        print(f"Packets : {rule['packets']}")
        print(f"Bytes   : {rule['bytes']}")
        print(f"Rule    : {rule['rule']}")
        print("-" * 60)


if __name__ == "__main__":
    main()