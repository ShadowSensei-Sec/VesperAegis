from app.firewall.nftables import NftablesManager


def main():
    firewall = NftablesManager()

    print("=" * 60)
    print("Firewall Project - Forwarding Counters")
    print("=" * 60)

    print("\n[+] Current FORWARD chain:\n")

    print(firewall.get_forward_counters())


if __name__ == "__main__":
    main()