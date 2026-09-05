from app.firewall.nftables import NftablesManager


def main():
    firewall = NftablesManager()

    print("=" * 60)
    print("nftables Initialization")
    print("=" * 60)

    print("\n[1] Checking nftables...")
    print(firewall.version())

    print("\n[2] Creating firewall table...")
    firewall.create_table()

    print("\n[3] Creating base chains...")
    firewall.create_base_chains()

    print("\n[4] Current firewall configuration:")
    print(firewall.get_ruleset())

    print("\nFirewall foundation initialized successfully.")


if __name__ == "__main__":
    main()