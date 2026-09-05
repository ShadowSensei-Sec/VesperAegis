from app.firewall.nftables import NftablesManager


WAN_INTERFACE = "enp0s3"
LAN_INTERFACE = "enp0s8"


def main():

    firewall = NftablesManager()

    print("=" * 60)
    print("Firewall Project - Network Firewall Configuration")
    print("=" * 60)

    print("\n[1] Creating firewall table...")
    firewall.create_table()

    print("\n[2] Creating base chains...")
    firewall.create_base_chains()

    print("\n[3] Configuring FORWARD policy...")
    firewall.set_forward_policy("drop")

    print("\n[4] Allowing established/related traffic...")
    firewall.add_stateful_forward_rules()

    print("\n[5] Allowing LAN-originated traffic...")
    firewall.add_lan_forward_rule(LAN_INTERFACE)

    print("\n[6] Configuring NAT...")
    firewall.configure_nat(WAN_INTERFACE)

    print("\n[7] Active firewall configuration:")
    print(firewall.get_ruleset())

    print("\nNetwork firewall configured successfully.")


if __name__ == "__main__":
    main()