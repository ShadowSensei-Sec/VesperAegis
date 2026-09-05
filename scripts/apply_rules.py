from app.firewall.nftables import NftablesManager
from app.firewall.rule_parser import RuleParser, FirewallRule

from app.database.database import (
    get_firewall_rules,
    create_firewall_rule,
    update_firewall_rule_handle,
)

CONFIG_PATH = "config/firewall.yaml"

def bootstrap_database_from_yaml():
    print("\n[+] Bootstrapping database from YAML...")

    parser = RuleParser(CONFIG_PATH)
    yaml_rules = parser.parse_rules()

    existing_rules = get_firewall_rules()

    existing_names = {
        rule["name"]
        for rule in existing_rules
    }

    created = 0
    skipped = 0

    for rule in yaml_rules:

        if rule.name in existing_names:
            print(
                f"Skipping existing rule: {rule.name}"
            )
            skipped += 1
            continue

        rule_id = create_firewall_rule(rule)

        print(
            f"Added default rule: "
            f"{rule.name} "
            f"(database ID {rule_id})"
        )

        created += 1

    print(
        f"[+] Bootstrap complete: "
        f"{created} created, {skipped} skipped."
    )

def restore_database_rules(firewall):
    print("\n[+] Restoring rules from SQLite...")

    rules = sorted(
        get_firewall_rules(),
        key=lambda rule: rule.get("priority", 100)
    )

    restored = 0

    for rule in rules:

        if not rule["enabled"]:
            print(
                f"Skipping disabled rule {rule['id']}: "
                f"{rule['name']}"
            )
            continue

        firewall_rule = FirewallRule(
            id=rule["id"],
            name=rule["name"],
            action=rule["action"],
            protocol=rule["protocol"],
            source_ip=rule["source_ip"],
            source_port=rule["source_port"],
            destination_ip=rule["destination_ip"],
            destination_port=rule["destination_port"],
            interface=rule["interface"],
            direction=rule["direction"],
            enabled=True,
            description=rule["description"],
            priority=rule["priority"],
        )

        firewall_rule.validate()

        nft_handle = firewall.add_rule(
            firewall_rule,
            chain="forward"
        )

        update_firewall_rule_handle(
            rule["id"],
            nft_handle
        )

        print(
            f"Restored rule {rule['id']}: "
            f"{rule['name']} "
            f"(handle {nft_handle})"
        )

        restored += 1

    print(f"[+] Restored {restored} enabled database rule(s).")


def main():

    print("=" * 60)
    print("Firewall Project - Rule Deployment")
    print("=" * 60)

    firewall = NftablesManager()

    # ---------------------------------------------------------
    # 1. Initialize nftables table
    # ---------------------------------------------------------
    print("\n[1] Initializing nftables...")

    firewall.create_table()

    # ---------------------------------------------------------
    # 2. Clear old rules
    # ---------------------------------------------------------
    print("\n[2] Clearing existing managed rules...")

    firewall.flush()

    # ---------------------------------------------------------
    # 3. Create base chains
    # ---------------------------------------------------------
    print("\n[3] Creating firewall base chains...")

    firewall.create_base_chains()

    # ---------------------------------------------------------
    # 4. Configure forwarding foundation
    # ---------------------------------------------------------
    print("\n[4] Configuring forwarding policy...")

    # Allow traffic belonging to already-established connections
    firewall.add_stateful_forward_rules()

    # ---------------------------------------------------------
    # 5. Configure NAT
    # ---------------------------------------------------------
    print("\n[5] Configuring NAT...")

    firewall.configure_nat(
        wan_interface="enp0s3"
    )

       # ---------------------------------------------------------
    # 6. Restore persistent database rules
    # ---------------------------------------------------------
    print("\n[6] Restoring persistent firewall rules...")

    restore_database_rules(firewall)

    # ---------------------------------------------------------
    # 7. Display active configuration
    # ---------------------------------------------------------
    print("\n[7] Active firewall configuration:")

    # ---------------------------------------------------------
    # 8. Display active configuration
    # ---------------------------------------------------------
    print("\n[8] Active firewall configuration:")

    print(firewall.get_ruleset())

    print("\nRules deployed successfully.")


if __name__ == "__main__":
    main()