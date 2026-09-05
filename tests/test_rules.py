from app.firewall.rule_parser import RuleParser


def main():

    parser = RuleParser("config/firewall.yaml")

    rules = parser.parse_rules()

    print("=" * 60)
    print("Firewall Rule Parser Test")
    print("=" * 60)

    print(f"\nLoaded rules: {len(rules)}")

    for rule in rules:

        print("\nRule")
        print("-" * 40)

        print(f"ID:              {rule.id}")
        print(f"Name:            {rule.name}")
        print(f"Action:          {rule.action}")
        print(f"Protocol:        {rule.protocol}")

        print(f"Source IP:       {rule.source_ip}")
        print(f"Source Port:     {rule.source_port}")

        print(f"Destination IP:  {rule.destination_ip}")
        print(f"Destination Port: {rule.destination_port}")

        print(f"Enabled:         {rule.enabled}")


if __name__ == "__main__":
    main()