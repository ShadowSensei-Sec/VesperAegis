from pathlib import Path

import yaml


class PolicyManager:

    def __init__(self, config_path="config/firewall.yaml"):
        self.config_path = Path(config_path)

    def load_rules(self):
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Firewall configuration not found: {self.config_path}"
            )

        with open(self.config_path, "r") as file:
            config = yaml.safe_load(file)

        return config.get("rules", [])

    def get_rule(self, rule_id):
        rules = self.load_rules()

        for rule in rules:
            if rule.get("id") == rule_id:
                return rule

        return None