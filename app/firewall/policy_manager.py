from pathlib import Path

import yaml


class PolicyManager:

    def __init__(self, config_path="config/firewall.yaml"):
        self.config_path = Path(config_path)

    def _load_config(self):
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Firewall configuration not found: {self.config_path}"
            )

        with open(self.config_path, "r", encoding="utf-8") as file:
            return yaml.safe_load(file) or {}

    def load_rules(self):
        config = self._load_config()

        return config.get("rules", [])

    def load_interfaces(self):
        config = self._load_config()

        return config.get("firewall", {}).get("interfaces", {})

    def get_rule(self, rule_id):
        rules = self.load_rules()

        for rule in rules:
            if rule.get("id") == rule_id:
                return rule

        return None