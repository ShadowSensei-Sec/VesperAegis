class RuleEngine:

    def __init__(self, rules=None):
        self.rules = []
        self.set_rules(rules or [])

    def set_rules(self, rules):
        # Firewall evaluation uses priority.
        # Lower priority number = evaluated first.
        self.rules = sorted(
            rules,
            key=lambda rule: rule.get("priority", 100)
        )

    def match_packet(self, metadata):
        for rule in self.rules:

            if not rule.get("enabled", True):
                continue

            if not self._matches(rule, metadata):
                continue

            return rule

        return None

    def _matches(self, rule, metadata):

        if rule.get("source_ip"):
            if rule["source_ip"] != metadata["source_ip"]:
                return False

        if rule.get("destination_ip"):
            if rule["destination_ip"] != metadata["destination_ip"]:
                return False

        if rule.get("protocol"):
            protocol = rule["protocol"].lower()

            if protocol != "any":
                if protocol != metadata["protocol"].lower():
                    return False

        if rule.get("source_port"):
            if rule["source_port"] != metadata["source_port"]:
                return False

        if rule.get("destination_port"):
            if rule["destination_port"] != metadata["destination_port"]:
                return False

        return True