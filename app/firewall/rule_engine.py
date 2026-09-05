class RuleEngine:

    def __init__(self, rules=None):
        self.rules = rules or []

    def set_rules(self, rules):
        self.rules = rules

    def match_packet(self, metadata):
        for rule in self.rules:

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
            if rule["protocol"].lower() != metadata["protocol"].lower():
                return False

        if rule.get("source_port"):
            if rule["source_port"] != metadata["source_port"]:
                return False

        if rule.get("destination_port"):
            if rule["destination_port"] != metadata["destination_port"]:
                return False

        return True