from app.firewall.packet_inspector import PacketInspector
from app.firewall.policy_manager import PolicyManager
from app.firewall.rule_engine import RuleEngine
from app.logging.event_service import FirewallEventService


class TrafficMonitor:

    def __init__(self, interface):
        self.interface = interface

        self.inspector = PacketInspector(
            interface=interface
        )

        self.event_service = FirewallEventService()

        self.policy_manager = PolicyManager()

        self.rule_engine = RuleEngine(
            self.policy_manager.load_rules()
        )

    def process_packet(self, packet):

        metadata = self.inspector.inspect_packet(packet)

        if metadata is None:
            return

        matched_rule = self.rule_engine.match_packet(
            metadata
        )

        # ================================
        # DEFAULT DECISION
        # ================================

        rule_match = "not_matched"
        rule_id = None
        rule_name = None
        rule_action = "no_match"

        # ================================
        # RULE MATCH
        # ================================

        if matched_rule:

            rule_match = "matched"

            rule_id = matched_rule.get("id")
            rule_name = matched_rule.get("name")

            rule_action = matched_rule.get(
                "action",
                "unknown"
            )

        # ================================
        # FIREWALL DECISION
        # ================================

        if rule_action == "allow":
            rule_decision = "allow"

        elif rule_action == "deny":
            rule_decision = "deny"

        else:
            rule_decision = "no_match"

        # ================================
        # RECORD EVENT
        # ================================

        self.event_service.record_packet_event(
            source_ip=metadata["source_ip"],
            source_port=metadata["source_port"],
            destination_ip=metadata["destination_ip"],
            destination_port=metadata["destination_port"],
            protocol=metadata["protocol"],
            interface=metadata["interface"],
            action=rule_action,
            rule_id=rule_id,
            rule_name=rule_name,
            rule_match=rule_match,
            rule_decision=rule_decision,
            packets=1,
            bytes_count=metadata["packet_size"],
        )

        print(
            f"[PACKET] "
            f"{metadata['source_ip']}:{metadata['source_port']} "
            f"→ "
            f"{metadata['destination_ip']}:{metadata['destination_port']} "
            f"{metadata['protocol']} "
            f"| MATCH: {rule_match} "
            f"| RULE ACTION: {rule_action} "
            f"| FIREWALL DECISION: {rule_decision}"
        )

    def start(self):

        print(
            f"[+] Starting traffic monitor on "
            f"{self.interface}"
        )

        print("[+] Continuous monitoring enabled.")
        print("[+] Rule correlation enabled.")
        print("[+] Press Ctrl+C to stop.\n")

        self.inspector.capture_continuously(
            callback=self.process_packet
        )