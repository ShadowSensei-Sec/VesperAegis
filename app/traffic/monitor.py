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

        if matched_rule:

            rule_action = matched_rule.get("action","unknown")

            rule_id = matched_rule.get("id")
            rule_name = matched_rule.get("name")
            rule_match = "matched"

        else:

            action = "no_match"
            rule_id = None
            rule_name = None
        action = "observed"

        self.event_service.record_packet_event(
            source_ip=metadata["source_ip"],
            source_port=metadata["source_port"],
            destination_ip=metadata["destination_ip"],
            destination_port=metadata["destination_port"],
            protocol=metadata["protocol"],
            interface=metadata["interface"],
            action=action,
            rule_id=rule_id,
            rule_name=rule_name,
            rule_match=rule_match,
            rule_decision="unknown",
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
            f"| FIREWALL DECISION: unknown"
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