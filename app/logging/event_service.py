from app.logging.logger import FirewallLogger


class FirewallEventService:

    def __init__(self):
        self.logger = FirewallLogger()

    def record_packet_event(
        self,
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
        interface,
        action,
        rule_id=None,
        rule_name=None,
        rule_match=None,
        rule_decision=None,
        packets=1,
        bytes_count=0,
    ):
        self.logger.log_event(
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol=protocol,
            interface=interface,
            action=action,
            rule_id=rule_id,
            rule_name=rule_name,
            rule_match=rule_match,
            rule_decision=rule_decision,
            packets=packets,
            bytes_count=bytes_count,
        )

    def record_packet(self, metadata, action="observed"):
        if metadata is None:
            return

        self.record_packet_event(
            source_ip=metadata.get("source_ip"),
            source_port=metadata.get("source_port"),
            destination_ip=metadata.get("destination_ip"),
            destination_port=metadata.get("destination_port"),
            protocol=metadata.get("protocol"),
            interface=metadata.get("interface"),
            action=action,
            packets=1,
            bytes_count=metadata.get("packet_size", 0),
        )