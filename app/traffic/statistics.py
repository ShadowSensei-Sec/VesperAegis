from app.firewall.nftables import NftablesManager
from app.database.database import get_connection


class TrafficStatistics:

    def __init__(self):
        self.firewall = NftablesManager()

    def get_forward_statistics(self):
        counters = self.firewall.get_rule_counters()

        total_packets = 0
        total_bytes = 0
        accepted_packets = 0
        dropped_packets = 0

        for counter in counters:
            packets = counter["packets"]
            bytes_count = counter["bytes"]

            total_packets += packets
            total_bytes += bytes_count

            if counter["action"] == "accept":
                accepted_packets += packets

            elif counter["action"] == "drop":
                dropped_packets += packets

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "accepted_packets": accepted_packets,
            "dropped_packets": dropped_packets,
            "rules": counters,
        }

    def get_rule_statistics(self):
        counters = self.firewall.get_rule_counters()

        rules = []
        allow_packets = 0
        allow_bytes = 0
        drop_packets = 0
        drop_bytes = 0

        for counter in counters:
            packets = counter.get("packets", 0)
            bytes_count = counter.get("bytes", 0)
            action = counter.get("action", "unknown")

            rule = {
                "rule": counter.get("rule"),
                "action": action,
                "packets": packets,
                "bytes": bytes_count,
                "handle": counter.get("handle"),
            }

            rules.append(rule)

            if action == "accept":
                allow_packets += packets
                allow_bytes += bytes_count

            elif action == "drop":
                drop_packets += packets
                drop_bytes += bytes_count

        most_used_rules = sorted(
            rules,
            key=lambda rule: rule["packets"],
            reverse=True,
        )

        zero_hit_rules = [
            rule for rule in rules
            if rule["packets"] == 0
        ]

        return {
            "rules": rules,
            "most_used_rules": most_used_rules,
            "zero_hit_rules": zero_hit_rules,
            "allow": {
                "packets": allow_packets,
                "bytes": allow_bytes,
            },
            "drop": {
                "packets": drop_packets,
                "bytes": drop_bytes,
            },
        }

    def get_time_statistics(self):
        events = self._get_events()

        hourly = {}

        for event in events:
            timestamp = event.get("timestamp")

            if not timestamp:
                continue

            hour = str(timestamp)[:13]

            packets = event.get("packets") or 0
            bytes_count = event.get("bytes") or 0
            action = event.get("action") or "unknown"

            if hour not in hourly:
                hourly[hour] = {
                    "packets": 0,
                    "bytes": 0,
                    "allowed_packets": 0,
                    "dropped_packets": 0,
                }

            hourly[hour]["packets"] += packets
            hourly[hour]["bytes"] += bytes_count

            if action == "allow":
                hourly[hour]["allowed_packets"] += packets

            elif action == "deny":
                hourly[hour]["dropped_packets"] += packets

            elif action == "drop":
                hourly[hour]["dropped_packets"] += packets

        return hourly

    def _get_events(self):
        connection = get_connection()

        try:
            rows = connection.execute(
                """
                SELECT *
                FROM firewall_events
                ORDER BY timestamp DESC
                """
            ).fetchall()

            return [dict(row) for row in rows]

        finally:
            connection.close()

    def get_protocol_statistics(self):
        events = self._get_events()

        protocols = {}

        for event in events:
            protocol = event.get("protocol") or "unknown"
            packets = event.get("packets") or 0
            bytes_count = event.get("bytes") or 0

            if protocol not in protocols:
                protocols[protocol] = {
                    "packets": 0,
                    "bytes": 0,
                }

            protocols[protocol]["packets"] += packets
            protocols[protocol]["bytes"] += bytes_count

        return protocols

    def get_ip_statistics(self):
        events = self._get_events()

        source_ips = {}
        destination_ips = {}

        for event in events:
            packets = event.get("packets") or 0
            bytes_count = event.get("bytes") or 0

            source_ip = event.get("source_ip")
            destination_ip = event.get("destination_ip")

            if source_ip:
                if source_ip not in source_ips:
                    source_ips[source_ip] = {
                        "packets": 0,
                        "bytes": 0,
                    }

                source_ips[source_ip]["packets"] += packets
                source_ips[source_ip]["bytes"] += bytes_count

            if destination_ip:
                if destination_ip not in destination_ips:
                    destination_ips[destination_ip] = {
                        "packets": 0,
                        "bytes": 0,
                    }

                destination_ips[destination_ip]["packets"] += packets
                destination_ips[destination_ip]["bytes"] += bytes_count

        return {
            "source_ips": source_ips,
            "destination_ips": destination_ips,
        }

    def get_port_statistics(self):
        events = self._get_events()

        source_ports = {}
        destination_ports = {}

        for event in events:
            packets = event.get("packets") or 0
            bytes_count = event.get("bytes") or 0

            source_port = event.get("source_port")
            destination_port = event.get("destination_port")

            if source_port is not None:
                source_port = str(source_port)

                if source_port not in source_ports:
                    source_ports[source_port] = {
                        "packets": 0,
                        "bytes": 0,
                    }

                source_ports[source_port]["packets"] += packets
                source_ports[source_port]["bytes"] += bytes_count

            if destination_port is not None:
                destination_port = str(destination_port)

                if destination_port not in destination_ports:
                    destination_ports[destination_port] = {
                        "packets": 0,
                        "bytes": 0,
                    }

                destination_ports[destination_port]["packets"] += packets
                destination_ports[destination_port]["bytes"] += bytes_count

        return {
            "source_ports": source_ports,
            "destination_ports": destination_ports,
        }