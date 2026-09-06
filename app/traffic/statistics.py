from datetime import datetime, timedelta

from app.firewall.nftables import NftablesManager
from app.database.database import get_connection


class TrafficStatistics:

    VALID_RANGES = {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }

    def __init__(self):
        self.firewall = NftablesManager()

    # =========================================================
    # TIME RANGE
    # =========================================================

    def _get_range_start(self, time_range):
        if time_range not in self.VALID_RANGES:
            time_range = "1h"

        return datetime.utcnow() - self.VALID_RANGES[time_range]

    def _get_events(self, time_range="1h"):
        connection = get_connection()

        try:
            range_start = self._get_range_start(time_range)

            rows = connection.execute(
                """
                SELECT *
                FROM firewall_events
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
                """,
                (
                    range_start.strftime("%Y-%m-%d %H:%M:%S"),
                ),
            ).fetchall()

            return [dict(row) for row in rows]

        finally:
            connection.close()

    # =========================================================
    # FORWARD STATISTICS
    # =========================================================

    def get_forward_statistics(self, time_range="1h"):
        events = self._get_events(time_range)

        total_packets = 0
        total_bytes = 0
        accepted_packets = 0
        dropped_packets = 0

        for event in events:

            packets = event.get("packets") or 0
            bytes_count = event.get("bytes") or 0
            action = event.get("action") or ""

            total_packets += packets
            total_bytes += bytes_count

            if action == "allow":
                accepted_packets += packets

            elif action in ("deny", "drop"):
                dropped_packets += packets

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "accepted_packets": accepted_packets,
            "dropped_packets": dropped_packets,
        }

    # =========================================================
    # PROTOCOL STATISTICS
    # =========================================================

    def get_protocol_statistics(self, time_range="1h"):
        events = self._get_events(time_range)

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

    # =========================================================
    # TIME STATISTICS
    # =========================================================

    def get_time_statistics(self, time_range="1h"):
        events = self._get_events(time_range)

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

            elif action in ("deny", "drop"):

                hourly[hour]["dropped_packets"] += packets

        return hourly

    # =========================================================
    # IP STATISTICS
    # =========================================================

    def get_ip_statistics(self, time_range="1h"):
        events = self._get_events(time_range)

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

    # =========================================================
    # PORT STATISTICS
    # =========================================================

    def get_port_statistics(self, time_range="1h"):
        events = self._get_events(time_range)

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

    # =========================================================
    # RULE STATISTICS
    # =========================================================

    def get_rule_statistics(self, time_range="1h"):
        events = self._get_events(time_range)

        rules = {}

        for event in events:

            rule_id = event.get("rule_id")

            if rule_id is None:
                continue

            if rule_id not in rules:

                rules[rule_id] = {
                    "rule_id": rule_id,
                    "rule_name": event.get("rule_name") or "Unknown",
                    "action": event.get("action") or "unknown",
                    "packets": 0,
                    "bytes": 0,
                }

            rules[rule_id]["packets"] += (
                event.get("packets") or 0
            )

            rules[rule_id]["bytes"] += (
                event.get("bytes") or 0
            )

        return list(rules.values())