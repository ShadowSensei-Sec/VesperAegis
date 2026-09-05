from app.firewall.nftables import NftablesManager


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