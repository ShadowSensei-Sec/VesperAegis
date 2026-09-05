from scapy.all import IP, IPv6, TCP, UDP, ICMP, sniff


class PacketInspector:

    def __init__(self, interface=None):
        self.interface = interface

    def inspect_packet(self, packet):

        try:

            # ================================
            # IP VERSION
            # ================================

            if packet.haslayer(IP):

                ip_layer = packet[IP]
                ip_version = 4

            elif packet.haslayer(IPv6):

                ip_layer = packet[IPv6]
                ip_version = 6

            else:
                return None

            # ================================
            # DEFAULT VALUES
            # ================================

            source_port = None
            destination_port = None
            protocol_name = "other"

            # ================================
            # TCP
            # ================================

            if packet.haslayer(TCP):

                protocol_name = "tcp"

                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport

            # ================================
            # UDP
            # ================================

            elif packet.haslayer(UDP):

                protocol_name = "udp"

                source_port = packet[UDP].sport
                destination_port = packet[UDP].dport

            # ================================
            # ICMP
            # ================================

            elif packet.haslayer(ICMP):

                protocol_name = "icmp"

            # ================================
            # METADATA
            # ================================

            return {
                "source_ip": ip_layer.src,
                "destination_ip": ip_layer.dst,
                "source_port": source_port,
                "destination_port": destination_port,
                "protocol": protocol_name,
                "ip_version": ip_version,
                "packet_size": len(packet),
                "interface": self.interface,
            }

        except Exception as error:

            print(
                f"[!] Packet inspection failed: {error}"
            )

            return None

    def capture(
        self,
        packet_count=10,
        packet_filter=None
    ):

        return sniff(
            iface=self.interface,
            count=packet_count,
            filter=packet_filter,
            store=True,
        )

    def capture_continuously(
        self,
        callback,
        packet_filter=None
    ):

        sniff(
            iface=self.interface,
            filter=packet_filter,
            prn=callback,
            store=False,
        )