from scapy.all import IP, TCP, UDP, sniff


class PacketInspector:

    def __init__(self, interface=None):
        self.interface = interface

    def inspect_packet(self, packet):
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]

        source_port = None
        destination_port = None
        protocol_name = "other"

        if packet.haslayer(TCP):
            protocol_name = "tcp"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif packet.haslayer(UDP):
            protocol_name = "udp"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        return {
            "source_ip": ip_layer.src,
            "destination_ip": ip_layer.dst,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol_name,
            "packet_size": len(packet),
            "interface": self.interface,
        }

    def capture(self, packet_count=10, packet_filter=None):
        return sniff(
            iface=self.interface,
            count=packet_count,
            filter=packet_filter,
            store=True,
        )
    def capture_continuously(self, callback, packet_filter=None):
        sniff(
            iface=self.interface,
            filter=packet_filter,
            prn=callback,
            store=False,
        )