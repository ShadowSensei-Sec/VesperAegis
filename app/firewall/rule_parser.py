from dataclasses import dataclass
from typing import Optional

import yaml


@dataclass
class FirewallRule:
    id: int
    name: str
    action: str
    protocol: str
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    interface: Optional[str] = None
    direction: Optional[str] = None
    enabled: bool = True
    description: str = ""
    priority: int = 100

    def validate(self) -> None:

        # ================================
        # ACTION VALIDATION
        # ================================

        if self.action not in {"allow", "deny"}:
            raise ValueError(
                "Action must be either 'allow' or 'deny'."
            )

        # ================================
        # PROTOCOL VALIDATION
        # ================================

        protocol = self.protocol.lower()

        allowed_protocols = {
            "tcp",
            "udp",
            "icmp",
            "icmpv6",
            "any"
        }

        if protocol not in allowed_protocols:
            raise ValueError(
                "Protocol must be tcp, udp, icmp, icmpv6, or any."
            )

        # ================================
        # PORT VALIDATION
        # ================================

        if (
            self.source_port is not None
            or self.destination_port is not None
        ):

            if protocol not in {"tcp", "udp"}:
                raise ValueError(
                    "Source or destination ports require "
                    "TCP or UDP protocol."
                )

        # ================================
        # PORT RANGE VALIDATION
        # ================================

        for port_name, port in [
            ("source_port", self.source_port),
            ("destination_port", self.destination_port),
        ]:

            if port is not None:

                if not isinstance(port, int):
                    raise ValueError(
                        f"{port_name} must be an integer."
                    )

                if port < 1 or port > 65535:
                    raise ValueError(
                        f"{port_name} must be between 1 and 65535."
                    )


class RuleParser:

    def __init__(self, config_path: str):
        self.config_path = config_path

    def parse_rules(self):
        with open(self.config_path, "r") as file:
            config = yaml.safe_load(file)

        rules = []

        for item in config.get("rules", []):

            source = item.get("source", {})
            destination = item.get("destination", {})

            source_ip = source.get("ip")
            destination_ip = destination.get("ip")

            if source_ip == "any":
                source_ip = None

            if destination_ip == "any":
                destination_ip = None

            rule = FirewallRule(
                id=item["id"],
                name=item["name"],
                action=item["action"].lower(),
                protocol=item["protocol"].lower(),
                source_ip=source_ip,
                source_port=source.get("port"),
                destination_ip=destination_ip,
                destination_port=destination.get("port"),
                interface=item.get("interface"),
                direction=item.get("direction"),
                enabled=item.get("enabled", True),
                description=item.get("description", ""),
                priority=item.get("priority", 100),
            )

            rule.validate()

            rules.append(rule)

        return rules