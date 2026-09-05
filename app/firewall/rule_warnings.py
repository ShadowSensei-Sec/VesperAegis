from dataclasses import dataclass
from typing import List


@dataclass
class RuleWarning:
    warning_type: str
    severity: str
    message: str


class RuleWarningAnalyzer:

    def analyze(self, rule) -> List[RuleWarning]:

        warnings = []

        # -------------------------------------------------
        # 1. Allow ANY traffic
        # -------------------------------------------------

        if (
            rule.action == "allow"
            and rule.protocol == "any"
            and rule.source_ip is None
            and rule.destination_ip is None
            and rule.source_port is None
            and rule.destination_port is None
        ):
            warnings.append(
                RuleWarning(
                    warning_type="allow_any",
                    severity="high",
                    message=(
                        "Rule allows all traffic from any source "
                        "to any destination."
                    ),
                )
            )

        # -------------------------------------------------
        # 2. Allow ANY protocol
        # -------------------------------------------------

        elif (
            rule.action == "allow"
            and rule.protocol == "any"
        ):
            warnings.append(
                RuleWarning(
                    warning_type="allow_any_protocol",
                    severity="medium",
                    message=(
                        "Rule allows traffic for any protocol."
                    ),
                )
            )

        # -------------------------------------------------
        # 3. Allow from ANY source
        # -------------------------------------------------

        if (
            rule.action == "allow"
            and rule.source_ip is None
            and rule.protocol != "any"
        ):
            warnings.append(
                RuleWarning(
                    warning_type="allow_any_source",
                    severity="medium",
                    message=(
                        "Rule allows traffic from any source."
                    ),
                )
            )

        # -------------------------------------------------
        # 4. Allow to ANY destination
        # -------------------------------------------------

        if (
            rule.action == "allow"
            and rule.destination_ip is None
            and rule.protocol != "any"
        ):
            warnings.append(
                RuleWarning(
                    warning_type="allow_any_destination",
                    severity="medium",
                    message=(
                        "Rule allows traffic to any destination."
                    ),
                )
            )

        # -------------------------------------------------
        # 5. Broad TCP/UDP rule without destination port
        # -------------------------------------------------

        if (
            rule.action == "allow"
            and rule.protocol in {"tcp", "udp"}
            and rule.destination_port is None
        ):
            warnings.append(
                RuleWarning(
                    warning_type="broad_port_access",
                    severity="medium",
                    message=(
                        f"Rule allows {rule.protocol.upper()} traffic "
                        "without restricting the destination port."
                    ),
                )
            )

        return warnings