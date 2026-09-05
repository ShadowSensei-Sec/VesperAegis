from dataclasses import dataclass
from typing import List


@dataclass
class ConflictResult:
    rule_id: int
    conflicting_rule_id: int
    conflict_type: str
    message: str


class RuleConflictDetector:

    @staticmethod
    def _get_value(rule, field):
        if isinstance(rule, dict):
            return rule.get(field)

        return getattr(rule, field, None)

    def _same_match(self, rule1, rule2):
        fields = [
            "protocol",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "interface",
            "direction",
        ]

        return all(
            self._get_value(rule1, field)
            == self._get_value(rule2, field)
            for field in fields
        )

    def check_rule(self, new_rule, existing_rules) -> List[ConflictResult]:

        conflicts = []

        for existing_rule in existing_rules:

            if not self._get_value(existing_rule, "enabled"):
                continue

            if self._same_match(new_rule, existing_rule):

                new_action = self._get_value(
                    new_rule, "action"
                )

                existing_action = self._get_value(
                    existing_rule, "action"
                )

                existing_id = self._get_value(
                    existing_rule, "id"
                )

                if new_action == existing_action:

                    conflicts.append(
                        ConflictResult(
                            rule_id=self._get_value(
                                new_rule, "id"
                            ),
                            conflicting_rule_id=existing_id,
                            conflict_type="duplicate",
                            message=(
                                f"Rule matches existing rule "
                                f"{existing_id} with the same action."
                            ),
                        )
                    )

                else:

                    conflicts.append(
                        ConflictResult(
                            rule_id=self._get_value(
                                new_rule, "id"
                            ),
                            conflicting_rule_id=existing_id,
                            conflict_type="conflict",
                            message=(
                                f"Rule conflicts with existing rule "
                                f"{existing_id}: "
                                f"{existing_action} vs "
                                f"{new_action}."
                            ),
                        )
                    )

        return conflicts
    def check_shadowing(self, new_rule, existing_rules) -> List[ConflictResult]:

        conflicts = []

        for existing_rule in existing_rules:

            if not self._get_value(existing_rule, "enabled"):
                continue

            existing_protocol = self._get_value(
                existing_rule, "protocol"
            )

            new_protocol = self._get_value(
                new_rule, "protocol"
            )

            if existing_protocol != "any" and (
                existing_protocol != new_protocol
            ):
                continue

            broader = True

            fields = [
                "source_ip",
                "source_port",
                "destination_ip",
                "destination_port",
            ]

            for field in fields:

                existing_value = self._get_value(
                    existing_rule, field
                )

                new_value = self._get_value(
                    new_rule, field
                )

                if existing_value is not None:
                    if existing_value != new_value:
                        broader = False
                        break

            if broader:

                existing_id = self._get_value(
                    existing_rule, "id"
                )

                existing_action = self._get_value(
                    existing_rule, "action"
                )

                new_action = self._get_value(
                    new_rule, "action"
                )

                if existing_action != new_action:

                    conflicts.append(
                        ConflictResult(
                            rule_id=self._get_value(
                                new_rule, "id"
                            ),
                            conflicting_rule_id=existing_id,
                            conflict_type="shadowing",
                            message=(
                                f"Rule may be shadowed by broader "
                                f"rule {existing_id}: "
                                f"{existing_action} vs {new_action}."
                            ),
                        )
                    )

        return conflicts