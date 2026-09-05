from app.database.database import get_connection


class FirewallLogger:

    def log_event(
        self,
        source_ip=None,
        source_port=None,
        destination_ip=None,
        destination_port=None,
        protocol=None,
        interface=None,
        action=None,
        rule_id=None,
        rule_name=None,
        rule_match=None,
        rule_decision=None,
        packets=0,
        bytes_count=0,
    ):
        connection = get_connection()

        try:
            connection.execute(
                """
                INSERT INTO firewall_events (
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port,
                    protocol,
                    interface,
                    action,
                    rule_id,
                    rule_name,
                    rule_match,
                    rule_decision,
                    packets,
                    bytes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port,
                    protocol,
                    interface,
                    action,
                    rule_id,
                    rule_name,
                    rule_match,
                    rule_decision,
                    packets,
                    bytes_count,
                ),
            )

            connection.commit()

        finally:
            connection.close()

    def get_events(self, limit=100):
        connection = get_connection()

        try:
            rows = connection.execute(
                """
                SELECT *
                FROM firewall_events
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

            return [dict(row) for row in rows]

        finally:
            connection.close()