import sqlite3
from pathlib import Path


DATABASE_PATH = Path("data/firewall.db")


def get_connection():
    """Create and return a SQLite database connection."""

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(DATABASE_PATH, timeout=10)

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL;")

    return connection


def initialize_database():
    """Create the firewall database tables."""

    schema_path = Path("app/database/schema.sql")

    schema = schema_path.read_text()

    connection = get_connection()

    try:
        connection.executescript(schema)
        connection.commit()

    finally:
        connection.close()

def create_firewall_rule(rule):
    connection = get_connection()

    existing_ids = connection.execute(
        """
        SELECT id
        FROM firewall_rules
        ORDER BY id ASC
        """
    ).fetchall()

    used_ids = {row["id"] for row in existing_ids}

    new_id = 1

    while new_id in used_ids:
        new_id += 1

    connection.execute(
        """
        INSERT INTO firewall_rules (
            id,
            name,
            action,
            protocol,
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            interface,
            direction,
            enabled,
            description,
            priority,
            nft_handle
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            new_id,
            rule.name,
            rule.action,
            rule.protocol,
            rule.source_ip,
            rule.source_port,
            rule.destination_ip,
            rule.destination_port,
            rule.interface,
            rule.direction,
            int(rule.enabled),
            rule.description,
            rule.priority,
            getattr(rule, "nft_handle", None),
        ),
    )

    connection.commit()
    connection.close()

    return new_id


def get_firewall_rules():
    connection = get_connection()

    rows = connection.execute(
        """
        SELECT *
        FROM firewall_rules
        ORDER BY priority ASC, id ASC
        """
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]


def update_firewall_rule_handle(rule_id, nft_handle):
    connection = get_connection()

    connection.execute(
        """
        UPDATE firewall_rules
        SET nft_handle = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (nft_handle, rule_id),
    )

    connection.commit()
    connection.close()


def delete_firewall_rule(rule_id):
    connection = get_connection()

    try:
        rule = connection.execute(
            """
            SELECT id
            FROM firewall_rules
            WHERE id = ?
            """,
            (rule_id,),
        ).fetchone()

        if rule is None:
            return

        # Temporarily move higher IDs into negative space
        connection.execute(
            """
            UPDATE firewall_rules
            SET id = -id
            WHERE id > ?
            """,
            (rule_id,),
        )

        # Delete the requested rule
        connection.execute(
            """
            DELETE FROM firewall_rules
            WHERE id = ?
            """,
            (rule_id,),
        )

        # Move the remaining rules back down by one
        connection.execute(
            """
            UPDATE firewall_rules
            SET id = -id - 1
            WHERE id < 0
            """
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

def set_firewall_rule_enabled(rule_id, enabled):
    connection = get_connection()

    connection.execute(
        """
        UPDATE firewall_rules
        SET enabled = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (int(enabled), rule_id),
    )

    connection.commit()
    connection.close()
def update_firewall_rule(
    rule_id,
    name,
    action,
    protocol,
    source_ip,
    source_port,
    destination_ip,
    destination_port,
    interface,
    direction,
    enabled,
    description,
    priority,
):
    connection = get_connection()

    connection.execute(
        """
        UPDATE firewall_rules
        SET
            name = ?,
            action = ?,
            protocol = ?,
            source_ip = ?,
            source_port = ?,
            destination_ip = ?,
            destination_port = ?,
            interface = ?,
            direction = ?,
            enabled = ?,
            description = ?,
            priority = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (
            name,
            action,
            protocol,
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            interface,
            direction,
            int(enabled),
            description,
            priority,
            rule_id,
        ),
    )

    connection.commit()
    connection.close()