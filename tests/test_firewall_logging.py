import pytest

from app.database.database import initialize_database, get_connection
from app.logging.event_service import FirewallEventService


@pytest.fixture
def test_database(tmp_path, monkeypatch):
    import app.database.database as database

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "test_logging.db",
    )

    initialize_database()
    yield


def test_matched_firewall_event_is_logged(test_database):
    service = FirewallEventService()

    service.record_packet_event(
        source_ip="192.168.50.10",
        source_port=50000,
        destination_ip="192.168.60.10",
        destination_port=80,
        protocol="tcp",
        interface="enp0s8",
        action="deny",
        rule_id=1,
        rule_name="Deny HTTP",
        rule_match="matched",
        rule_decision="deny",
        packets=1,
        bytes_count=60,
    )

    connection = get_connection()

    try:
        row = connection.execute(
            "SELECT * FROM firewall_events"
        ).fetchone()
    finally:
        connection.close()

    assert row is not None
    assert row["source_ip"] == "192.168.50.10"
    assert row["destination_ip"] == "192.168.60.10"
    assert row["action"] == "deny"
    assert row["rule_match"] == "matched"


def test_normal_traffic_is_aggregated(test_database):
    service = FirewallEventService()

    for _ in range(3):
        service.record_packet_event(
            source_ip="192.168.50.10",
            source_port=50000,
            destination_ip="192.168.60.20",
            destination_port=22,
            protocol="tcp",
            interface="enp0s8",
            action="observed",
            packets=1,
            bytes_count=100,
        )

    connection = get_connection()

    try:
        event_count = connection.execute(
            "SELECT COUNT(*) FROM firewall_events"
        ).fetchone()[0]

        stats = connection.execute(
            "SELECT * FROM traffic_stats"
        ).fetchone()
    finally:
        connection.close()

    assert event_count == 0
    assert stats is not None
    assert stats["packets"] == 3
    assert stats["bytes"] == 300


def test_traffic_statistics_are_aggregated_by_flow(test_database):
    service = FirewallEventService()

    service.record_packet_event(
        source_ip="192.168.50.10",
        source_port=50000,
        destination_ip="192.168.60.20",
        destination_port=22,
        protocol="tcp",
        interface="enp0s8",
        action="observed",
        packets=5,
        bytes_count=500,
    )

    service.record_packet_event(
        source_ip="192.168.50.10",
        source_port=50000,
        destination_ip="192.168.60.20",
        destination_port=22,
        protocol="tcp",
        interface="enp0s8",
        action="observed",
        packets=2,
        bytes_count=200,
    )

    connection = get_connection()

    try:
        rows = connection.execute(
            "SELECT * FROM traffic_stats"
        ).fetchall()
    finally:
        connection.close()

    assert len(rows) == 1
    assert rows[0]["packets"] == 7
    assert rows[0]["bytes"] == 700
