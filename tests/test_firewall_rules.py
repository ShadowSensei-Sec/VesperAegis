import pytest

from app.database.database import (
    initialize_database,
    get_connection,
    create_firewall_rule,
    get_firewall_rules,
    update_firewall_rule,
    set_firewall_rule_enabled,
    delete_firewall_rule,
)
from app.firewall.rule_parser import FirewallRule


@pytest.fixture
def test_database(tmp_path, monkeypatch):
    import app.database.database as database

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "test_firewall.db",
    )

    initialize_database()
    yield


def make_rule(**overrides):
    data = {
        "id": 1,
        "name": "Test Rule",
        "action": "deny",
        "protocol": "tcp",
        "source_ip": "192.168.50.10",
        "destination_ip": "192.168.60.10",
        "destination_port": 80,
        "enabled": True,
        "priority": 10,
    }
    data.update(overrides)
    return FirewallRule(**data)


def test_create_firewall_rule(test_database):
    rule_id = create_firewall_rule(make_rule())

    rules = get_firewall_rules()

    assert rule_id == 1
    assert len(rules) == 1
    assert rules[0]["name"] == "Test Rule"
    assert rules[0]["action"] == "deny"


def test_update_firewall_rule(test_database):
    rule_id = create_firewall_rule(make_rule())

    update_firewall_rule(
        rule_id=rule_id,
        name="Updated Rule",
        action="allow",
        protocol="tcp",
        source_ip="192.168.50.10",
        source_port=None,
        destination_ip="192.168.60.10",
        destination_port=443,
        interface=None,
        direction="forward",
        enabled=True,
        description="Updated firewall rule",
        priority=5,
    )

    rule = get_firewall_rules()[0]

    assert rule["name"] == "Updated Rule"
    assert rule["action"] == "allow"
    assert rule["destination_port"] == 443
    assert rule["priority"] == 5


def test_disable_and_enable_firewall_rule(test_database):
    rule_id = create_firewall_rule(make_rule())

    set_firewall_rule_enabled(rule_id, False)

    assert get_firewall_rules()[0]["enabled"] == 0

    set_firewall_rule_enabled(rule_id, True)

    assert get_firewall_rules()[0]["enabled"] == 1


def test_delete_firewall_rule(test_database):
    first_id = create_firewall_rule(make_rule())
    create_firewall_rule(make_rule(name="Second Rule"))

    delete_firewall_rule(first_id)

    rules = get_firewall_rules()

    assert len(rules) == 1
    assert rules[0]["name"] == "Second Rule"


def test_firewall_rule_validation(test_database):
    rule = make_rule()

    rule.validate()

    assert rule.action in {"allow", "deny"}
    assert rule.protocol == "tcp"


def test_invalid_action_is_rejected():
    rule = make_rule(action="block")

    with pytest.raises(ValueError):
        rule.validate()


def test_invalid_port_is_rejected():
    rule = make_rule(destination_port=70000)

    with pytest.raises(ValueError):
        rule.validate()
