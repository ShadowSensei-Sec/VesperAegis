from app.firewall.rule_engine import RuleEngine


def rule(**overrides):
    data = {
        "id": 1,
        "name": "Deny HTTP",
        "action": "deny",
        "protocol": "tcp",
        "source_ip": "192.168.50.10",
        "destination_ip": "192.168.60.10",
        "destination_port": 80,
        "enabled": True,
        "priority": 10,
    }
    data.update(overrides)
    return data


def packet(**overrides):
    data = {
        "source_ip": "192.168.50.10",
        "source_port": 50000,
        "destination_ip": "192.168.60.10",
        "destination_port": 80,
        "protocol": "tcp",
    }
    data.update(overrides)
    return data


def test_source_ip_matching():
    engine = RuleEngine([rule()])

    assert engine.match_packet(packet())["id"] == 1

    assert engine.match_packet(
        packet(source_ip="192.168.50.20")
    ) is None


def test_destination_ip_matching():
    engine = RuleEngine([rule()])

    assert engine.match_packet(packet())["id"] == 1

    assert engine.match_packet(
        packet(destination_ip="192.168.60.20")
    ) is None


def test_protocol_matching():
    engine = RuleEngine([rule(protocol="tcp")])

    assert engine.match_packet(
        packet(protocol="tcp")
    )["id"] == 1

    assert engine.match_packet(
        packet(protocol="udp")
    ) is None


def test_any_protocol_matches():
    engine = RuleEngine([rule(protocol="any")])

    assert engine.match_packet(
        packet(protocol="tcp")
    )["id"] == 1

    assert engine.match_packet(
        packet(protocol="udp")
    )["id"] == 1


def test_destination_port_matching():
    engine = RuleEngine([rule(destination_port=80)])

    assert engine.match_packet(
        packet(destination_port=80)
    )["id"] == 1

    assert engine.match_packet(
        packet(destination_port=443)
    ) is None


def test_source_port_matching():
    engine = RuleEngine([
        rule(
            source_port=50000,
            destination_port=None
        )
    ])

    assert engine.match_packet(
        packet(source_port=50000)
    )["id"] == 1

    assert engine.match_packet(
        packet(source_port=40000)
    ) is None


def test_disabled_rule_is_ignored():
    engine = RuleEngine([
        rule(enabled=False)
    ])

    assert engine.match_packet(packet()) is None


def test_rule_priority():
    low_priority = rule(
        id=1,
        name="Low Priority Deny",
        action="deny",
        priority=20,
    )

    high_priority = rule(
        id=2,
        name="High Priority Allow",
        action="allow",
        priority=5,
    )

    engine = RuleEngine([
        low_priority,
        high_priority,
    ])

    matched = engine.match_packet(packet())

    assert matched["id"] == 2
    assert matched["action"] == "allow"


def test_first_matching_rule_wins():
    allow_rule = rule(
        id=1,
        name="Allow HTTP",
        action="allow",
        priority=5,
    )

    deny_rule = rule(
        id=2,
        name="Deny HTTP",
        action="deny",
        priority=10,
    )

    engine = RuleEngine([
        deny_rule,
        allow_rule,
    ])

    matched = engine.match_packet(packet())

    assert matched["id"] == 1
    assert matched["action"] == "allow"


def test_no_matching_rule_returns_none():
    engine = RuleEngine([rule()])

    result = engine.match_packet(
        packet(
            source_ip="10.10.10.10",
            destination_port=443,
        )
    )

    assert result is None
