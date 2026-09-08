from app.firewall.nftables import NftablesManager
from app.firewall.rule_parser import FirewallRule


def make_rule(**overrides):
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

    return FirewallRule(**data)


def test_deny_rule_generates_drop_expression():
    manager = NftablesManager()

    expression = manager.build_rule_expression(
        make_rule(action="deny")
    )

    assert "ip" in expression
    assert "saddr" in expression
    assert "192.168.50.10" in expression
    assert "daddr" in expression
    assert "192.168.60.10" in expression
    assert "tcp" in expression
    assert "dport" in expression
    assert "80" in expression
    assert "counter" in expression
    assert "drop" in expression


def test_allow_rule_generates_accept_expression():
    manager = NftablesManager()

    expression = manager.build_rule_expression(
        make_rule(action="allow")
    )

    assert "accept" in expression
    assert "drop" not in expression


def test_icmp_rule_generates_icmp_expression():
    manager = NftablesManager()

    expression = manager.build_rule_expression(
        make_rule(
            protocol="icmp",
            destination_port=None,
        )
    )

    assert "icmp" in expression
    assert "counter" in expression
    assert "drop" in expression


def test_any_protocol_does_not_add_protocol_filter():
    manager = NftablesManager()

    expression = manager.build_rule_expression(
        make_rule(
            protocol="any",
            destination_port=None,
        )
    )

    assert "any" not in expression
    assert "tcp" not in expression
    assert "udp" not in expression
    assert "icmp" not in expression


def test_disabled_rule_is_not_added(monkeypatch):
    manager = NftablesManager()

    called = []

    monkeypatch.setattr(
        manager,
        "_run",
        lambda *args, **kwargs: called.append(args),
    )

    result = manager.add_rule(
        make_rule(enabled=False)
    )

    assert result is None
    assert called == []


def test_stateful_forward_rule_command(monkeypatch):
    manager = NftablesManager()

    captured = {}

    def fake_run(command, sudo=False):
        captured["command"] = command
        captured["sudo"] = sudo
        return ""

    monkeypatch.setattr(manager, "_run", fake_run)

    manager.add_stateful_forward_rules()

    assert captured["command"] == [
        "nft",
        "add",
        "rule",
        "inet",
        "nftable",
        "forward",
        "ct",
        "state",
        "established,related",
        "accept",
    ]

    assert captured["sudo"] is True
