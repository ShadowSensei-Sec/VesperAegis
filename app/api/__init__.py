from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.firewall.nftables import NftablesManager
from app.firewall.rule_parser import FirewallRule
from app.logging.logger import FirewallLogger
from app.traffic.statistics import TrafficStatistics

from app.database.database import (
    create_firewall_rule,
    get_firewall_rules,
    update_firewall_rule,
    update_firewall_rule_handle,
    set_firewall_rule_enabled,
    delete_firewall_rule,
)

router = APIRouter()

firewall = NftablesManager()
logger = FirewallLogger()
statistics = TrafficStatistics()


class FirewallRuleRequest(BaseModel):
    name: str
    action: str
    protocol: str = "any"
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    interface: str | None = None
    direction: str | None = None
    enabled: bool = True
    description: str = ""
    priority: int = 100


@router.get("/status")
def firewall_status():
    return {
        "status": "running",
        "firewall": "nftables"
    }


@router.get("/rules")
def firewall_rules():
    application_rules = get_firewall_rules()
    nft_rules = firewall.get_forward_rule_details()

    nft_by_handle = {
        rule["handle"]: rule
        for rule in nft_rules
        if rule.get("handle") is not None
    }

    rules = []

    for rule in application_rules:
        runtime_rule = nft_by_handle.get(rule.get("nft_handle"), {})

        rules.append({
            "id": rule["id"],
            "name": rule["name"],
            "action": rule["action"],
            "protocol": rule["protocol"],
            "source_ip": rule["source_ip"],
            "source_port": rule["source_port"],
            "destination_ip": rule["destination_ip"],
            "destination_port": rule["destination_port"],
            "interface": rule["interface"],
            "direction": rule["direction"],
            "enabled": bool(rule["enabled"]),
            "description": rule["description"],
            "priority": rule["priority"],
            "nft_handle": rule["nft_handle"],
            "packets": runtime_rule.get("packets", 0),
            "bytes": runtime_rule.get("bytes", 0),
        })

    return {
        "rules": rules
    }

@router.post("/rules")
def create_rule(rule: FirewallRuleRequest):

    try:
        firewall_rule = FirewallRule(
            id=0,
            name=rule.name,
            action=rule.action.lower(),
            protocol=rule.protocol.lower(),
            source_ip=rule.source_ip,
            source_port=rule.source_port,
            destination_ip=rule.destination_ip,
            destination_port=rule.destination_port,
            interface=rule.interface,
            direction=rule.direction,
            enabled=rule.enabled,
            description=rule.description,
            priority=rule.priority,
        )

        firewall_rule.validate()

        # Apply the rule to nftables
        nft_handle = firewall.add_rule(firewall_rule)

        # Store the rule in SQLite
        rule_id = create_firewall_rule(firewall_rule)

        # Store the nftables handle against our application rule ID
        update_firewall_rule_handle(rule_id, nft_handle)

        return {
            "status": "success",
            "message": "Firewall rule added",
            "rule": {
                "id": rule_id,
                "name": firewall_rule.name,
                "action": firewall_rule.action,
                "protocol": firewall_rule.protocol,
                "source_ip": firewall_rule.source_ip,
                "destination_ip": firewall_rule.destination_ip,
                "source_port": firewall_rule.source_port,
                "destination_port": firewall_rule.destination_port,
                "enabled": firewall_rule.enabled,
                "description": firewall_rule.description,
                "priority": firewall_rule.priority,
                "nft_handle": nft_handle,
            }
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )

@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int):
    try:
        rules = get_firewall_rules()

        rule = next(
            (item for item in rules if item["id"] == rule_id),
            None
        )

        if rule is None:
            raise HTTPException(
                status_code=404,
                detail="Firewall rule not found"
            )

        # Remove active nftables rule
        if rule["enabled"] and rule["nft_handle"] is not None:
            firewall.delete_rule(rule["nft_handle"])

        # Remove persistent database record
        delete_firewall_rule(rule_id)

        return {
            "status": "success",
            "message": f"Firewall rule {rule_id} deleted",
            "rule_id": rule_id
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )

@router.patch("/rules/{rule_id}/toggle")
def toggle_rule(rule_id: int):

    try:
        rules = get_firewall_rules()

        rule = next(
            (item for item in rules if item["id"] == rule_id),
            None
        )

        if rule is None:
            raise HTTPException(
                status_code=404,
                detail="Firewall rule not found"
            )

        new_enabled = not bool(rule["enabled"])

        if new_enabled:
            firewall_rule = FirewallRule(
                id=rule["id"],
                name=rule["name"],
                action=rule["action"],
                protocol=rule["protocol"],
                source_ip=rule["source_ip"],
                source_port=rule["source_port"],
                destination_ip=rule["destination_ip"],
                destination_port=rule["destination_port"],
                interface=rule["interface"],
                direction=rule["direction"],
                enabled=True,
                description=rule["description"],
                priority=rule["priority"],
            )

            firewall_rule.validate()

            nft_handle = firewall.add_rule(firewall_rule)

            set_firewall_rule_enabled(
                rule_id,
                True
            )

            update_firewall_rule_handle(
                rule_id,
                nft_handle
            )

        else:
            if rule["nft_handle"] is not None:
                firewall.delete_rule(
                    rule["nft_handle"]
                )

            set_firewall_rule_enabled(
                rule_id,
                False
            )

            update_firewall_rule_handle(
                rule_id,
                None
            )

        return {
            "status": "success",
            "rule_id": rule_id,
            "enabled": new_enabled,
            "message": (
                "Firewall rule enabled"
                if new_enabled
                else "Firewall rule disabled"
            )
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )

@router.put("/rules/{rule_id}")
def edit_rule(rule_id: int, rule: FirewallRuleRequest):
    try:
        rules = get_firewall_rules()

        existing_rule = next(
            (item for item in rules if item["id"] == rule_id),
            None
        )

        if existing_rule is None:
            raise HTTPException(
                status_code=404,
                detail="Firewall rule not found"
            )

        # Remove the old nftables rule if it is currently active
        if existing_rule["enabled"] and existing_rule["nft_handle"] is not None:
            firewall.delete_rule(existing_rule["nft_handle"])

        # Build the updated firewall rule
        firewall_rule = FirewallRule(
            id=rule_id,
            name=rule.name,
            action=rule.action.lower(),
            protocol=rule.protocol.lower(),
            source_ip=rule.source_ip,
            source_port=rule.source_port,
            destination_ip=rule.destination_ip,
            destination_port=rule.destination_port,
            interface=rule.interface,
            direction=rule.direction,
            enabled=rule.enabled,
            description=rule.description,
            priority=rule.priority,
        )

        firewall_rule.validate()

        # Add the updated rule to nftables if enabled
        nft_handle = None

        if firewall_rule.enabled:
            nft_handle = firewall.add_rule(firewall_rule)

        # Update database
        update_firewall_rule(
            rule_id=rule_id,
            name=firewall_rule.name,
            action=firewall_rule.action,
            protocol=firewall_rule.protocol,
            source_ip=firewall_rule.source_ip,
            source_port=firewall_rule.source_port,
            destination_ip=firewall_rule.destination_ip,
            destination_port=firewall_rule.destination_port,
            interface=firewall_rule.interface,
            direction=firewall_rule.direction,
            enabled=firewall_rule.enabled,
            description=firewall_rule.description,
            priority=firewall_rule.priority,
        )

        update_firewall_rule_handle(
            rule_id,
            nft_handle
        )

        return {
            "status": "success",
            "message": "Firewall rule updated",
            "rule": {
                "id": rule_id,
                "name": firewall_rule.name,
                "action": firewall_rule.action,
                "protocol": firewall_rule.protocol,
                "source_ip": firewall_rule.source_ip,
                "source_port": firewall_rule.source_port,
                "destination_ip": firewall_rule.destination_ip,
                "destination_port": firewall_rule.destination_port,
                "enabled": firewall_rule.enabled,
                "description": firewall_rule.description,
                "priority": firewall_rule.priority,
                "nft_handle": nft_handle,
            }
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )

@router.get("/logs")
def firewall_logs(limit: int = 100):
    return {
        "events": logger.get_events(limit=limit)
    }


@router.get("/statistics")
def firewall_statistics():
    return statistics.get_forward_statistics()