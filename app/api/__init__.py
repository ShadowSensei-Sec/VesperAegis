from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel
from typing import Optional

from app.firewall.rule_conflict import RuleConflictDetector
from app.firewall.nftables import NftablesManager
from app.firewall.rule_parser import FirewallRule
from app.logging.logger import FirewallLogger
from app.traffic.statistics import TrafficStatistics
from app.firewall.rule_warnings import RuleWarningAnalyzer
from app.system.system_info import SystemInfo

from app.auth import initialize_admin_credentials
from app.auth_service import (
    login,
    validate_session,
    destroy_session,
    update_credentials,
)

from app.database.database import (
    create_firewall_rule,
    get_firewall_rules,
    update_firewall_rule,
    update_firewall_rule_handle,
    set_firewall_rule_enabled,
    delete_firewall_rule,
    reset_firewall_data,
)

router = APIRouter()

firewall = NftablesManager()
logger = FirewallLogger()
statistics = TrafficStatistics()
conflict_detector = RuleConflictDetector()
warning_analyzer = RuleWarningAnalyzer()

class LoginRequest(BaseModel):
    username: str
    password: str


class ChangeCredentialsRequest(BaseModel):
    username: str
    password: str

@router.post("/auth/login")
def auth_login(credentials: LoginRequest, response: Response):

    initialize_admin_credentials()

    result = login(
        username=credentials.username,
        password=credentials.password,
    )

    if result is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password.",
        )

    response.set_cookie(
        key="vesper_session",
        value=result["token"],
        httponly=True,
        samesite="strict",
        secure=False,
        max_age=3600,
    )

    return {
        "success": True,
        "must_change_password":
            result["must_change_password"],
    }


@router.post("/auth/change-credentials")
def auth_change_credentials(
    credentials: ChangeCredentialsRequest,
    request: Request,
):

    token = request.cookies.get("vesper_session")

    if not validate_session(token):
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        )

    try:

        result = update_credentials(
            current_token=token,
            username=credentials.username,
            password=credentials.password,
        )

        return result

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


@router.post("/auth/logout")
def auth_logout(
    request: Request,
    response: Response,
):

    token = request.cookies.get("vesper_session")

    destroy_session(token)

    response.delete_cookie(
        key="vesper_session"
    )

    return {
        "success": True
    }


@router.get("/auth/status")
def auth_status(request: Request):

    token = request.cookies.get("vesper_session")

    return {
        "authenticated": validate_session(token)
    }

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

    nft_handle = None

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

        # Validate before touching nftables
        firewall_rule.validate()
        # Check for duplicate/conflicting rules
        existing_rules = get_firewall_rules()
        conflicts = conflict_detector.check_rule(
            firewall_rule,
            existing_rules
        )

        if conflicts:
            conflict = conflicts[0]
            raise HTTPException(
                status_code=409,
                detail={
                    "type": conflict.conflict_type,
                    "rule_id": conflict.conflicting_rule_id,
                    "message": conflict.message
                }
            )
        # Check for possible rule shadowing
        shadowing = conflict_detector.check_shadowing(
            firewall_rule,
            existing_rules
        )

        if shadowing:

            conflict = shadowing[0]

            raise HTTPException(
                status_code=409,
                detail={
                    "type": conflict.conflict_type,
                    "rule_id": conflict.conflicting_rule_id,
                    "message": conflict.message
                }
             )
        # Analyze dangerous rule patterns
        warnings = warning_analyzer.analyze(
            firewall_rule
        )

        # Apply rule to nftables
        if firewall_rule.enabled:
            nft_handle = firewall.add_rule(
                firewall_rule,
                chain="forward"
            )

        # Store rule in SQLite
        rule_id = create_firewall_rule(
            firewall_rule
        )

        # Store nftables handle
        update_firewall_rule_handle(
            rule_id,
            nft_handle
        )

        return {
            "status": "success",
            "message": "Firewall rule added",
            "warnings": [{
                    "type": warning.warning_type,
                    "severity": warning.severity,
                    "message": warning.message
                } for warning in warnings],
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

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except HTTPException:
        raise

    except Exception as error:

        # Roll back nftables if database operation failed
        if nft_handle is not None:

            try:
                firewall.delete_rule(
                    nft_handle,
                    chain="forward"
                )

            except Exception as rollback_error:

                print(
                    "[!] Failed to rollback nftables rule:",
                    rollback_error
                )

        print(
            "[!] Firewall rule creation failed:",
            error
        )

        raise HTTPException(
            status_code=500,
            detail="Internal firewall error."
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

    old_nft_handle = None
    new_nft_handle = None

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

        # -------------------------------------------------
        # 1. Build the new firewall rule
        # -------------------------------------------------

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

        # -------------------------------------------------
        # 2. Validate BEFORE touching nftables
        # -------------------------------------------------

        firewall_rule.validate()

        # -------------------------------------------------
        # 3. Check duplicate/conflicting rules
        #    Exclude the rule currently being edited
        # -------------------------------------------------

        other_rules = [
            item for item in rules
            if item["id"] != rule_id
        ]

        conflicts = conflict_detector.check_rule(
            firewall_rule,
            other_rules
        )

        if conflicts:

            conflict = conflicts[0]

            raise HTTPException(
                status_code=409,
                detail={
                    "type": conflict.conflict_type,
                    "rule_id": conflict.conflicting_rule_id,
                    "message": conflict.message
                }
            )

        # -------------------------------------------------
        # 4. Check possible shadowing
        # -------------------------------------------------

        shadowing = conflict_detector.check_shadowing(
            firewall_rule,
            other_rules
        )

        if shadowing:

            conflict = shadowing[0]

            raise HTTPException(
                status_code=409,
                detail={
                    "type": conflict.conflict_type,
                    "rule_id": conflict.conflicting_rule_id,
                    "message": conflict.message
                }
            )

        # -------------------------------------------------
        # 5. Remember old nftables rule
        # -------------------------------------------------

        if (
            existing_rule["enabled"]
            and existing_rule["nft_handle"] is not None
        ):
            old_nft_handle = existing_rule["nft_handle"]

        # -------------------------------------------------
        # 6. Add new rule FIRST
        # -------------------------------------------------

        if firewall_rule.enabled:

            new_nft_handle = firewall.add_rule(
                firewall_rule,
                chain="forward"
            )

        # -------------------------------------------------
        # 7. Update database
        # -------------------------------------------------

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
            new_nft_handle
        )

        # -------------------------------------------------
        # 8. Remove old nftables rule
        # -------------------------------------------------

        if old_nft_handle is not None:

            try:

                firewall.delete_rule(
                    old_nft_handle,
                    chain="forward"
                )

            except Exception as delete_error:

                # New rule is already active.
                # Try to restore the previous database state
                # and remove the newly-created nftables rule.

                print(
                    "[!] Failed to remove old nftables rule:",
                    delete_error
                )

                try:

                    if new_nft_handle is not None:
                        firewall.delete_rule(
                            new_nft_handle,
                            chain="forward"
                        )

                except Exception as rollback_error:

                    print(
                        "[!] Failed to rollback new nftables rule:",
                        rollback_error
                    )

                raise RuntimeError(
                    "Firewall rule synchronization failed."
                )

        # -------------------------------------------------
        # 9. Return success
        # -------------------------------------------------

        return {
            "status": "success",
            "message": "Firewall rule updated",
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
                "nft_handle": new_nft_handle,
            }
        }

    except HTTPException:
        raise

    except Exception as error:

        # -------------------------------------------------
        # Roll back newly-created nftables rule
        # -------------------------------------------------

        if new_nft_handle is not None:

            try:
                firewall.delete_rule(
                    new_nft_handle,
                    chain="forward"
                )

            except Exception as rollback_error:

                print(
                    "[!] Failed to rollback new nftables rule:",
                    rollback_error
                )

        print(
            "[!] Firewall rule edit failed:",
            error
        )

        raise HTTPException(
            status_code=500,
            detail="Internal firewall error."
        )

@router.get("/logs")
def firewall_logs(limit: int = 100):
    return {
        "events": logger.get_events(limit=limit)
    }


@router.get("/statistics")
def firewall_statistics(range: str = "1h"):
    valid_ranges = {"1h", "24h", "7d", "30d"}

    if range not in valid_ranges:
        raise HTTPException(
            status_code=400,
            detail="Invalid time range. Use 1h, 24h, 7d, or 30d.",
        )

    forward = statistics.get_forward_statistics(range)

    return {
        **forward,
        "range": range,
        "protocols": statistics.get_protocol_statistics(range),
        "time_statistics": statistics.get_time_statistics(range),
    }

@router.get("/system")
def get_system_info():
    system_info = SystemInfo.get_system_info()

    system_info["network_interfaces"] = (
        SystemInfo.get_network_interfaces()
    )

    system_info["services"] = (
        SystemInfo.get_service_status()
    )

    system_info["configuration"] = {
        "rules": SystemInfo.get_configuration_status(),
        "default_policy": SystemInfo.get_default_policies(),
    }

    return system_info

