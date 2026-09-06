import platform
import shutil
import socket
import yaml
from datetime import datetime, timezone

import psutil


class SystemInfo:
    """Collect live system information from the host running the firewall."""

    @staticmethod
    def get_system_info():
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        boot_time = datetime.fromtimestamp(
            psutil.boot_time(),
            tz=timezone.utc
        )

        uptime_seconds = int(
            datetime.now(timezone.utc).timestamp()
            - boot_time.timestamp()
        )

        return {
            "hostname": platform.node(),
            "operating_system": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "processor": SystemInfo.get_processor_info(),

            "cpu": {
                "usage_percent": psutil.cpu_percent(interval=0.2),
                "logical_cores": psutil.cpu_count(logical=True),
                "physical_cores": psutil.cpu_count(logical=False),
            },

            "memory": {
                "total_bytes": memory.total,
                "used_bytes": memory.used,
                "available_bytes": memory.available,
                "usage_percent": memory.percent,
            },

            "disk": {
                "total_bytes": disk.total,
                "used_bytes": disk.used,
                "free_bytes": disk.free,
                "usage_percent": disk.percent,
            },

            "uptime": {
                "seconds": uptime_seconds,
                "boot_time": boot_time.isoformat(),
            },

            "system_time": datetime.now(timezone.utc).astimezone().isoformat(),
        }
        
    @staticmethod
    def get_network_interfaces():
        interfaces = []

        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        counters = psutil.net_io_counters(pernic=True)

        for interface_name, address_list in addresses.items():
            interface = {
                "name": interface_name,
                "status": "DOWN",
                "mac_address": None,
                "ipv4_addresses": [],
                "ipv6_addresses": [],
                "rx_packets": 0,
                "tx_packets": 0,
                "rx_bytes": 0,
                "tx_bytes": 0,
            }

            # Interface state
            interface_stats = stats.get(interface_name)

            if interface_stats:
                interface["status"] = (
                    "UP" if interface_stats.isup else "DOWN"
                )

            # Interface addresses
            for address in address_list:

                if address.family == psutil.AF_LINK:
                    interface["mac_address"] = address.address

                elif address.family == __import__("socket").AF_INET:
                    interface["ipv4_addresses"].append(
                        address.address
                    )

                elif address.family == __import__("socket").AF_INET6:
                    interface["ipv6_addresses"].append(
                        address.address
                    )

            # Interface traffic counters
            counter = counters.get(interface_name)

            if counter:
                interface["rx_packets"] = counter.packets_recv
                interface["tx_packets"] = counter.packets_sent
                interface["rx_bytes"] = counter.bytes_recv
                interface["tx_bytes"] = counter.bytes_sent

            interfaces.append(interface)

        return interfaces

    @staticmethod
    def get_service_status():
        services = {}

        # nftables availability
        nftables_path = shutil.which("nft")
        if nftables_path:
            try:
                result = __import__("subprocess").run(
                    [nftables_path, "list", "tables"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )

                services["nftables"] = {
                    "status": "active" if result.returncode == 0 else "error",
                    "available": True,
                }
            except Exception:
                services["nftables"] = {
                    "status": "error",
                    "available": True,
                }
        else:
            services["nftables"] = {
                "status": "unavailable",
                "available": False,
            }

        # Database connectivity
        try:
            from app.database.database import get_connection

            connection = get_connection()
            connection.execute("SELECT 1")
            connection.close()

            services["database"] = {
                "status": "connected",
                "available": True,
            }
        except Exception:
            services["database"] = {
                "status": "error",
                "available": False,
            }

        # REST API / local application reachability
        try:
            with socket.create_connection(
                ("127.0.0.1", 8000),
                timeout=1,
            ):
                services["rest_api"] = {
                    "status": "running",
                    "available": True,
                }
        except OSError:
            services["rest_api"] = {
                "status": "unavailable",
                "available": False,
            }

        # Firewall application
        services["firewall_application"] = {
            "status": "running",
            "available": True,
        }

        # Packet monitoring module
        try:
            from app.traffic.monitor import TrafficMonitor

            TrafficMonitor

            services["packet_monitoring"] = {
                "status": "available",
                "available": True,
            }
        except Exception:
            services["packet_monitoring"] = {
                "status": "unavailable",
                "available": False,
            }

        # Web interface
        try:
            with socket.create_connection(
                ("127.0.0.1", 8000),
                timeout=1,
            ):
                services["web_interface"] = {
                    "status": "running",
                    "available": True,
                }
        except OSError:
            services["web_interface"] = {
                "status": "unavailable",
                "available": False,
            }

        return services

    @staticmethod
    def get_configuration_status():
        from app.database.database import get_connection

        connection = get_connection()

        try:
            total_rules = connection.execute(
                "SELECT COUNT(*) FROM firewall_rules"
            ).fetchone()[0]

            active_rules = connection.execute(
                "SELECT COUNT(*) FROM firewall_rules WHERE enabled = 1"
            ).fetchone()[0]

            disabled_rules = total_rules - active_rules

            return {
                "active_rules": active_rules,
                "disabled_rules": disabled_rules,
                "total_rules": total_rules,
            }

        finally:
            connection.close()
    @staticmethod
    def get_default_policies():
        config_path = "config/firewall.yaml"

        try:
            with open(config_path, "r", encoding="utf-8") as file:
                config = yaml.safe_load(file) or {}

            policies = config.get("firewall", {}).get(
                "default_policy",
                {}
            )

            return {
                "input": policies.get("input"),
                "output": policies.get("output"),
                "forward": policies.get("forward"),
            }

        except (OSError, yaml.YAMLError):
            return {
                "input": None,
                "output": None,
                "forward": None,
            }
    @staticmethod
    def get_processor_info():
        processor = platform.processor().strip()

        if processor:
            return processor

        try:
            with open("/proc/cpuinfo", "r", encoding="utf-8") as file:
                for line in file:
                    if line.lower().startswith("model name"):
                        return line.split(":", 1)[1].strip()

                    if line.lower().startswith("hardware"):
                        return line.split(":", 1)[1].strip()

        except (OSError, UnicodeDecodeError):
            pass

        return "Unavailable"