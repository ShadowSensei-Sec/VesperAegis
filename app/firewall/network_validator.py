import ipaddress


class NetworkValidator:

    @staticmethod
    def validate_ip(value, field_name):
        if value is None:
            return

        if value == "any":
            return

        try:
            ipaddress.ip_address(value)

        except ValueError:
            raise ValueError(
                f"{field_name} must be a valid IP address."
            )

    @staticmethod
    def validate_network(value, field_name):
        if value is None:
            return

        if value == "any":
            return

        try:
            ipaddress.ip_network(
                value,
                strict=False
            )

        except ValueError:
            raise ValueError(
                f"{field_name} must be a valid IP address or CIDR network."
            )