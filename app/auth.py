import hashlib
import hmac
import secrets

from app.database.database import (
    get_auth_credentials,
    create_auth_credentials,
    update_auth_credentials,
)


PASSWORD_ITERATIONS = 310_000


def hash_password(password: str) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256.
    """

    if not password:
        raise ValueError("Password cannot be empty.")

    salt = secrets.token_bytes(32)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )

    return (
        f"pbkdf2_sha256${PASSWORD_ITERATIONS}$"
        f"{salt.hex()}${password_hash.hex()}"
    )


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify a password against a stored PBKDF2 hash.
    """

    try:
        algorithm, iterations, salt_hex, hash_hex = (
            stored_hash.split("$")
        )

        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations)

        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)

        calculated_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )

        return hmac.compare_digest(
            calculated_hash,
            expected_hash,
        )

    except (ValueError, TypeError):
        return False


def initialize_admin_credentials():
    """
    Create the initial administrator account if one does not exist.

    Default credentials:
        username: admin
        password: admin

    The first login must require a credential change.
    """

    credentials = get_auth_credentials()

    if credentials is not None:
        return False

    password_hash = hash_password("admin")

    create_auth_credentials(
        username="admin",
        password_hash=password_hash,
        must_change_password=True,
    )

    return True


def authenticate(username: str, password: str):
    """
    Authenticate the administrator account.

    Returns the credential record when successful.
    Returns None when authentication fails.
    """

    credentials = get_auth_credentials()

    if credentials is None:
        return None

    if not hmac.compare_digest(
        username,
        credentials["username"],
    ):
        return None

    if not verify_password(
        password,
        credentials["password_hash"],
    ):
        return None

    return credentials


def change_credentials(
    username: str,
    password: str,
):
    """
    Replace the administrator username and password.

    After the change, the forced credential-change flag
    is cleared.
    """

    username = username.strip()

    if not username:
        raise ValueError("Username cannot be empty.")

    if len(username) < 3:
        raise ValueError(
            "Username must contain at least 3 characters."
        )

    if len(username) > 64:
        raise ValueError(
            "Username cannot exceed 64 characters."
        )

    if not password:
        raise ValueError("Password cannot be empty.")

    if len(password) < 8:
        raise ValueError(
            "Password must contain at least 8 characters."
        )

    password_hash = hash_password(password)

    update_auth_credentials(
        username=username,
        password_hash=password_hash,
        must_change_password=False,
    )