import secrets
from typing import Optional

from app.auth import authenticate, change_credentials


_sessions: set[str] = set()


def create_session() -> str:
    token = secrets.token_urlsafe(32)
    _sessions.add(token)
    return token


def validate_session(token: Optional[str]) -> bool:
    if not token:
        return False

    return token in _sessions


def destroy_session(token: Optional[str]) -> None:
    if token:
        _sessions.discard(token)


def login(username: str, password: str):
    credentials = authenticate(username, password)

    if credentials is None:
        return None

    token = create_session()

    return {
        "token": token,
        "must_change_password": bool(
            credentials["must_change_password"]
        ),
    }


def update_credentials(
    current_token: str,
    username: str,
    password: str,
):
    if not validate_session(current_token):
        raise PermissionError("Invalid authentication session.")

    change_credentials(
        username=username,
        password=password,
    )

    return {
        "success": True,
        "must_change_password": False,
    }