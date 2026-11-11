"""
Tsukiko In-Process Offline Privacy Guard
Technically enforces the zero-outbound-network guarantee at the Python socket level.
Blocks any non-loopback outbound connection attempt with a PrivacyViolationError.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from typing import Any, Optional, Tuple, Union

from app.core.logging.logger import get_logger

logger = get_logger("SYSTEM")


class PrivacyViolationError(PermissionError, RuntimeError):
    """Raised when any runtime code or dependency attempts an unauthorized outbound network connection."""
    pass


_GUARD_LOCK = threading.RLock()
_GUARD_ACTIVE = False
_ORIGINAL_SOCKET_CONNECT = socket.socket.connect
_ORIGINAL_CREATE_CONNECTION = socket.create_connection

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "0.0.0.0"})


def _is_loopback(host: str) -> bool:
    """Returns True if the destination host is a strictly local loopback address."""
    if host.lower() in LOOPBACK_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_unspecified
    except ValueError:
        # Host is a domain name (e.g. "api.openai.com", "google.com")
        return False


def _guarded_socket_connect(self: socket.socket, address: Union[Tuple[Any, ...], str, bytes]) -> None:
    """Interception hook for socket.socket.connect."""
    if isinstance(address, tuple) and len(address) >= 2:
        host, port = address[0], address[1]
        if not _is_loopback(str(host)):
            msg = (
                f"Tsukiko Offline Privacy Contract Violation: "
                f"Outbound network connection to '{host}:{port}' was strictly blocked by in-process network guard."
            )
            logger.error(msg)
            raise PrivacyViolationError(msg)
    elif isinstance(address, str) and not _is_loopback(address):
        # AF_UNIX or path
        pass

    return _ORIGINAL_SOCKET_CONNECT(self, address)


def _guarded_create_connection(
    address: Tuple[str, int],
    timeout: Optional[float] = None,
    source_address: Optional[Tuple[str, int]] = None,
    *args: Any,
    **kwargs: Any,
) -> socket.socket:
    """Interception hook for socket.create_connection."""
    host, port = address[0], address[1]
    if not _is_loopback(str(host)):
        msg = (
            f"Tsukiko Offline Privacy Contract Violation: "
            f"Outbound network connection to '{host}:{port}' was strictly blocked by in-process network guard."
        )
        logger.error(msg)
        raise PrivacyViolationError(msg)

    return _ORIGINAL_CREATE_CONNECTION(address, timeout=timeout, source_address=source_address, *args, **kwargs)


def enable_offline_guard() -> None:
    """Installs the in-process network interception hooks."""
    global _GUARD_ACTIVE
    with _GUARD_LOCK:
        if _GUARD_ACTIVE:
            return
        socket.socket.connect = _guarded_socket_connect  # type: ignore
        socket.create_connection = _guarded_create_connection  # type: ignore
        _GUARD_ACTIVE = True
        logger.info("Technical Offline Privacy Guard is ACTIVE (all non-loopback outbound sockets blocked).")


def disable_offline_guard() -> None:
    """Restores standard Python socket functions (used for test teardown)."""
    global _GUARD_ACTIVE
    with _GUARD_LOCK:
        if not _GUARD_ACTIVE:
            return
        socket.socket.connect = _ORIGINAL_SOCKET_CONNECT  # type: ignore
        socket.create_connection = _ORIGINAL_CREATE_CONNECTION  # type: ignore
        _GUARD_ACTIVE = False
        logger.info("Offline Privacy Guard disabled.")


def is_offline_guard_active() -> bool:
    """Returns True if the offline privacy guard is currently installed."""
    with _GUARD_LOCK:
        return _GUARD_ACTIVE
