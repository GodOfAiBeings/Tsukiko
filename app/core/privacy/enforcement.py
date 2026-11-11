"""
Tsukiko In-Process Offline Privacy Guard
Technically enforces the zero-outbound-network guarantee at the Python socket and DNS level.
Blocks any non-loopback outbound connection and external DNS resolution attempt with a PrivacyViolationError.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from typing import Any, Optional, Tuple, Union

from app.core.logging.logger import get_logger

logger = get_logger("SYSTEM")


class PrivacyViolationError(PermissionError, RuntimeError):
    """Raised when any runtime code or dependency attempts an unauthorized outbound network connection or DNS lookup."""
    pass


_GUARD_LOCK = threading.RLock()
_GUARD_ACTIVE = False

# References to original unhooked socket functions
_ORIGINAL_SOCKET_CONNECT = socket.socket.connect
_ORIGINAL_SOCKET_CONNECT_EX = socket.socket.connect_ex
_ORIGINAL_SOCKET_SENDTO = socket.socket.sendto
_ORIGINAL_CREATE_CONNECTION = socket.create_connection
_ORIGINAL_GETADDRINFO = socket.getaddrinfo
_ORIGINAL_GETHOSTBYNAME = socket.gethostbyname
_ORIGINAL_GETHOSTBYNAME_EX = socket.gethostbyname_ex
_ORIGINAL_GETHOSTBYADDR = socket.gethostbyaddr
_ORIGINAL_GETNAMEINFO = socket.getnameinfo


def _validate_localhost_resolution() -> bool:
    """Verifies that 'localhost' strictly resolves to loopback IP addresses (127.0.0.1 or ::1)."""
    try:
        results = _ORIGINAL_GETADDRINFO("localhost", None)
        for res in results:
            sockaddr = res[4]
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            if not ip.is_loopback:
                return False
        return True
    except Exception:
        return False


def is_loopback_address(host: Any) -> bool:
    """Returns True ONLY if the destination host is a strictly verified IPv4 or IPv6 loopback address.

    Rejects unspecified addresses (0.0.0.0, ::), empty hosts, and unknown domain names.
    Validates 'localhost' against actual loopback resolution to prevent DNS-rebind / hosts poisoning.
    """
    if host is None:
        return False

    clean_host = str(host).strip().lower().rstrip(".")
    if not clean_host:
        return False

    # 1. Reject unspecified addresses explicitly (0.0.0.0, ::)
    if clean_host in ("0.0.0.0", "::"):
        return False

    # 2. Check strict IP literal loopback (127.0.0.0/8 or ::1)
    try:
        ip = ipaddress.ip_address(clean_host)
        # In ipaddress, is_loopback is True for 127.0.0.1..127.255.255.254 and ::1
        # is_unspecified is True for 0.0.0.0 and ::
        if ip.is_unspecified:
            return False
        return bool(ip.is_loopback)
    except ValueError:
        pass

    # 3. Carefully validated localhost resolution
    if clean_host == "localhost":
        return _validate_localhost_resolution()

    # Any other hostname (e.g. "api.openai.com", "huggingface.co", "lan-server.local") is rejected
    return False


def _extract_host_from_address(address: Any) -> Optional[str]:
    """Safely extracts the host component from various socket address representations."""
    if isinstance(address, tuple) and len(address) >= 1:
        return str(address[0])
    if isinstance(address, str):
        return address
    return None


def _guarded_socket_connect(self: socket.socket, address: Union[Tuple[Any, ...], str, bytes]) -> None:
    """Interception hook for socket.socket.connect."""
    host = _extract_host_from_address(address)
    if host is not None and not is_loopback_address(host):
        msg = (
            f"Tsukiko Offline Privacy Contract Violation: "
            f"Outbound network connection to '{address}' was strictly blocked by in-process network guard."
        )
        logger.error(msg)
        raise PrivacyViolationError(msg)

    return _ORIGINAL_SOCKET_CONNECT(self, address)


def _guarded_socket_connect_ex(self: socket.socket, address: Union[Tuple[Any, ...], str, bytes]) -> int:
    """Interception hook for socket.socket.connect_ex."""
    host = _extract_host_from_address(address)
    if host is not None and not is_loopback_address(host):
        msg = (
            f"Tsukiko Offline Privacy Contract Violation: "
            f"Outbound network connect_ex attempt to '{address}' was strictly blocked by in-process network guard."
        )
        logger.error(msg)
        raise PrivacyViolationError(msg)

    return _ORIGINAL_SOCKET_CONNECT_EX(self, address)


def _guarded_socket_sendto(self: socket.socket, data: bytes, *args: Any, **kwargs: Any) -> int:
    """Interception hook for socket.socket.sendto (UDP and connectionless sockets)."""
    address = None
    if len(args) == 1:
        address = args[0]
    elif len(args) >= 2:
        # Signature: sendto(data, flags, address)
        address = args[1]
    elif "address" in kwargs:
        address = kwargs["address"]

    if address is not None:
        host = _extract_host_from_address(address)
        if host is not None and not is_loopback_address(host):
            msg = (
                f"Tsukiko Offline Privacy Contract Violation: "
                f"Outbound UDP datagram transmission to '{address}' was strictly blocked by in-process network guard."
            )
            logger.error(msg)
            raise PrivacyViolationError(msg)

    return _ORIGINAL_SOCKET_SENDTO(self, data, *args, **kwargs)


def _guarded_create_connection(
    address: Tuple[str, int],
    timeout: Optional[float] = None,
    source_address: Optional[Tuple[str, int]] = None,
    *args: Any,
    **kwargs: Any,
) -> socket.socket:
    """Interception hook for socket.create_connection."""
    host = address[0] if isinstance(address, tuple) and len(address) >= 1 else str(address)
    if not is_loopback_address(host):
        msg = (
            f"Tsukiko Offline Privacy Contract Violation: "
            f"Outbound network connection to '{address}' was strictly blocked by in-process network guard."
        )
        logger.error(msg)
        raise PrivacyViolationError(msg)

    return _ORIGINAL_CREATE_CONNECTION(address, timeout=timeout, source_address=source_address, *args, **kwargs)


def _guarded_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
    """Interception hook for socket.getaddrinfo to prevent external DNS query leaks."""
    if host is not None and not is_loopback_address(str(host)):
        msg = (
            f"Tsukiko Offline Privacy Contract Violation: "
            f"DNS resolution for external host '{host}' was strictly blocked by in-process network guard."
        )
        logger.error(msg)
        raise PrivacyViolationError(msg)
    return _ORIGINAL_GETADDRINFO(host, port, *args, **kwargs)


def _guarded_gethostbyname(hostname: str) -> str:
    """Interception hook for socket.gethostbyname to prevent external DNS query leaks."""
    if not is_loopback_address(hostname):
        msg = (
            f"Tsukiko Offline Privacy Contract Violation: "
            f"DNS resolution for external hostname '{hostname}' was strictly blocked by in-process network guard."
        )
        logger.error(msg)
        raise PrivacyViolationError(msg)
    return _ORIGINAL_GETHOSTBYNAME(hostname)


def _guarded_gethostbyname_ex(hostname: str) -> Tuple[str, list[str], list[str]]:
    """Interception hook for socket.gethostbyname_ex to prevent external DNS query leaks."""
    if not is_loopback_address(hostname):
        msg = (
            f"Tsukiko Offline Privacy Contract Violation: "
            f"DNS extended resolution for external hostname '{hostname}' was strictly blocked by in-process network guard."
        )
        logger.error(msg)
        raise PrivacyViolationError(msg)
    return _ORIGINAL_GETHOSTBYNAME_EX(hostname)


def _guarded_gethostbyaddr(ip_address: str) -> Tuple[str, list[str], list[str]]:
    """Interception hook for socket.gethostbyaddr to prevent reverse DNS query leaks."""
    if not is_loopback_address(ip_address):
        msg = (
            f"Tsukiko Offline Privacy Contract Violation: "
            f"Reverse DNS lookup for IP '{ip_address}' was strictly blocked by in-process network guard."
        )
        logger.error(msg)
        raise PrivacyViolationError(msg)
    return _ORIGINAL_GETHOSTBYADDR(ip_address)


def _guarded_getnameinfo(sockaddr: Tuple[Any, ...], flags: int) -> Tuple[str, str]:
    """Interception hook for socket.getnameinfo to prevent reverse name resolution leaks."""
    host = sockaddr[0] if isinstance(sockaddr, tuple) and len(sockaddr) >= 1 else str(sockaddr)
    if not is_loopback_address(str(host)):
        msg = (
            f"Tsukiko Offline Privacy Contract Violation: "
            f"Reverse name lookup for address '{sockaddr}' was strictly blocked by in-process network guard."
        )
        logger.error(msg)
        raise PrivacyViolationError(msg)
    return _ORIGINAL_GETNAMEINFO(sockaddr, flags)


def enable_offline_guard() -> None:
    """Installs the in-process network interception hooks atomically.

    If installation fails partway through, rolls back all socket functions to original state.
    """
    global _GUARD_ACTIVE
    with _GUARD_LOCK:
        if _GUARD_ACTIVE:
            return

        try:
            socket.socket.connect = _guarded_socket_connect  # type: ignore
            socket.socket.connect_ex = _guarded_socket_connect_ex  # type: ignore
            socket.socket.sendto = _guarded_socket_sendto  # type: ignore
            socket.create_connection = _guarded_create_connection  # type: ignore
            socket.getaddrinfo = _guarded_getaddrinfo  # type: ignore
            socket.gethostbyname = _guarded_gethostbyname  # type: ignore
            socket.gethostbyname_ex = _guarded_gethostbyname_ex  # type: ignore
            socket.gethostbyaddr = _guarded_gethostbyaddr  # type: ignore
            socket.getnameinfo = _guarded_getnameinfo  # type: ignore
            _GUARD_ACTIVE = True
            logger.info("Technical Offline Privacy Guard is ACTIVE (all non-loopback sockets and DNS blocked).")
        except Exception as e:
            # Atomic rollback
            socket.socket.connect = _ORIGINAL_SOCKET_CONNECT  # type: ignore
            socket.socket.connect_ex = _ORIGINAL_SOCKET_CONNECT_EX  # type: ignore
            socket.socket.sendto = _ORIGINAL_SOCKET_SENDTO  # type: ignore
            socket.create_connection = _ORIGINAL_CREATE_CONNECTION  # type: ignore
            socket.getaddrinfo = _ORIGINAL_GETADDRINFO  # type: ignore
            socket.gethostbyname = _ORIGINAL_GETHOSTBYNAME  # type: ignore
            socket.gethostbyname_ex = _ORIGINAL_GETHOSTBYNAME_EX  # type: ignore
            socket.gethostbyaddr = _ORIGINAL_GETHOSTBYADDR  # type: ignore
            socket.getnameinfo = _ORIGINAL_GETNAMEINFO  # type: ignore
            _GUARD_ACTIVE = False
            logger.error(f"Failed to enable Offline Privacy Guard; rolled back to original socket state: {e}")
            raise


def disable_offline_guard() -> None:
    """Restores standard Python socket functions.

    Should ONLY be used for explicit test teardown, never during normal runtime lifecycle.
    """
    global _GUARD_ACTIVE
    with _GUARD_LOCK:
        if not _GUARD_ACTIVE:
            return
        socket.socket.connect = _ORIGINAL_SOCKET_CONNECT  # type: ignore
        socket.socket.connect_ex = _ORIGINAL_SOCKET_CONNECT_EX  # type: ignore
        socket.socket.sendto = _ORIGINAL_SOCKET_SENDTO  # type: ignore
        socket.create_connection = _ORIGINAL_CREATE_CONNECTION  # type: ignore
        socket.getaddrinfo = _ORIGINAL_GETADDRINFO  # type: ignore
        socket.gethostbyname = _ORIGINAL_GETHOSTBYNAME  # type: ignore
        socket.gethostbyname_ex = _ORIGINAL_GETHOSTBYNAME_EX  # type: ignore
        socket.gethostbyaddr = _ORIGINAL_GETHOSTBYADDR  # type: ignore
        socket.getnameinfo = _ORIGINAL_GETNAMEINFO  # type: ignore
        _GUARD_ACTIVE = False
        logger.info("Offline Privacy Guard disabled.")


def is_offline_guard_active() -> bool:
    """Returns True if the offline privacy guard is currently installed."""
    with _GUARD_LOCK:
        return _GUARD_ACTIVE
