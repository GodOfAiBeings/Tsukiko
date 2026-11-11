"""
Tsukiko In-Process Offline Privacy Guard
Technically enforces the zero-outbound-network guarantee at the Python socket and DNS level.
Blocks any non-loopback outbound connection, transmission, and external DNS resolution attempt with a PrivacyViolationError.

Note on Security Scope:
This in-process socket interception is defense-in-depth within the Python runtime.
It does not constitute an operating system kernel boundary against external processes or native C extensions.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from typing import Any, Optional, Tuple, Union

from app.core.logging.logger import get_logger

logger = get_logger("SYSTEM")

AF_UNIX = getattr(socket, "AF_UNIX", None)


class PrivacyViolationError(PermissionError, RuntimeError):
    """Raised when runtime code or a dependency attempts an unauthorized outbound network connection, transmission, or DNS lookup."""
    pass


_GUARD_LOCK = threading.RLock()
_GUARD_ACTIVE = False

# Saved references to original unhooked socket functions
_ORIGINAL_SOCKET_CONNECT = socket.socket.connect
_ORIGINAL_SOCKET_CONNECT_EX = socket.socket.connect_ex
_ORIGINAL_SOCKET_SEND = socket.socket.send
_ORIGINAL_SOCKET_SENDALL = socket.socket.sendall
_ORIGINAL_SOCKET_SENDMSG = getattr(socket.socket, "sendmsg", None)
_ORIGINAL_SOCKET_SENDTO = socket.socket.sendto
_ORIGINAL_CREATE_CONNECTION = socket.create_connection
_ORIGINAL_GETADDRINFO = socket.getaddrinfo
_ORIGINAL_GETHOSTBYNAME = socket.gethostbyname
_ORIGINAL_GETHOSTBYNAME_EX = socket.gethostbyname_ex
_ORIGINAL_GETHOSTBYADDR = socket.gethostbyaddr
_ORIGINAL_GETNAMEINFO = socket.getnameinfo


def is_numeric_loopback_ip(host: Any, family: Optional[int] = None) -> bool:
    """Validates whether host is strictly a numeric IPv4 or IPv6 loopback IP.

    Permits:
    - IPv4 loopback (127.0.0.0/8)
    - IPv6 loopback (::1)

    Rejects:
    - 'localhost' (hostname, not a numeric IP; requires local numeric resolution)
    - 0.0.0.0 and :: (unspecified addresses)
    - Empty or None values
    - External and private LAN non-loopback addresses
    """
    if host is None:
        return False

    clean = str(host).strip().lower().rstrip(".")
    if not clean:
        return False

    if clean in ("0.0.0.0", "::", "localhost"):
        return False

    try:
        ip = ipaddress.ip_address(clean)
        if ip.is_unspecified or not ip.is_loopback:
            return False
        if family == socket.AF_INET and not isinstance(ip, ipaddress.IPv4Address):
            return False
        if family == socket.AF_INET6 and not isinstance(ip, ipaddress.IPv6Address):
            return False
        return True
    except ValueError:
        return False


def is_valid_loopback_ip(host: Any, family: Optional[int] = None) -> bool:
    """Validates IPv4 or IPv6 numeric loopback addresses strictly without initiating network DNS queries.

    Requires numeric loopback IP. Hostnames such as 'localhost' are rejected to prevent hostname trust
    without local numeric-only resolution.
    """
    return is_numeric_loopback_ip(host, family=family)


def is_loopback_address(host: Any) -> bool:
    """Convenience alias for is_numeric_loopback_ip."""
    return is_numeric_loopback_ip(host)


def resolve_localhost_numeric(family: Optional[int] = None) -> list[str]:
    """Deterministically maps 'localhost' to numeric loopback IP addresses without invoking any system resolver."""
    if family == socket.AF_INET:
        return ["127.0.0.1"]
    elif family == socket.AF_INET6:
        return ["::1"]
    return ["127.0.0.1", "::1"]


def _normalize_destination_address(
    sock: Optional[socket.socket],
    address: Union[Tuple[Any, ...], str, bytes],
) -> Union[Tuple[Any, ...], str, bytes]:
    """Normalizes destination address so 'localhost' is converted to numeric loopback IP.

    Prevents the underlying OS C-level connect implementation from performing an unrestricted DNS lookup.
    """
    if isinstance(address, tuple) and len(address) >= 2:
        host, port = address[0], address[1]
        clean = str(host).strip().lower().rstrip(".")
        if clean == "localhost":
            family = getattr(sock, "family", socket.AF_INET) if sock is not None else socket.AF_INET
            resolved_ip = "::1" if family == socket.AF_INET6 else "127.0.0.1"
            return (resolved_ip, port, *address[2:])
    return address


def _is_allowed_destination(sock: Optional[socket.socket], address: Any) -> bool:
    """Family-aware destination address validation.

    Strictly enforces:
    - AF_UNIX: validates as local filesystem IPC path or abstract socket (string/bytes).
    - AF_INET: strictly validates IPv4 numeric loopback or 'localhost' resolved strictly to 127.0.0.1.
    - AF_INET6: strictly validates IPv6 numeric loopback or 'localhost' resolved strictly to ::1.
    - Unsupported / unknown socket families: FAILS CLOSED immediately (returns False), even if address looks like a tuple.
    - If sock is None: validates address tuple against numeric loopback or 'localhost'.
    """
    if address is None:
        return False

    # When socket instance is present, strictly enforce socket family support
    if sock is not None:
        family = getattr(sock, "family", None)

        # 1. AF_UNIX local IPC check
        if AF_UNIX is not None and family == AF_UNIX:
            if isinstance(address, (str, bytes)) and len(address) > 0:
                return True
            return False

        # 2. IPv4 Internet socket
        if family == socket.AF_INET:
            if not isinstance(address, tuple) or len(address) < 2:
                return False
            host, port = address[0], address[1]
            try:
                port_num = int(port)
                if not (0 <= port_num <= 65535):
                    return False
            except (ValueError, TypeError):
                return False

            clean = str(host).strip().lower().rstrip(".")
            if clean == "localhost":
                return True
            return is_numeric_loopback_ip(clean, family=socket.AF_INET)

        # 3. IPv6 Internet socket
        if family == socket.AF_INET6:
            if not isinstance(address, tuple) or len(address) < 2:
                return False
            host, port = address[0], address[1]
            try:
                port_num = int(port)
                if not (0 <= port_num <= 65535):
                    return False
            except (ValueError, TypeError):
                return False

            clean = str(host).strip().lower().rstrip(".")
            if clean == "localhost":
                return True
            return is_numeric_loopback_ip(clean, family=socket.AF_INET6)

        # 4. Any other or unsupported socket family fails closed
        return False

    # When sock is None (e.g. create_connection or standalone address check)
    if isinstance(address, tuple) and len(address) >= 2:
        host, port = address[0], address[1]
        try:
            port_num = int(port)
            if not (0 <= port_num <= 65535):
                return False
        except (ValueError, TypeError):
            return False

        clean = str(host).strip().lower().rstrip(".")
        if clean == "localhost":
            return True
        return is_numeric_loopback_ip(clean)

    # String or other address without an AF_UNIX socket fails closed
    return False


def _validate_connected_socket(sock: socket.socket) -> None:
    """Validates that a connected socket's peer is a permitted local loopback or local IPC endpoint.

    For unconnected sockets, allows standard socket error behavior (e.g. ENOTCONN).
    """
    try:
        peer = sock.getpeername()
    except OSError:
        # Socket is not connected; normal socket methods will raise ENOTCONN
        return

    if not _is_allowed_destination(sock, peer):
        msg = (
            f"Tsukiko Offline Privacy Contract Violation: "
            f"Outbound transmission on connected socket to '{peer}' "
            f"was strictly blocked by in-process network guard."
        )
        logger.error(msg)
        raise PrivacyViolationError(msg)


def _guarded_socket_connect(self: socket.socket, address: Union[Tuple[Any, ...], str, bytes]) -> None:
    """Interception hook for socket.socket.connect."""
    if not _is_allowed_destination(self, address):
        msg = (
            f"Tsukiko Offline Privacy Contract Violation: "
            f"Outbound network connection to '{address}' was strictly blocked by in-process network guard."
        )
        logger.error(msg)
        raise PrivacyViolationError(msg)

    norm_address = _normalize_destination_address(self, address)
    return _ORIGINAL_SOCKET_CONNECT(self, norm_address)


def _guarded_socket_connect_ex(self: socket.socket, address: Union[Tuple[Any, ...], str, bytes]) -> int:
    """Interception hook for socket.socket.connect_ex."""
    if not _is_allowed_destination(self, address):
        msg = (
            f"Tsukiko Offline Privacy Contract Violation: "
            f"Outbound network connect_ex attempt to '{address}' was strictly blocked by in-process network guard."
        )
        logger.error(msg)
        raise PrivacyViolationError(msg)

    norm_address = _normalize_destination_address(self, address)
    return _ORIGINAL_SOCKET_CONNECT_EX(self, norm_address)


def _guarded_socket_send(self: socket.socket, data: bytes, flags: int = 0) -> int:
    """Interception hook for socket.socket.send."""
    _validate_connected_socket(self)
    return _ORIGINAL_SOCKET_SEND(self, data, flags)


def _guarded_socket_sendall(self: socket.socket, data: bytes, flags: int = 0) -> None:
    """Interception hook for socket.socket.sendall."""
    _validate_connected_socket(self)
    return _ORIGINAL_SOCKET_SENDALL(self, data, flags)


def _guarded_socket_sendmsg(
    self: socket.socket,
    buffers: Any,
    ancdata: Any = (),
    flags: int = 0,
    address: Any = None,
) -> int:
    """Interception hook for socket.socket.sendmsg (when available)."""
    if _ORIGINAL_SOCKET_SENDMSG is None:
        raise NotImplementedError("sendmsg is not supported on this platform.")

    if address is not None:
        if not _is_allowed_destination(self, address):
            msg = (
                f"Tsukiko Offline Privacy Contract Violation: "
                f"Outbound sendmsg transmission to '{address}' was strictly blocked by in-process network guard."
            )
            logger.error(msg)
            raise PrivacyViolationError(msg)
        norm_address = _normalize_destination_address(self, address)
        return _ORIGINAL_SOCKET_SENDMSG(self, buffers, ancdata, flags, norm_address)
    else:
        _validate_connected_socket(self)
        return _ORIGINAL_SOCKET_SENDMSG(self, buffers, ancdata, flags)


def _guarded_socket_sendto(self: socket.socket, data: bytes, *args: Any, **kwargs: Any) -> int:
    """Interception hook for socket.socket.sendto (UDP and connectionless sockets)."""
    address = None
    if len(args) == 1:
        address = args[0]
    elif len(args) >= 2:
        address = args[1]
    elif "address" in kwargs:
        address = kwargs["address"]

    if address is not None:
        if not _is_allowed_destination(self, address):
            msg = (
                f"Tsukiko Offline Privacy Contract Violation: "
                f"Outbound UDP datagram transmission to '{address}' was strictly blocked by in-process network guard."
            )
            logger.error(msg)
            raise PrivacyViolationError(msg)
        norm_address = _normalize_destination_address(self, address)
        if len(args) == 1:
            return _ORIGINAL_SOCKET_SENDTO(self, data, norm_address, **kwargs)
        elif len(args) >= 2:
            new_args = list(args)
            new_args[1] = norm_address
            return _ORIGINAL_SOCKET_SENDTO(self, data, *new_args, **kwargs)
        else:
            kwargs["address"] = norm_address
            return _ORIGINAL_SOCKET_SENDTO(self, data, *args, **kwargs)
    else:
        _validate_connected_socket(self)
        return _ORIGINAL_SOCKET_SENDTO(self, data, *args, **kwargs)


def _guarded_create_connection(
    address: Tuple[str, int],
    timeout: Optional[float] = None,
    source_address: Optional[Tuple[str, int]] = None,
    *args: Any,
    **kwargs: Any,
) -> socket.socket:
    """Interception hook for socket.create_connection."""
    if not _is_allowed_destination(None, address):
        msg = (
            f"Tsukiko Offline Privacy Contract Violation: "
            f"Outbound network connection to '{address}' was strictly blocked by in-process network guard."
        )
        logger.error(msg)
        raise PrivacyViolationError(msg)

    norm_address = _normalize_destination_address(None, address)
    return _ORIGINAL_CREATE_CONNECTION(norm_address, timeout=timeout, source_address=source_address, *args, **kwargs)


def _guarded_getaddrinfo(
    host: Any,
    port: Any,
    family: int = 0,
    type: int = 0,
    proto: int = 0,
    flags: int = 0,
) -> Any:
    """Interception hook for socket.getaddrinfo to prevent external DNS query leaks."""
    if host is None:
        return _ORIGINAL_GETADDRINFO(None, port, family, type, proto, flags)

    clean = str(host).strip().lower().rstrip(".")
    if clean in ("0.0.0.0", "::"):
        raise PrivacyViolationError(
            f"Tsukiko Offline Privacy Contract Violation: "
            f"DNS resolution for unspecified address '{host}' was strictly blocked."
        )

    # For localhost, resolve locally with AI_NUMERICHOST to guarantee zero external DNS queries
    if clean == "localhost":
        results = []
        if family in (socket.AF_INET, socket.AF_UNSPEC, 0):
            try:
                res4 = _ORIGINAL_GETADDRINFO(
                    "127.0.0.1", port, socket.AF_INET, type, proto, flags | socket.AI_NUMERICHOST
                )
                results.extend(res4)
            except Exception:
                pass
        if family in (socket.AF_INET6, socket.AF_UNSPEC, 0):
            try:
                res6 = _ORIGINAL_GETADDRINFO(
                    "::1", port, socket.AF_INET6, type, proto, flags | socket.AI_NUMERICHOST
                )
                results.extend(res6)
            except Exception:
                pass
        if results:
            return results
        raise PrivacyViolationError(f"Local numeric resolution for 'localhost' failed on port '{port}'.")

    # If host is a numeric loopback IP, resolve strictly with AI_NUMERICHOST
    if is_numeric_loopback_ip(clean):
        req_fam = socket.AF_INET6 if ":" in clean else socket.AF_INET
        if family not in (0, socket.AF_UNSPEC, req_fam):
            raise PrivacyViolationError(f"Address family mismatch for numeric loopback IP '{clean}'.")
        return _ORIGINAL_GETADDRINFO(clean, port, req_fam, type, proto, flags | socket.AI_NUMERICHOST)

    # All external names, non-loopback IPs, and LAN hostnames FAIL CLOSED
    msg = (
        f"Tsukiko Offline Privacy Contract Violation: "
        f"DNS resolution for external host '{host}' was strictly blocked by in-process network guard."
    )
    logger.error(msg)
    raise PrivacyViolationError(msg)


def _guarded_gethostbyname(hostname: str) -> str:
    """Interception hook for socket.gethostbyname to prevent external DNS query leaks."""
    clean = str(hostname).strip().lower().rstrip(".")
    if clean in ("0.0.0.0", "::"):
        raise PrivacyViolationError(f"DNS resolution for unspecified address '{hostname}' was blocked.")

    if clean == "localhost":
        return "127.0.0.1"

    if is_numeric_loopback_ip(clean, family=socket.AF_INET):
        return clean

    msg = (
        f"Tsukiko Offline Privacy Contract Violation: "
        f"DNS resolution for external hostname '{hostname}' was strictly blocked by in-process network guard."
    )
    logger.error(msg)
    raise PrivacyViolationError(msg)


def _guarded_gethostbyname_ex(hostname: str) -> Tuple[str, list[str], list[str]]:
    """Interception hook for socket.gethostbyname_ex to prevent external DNS query leaks."""
    clean = str(hostname).strip().lower().rstrip(".")
    if clean in ("0.0.0.0", "::"):
        raise PrivacyViolationError(f"DNS resolution for unspecified address '{hostname}' was blocked.")

    if clean == "localhost":
        return ("localhost", [], ["127.0.0.1"])

    if is_numeric_loopback_ip(clean, family=socket.AF_INET):
        return (clean, [], [clean])

    msg = (
        f"Tsukiko Offline Privacy Contract Violation: "
        f"DNS extended resolution for external hostname '{hostname}' was strictly blocked by in-process network guard."
    )
    logger.error(msg)
    raise PrivacyViolationError(msg)


def _guarded_gethostbyaddr(ip_address: str) -> Tuple[str, list[str], list[str]]:
    """Interception hook for socket.gethostbyaddr to prevent reverse DNS query leaks."""
    clean = str(ip_address).strip().lower().rstrip(".")
    if clean in ("0.0.0.0", "::"):
        raise PrivacyViolationError(f"Reverse DNS lookup for unspecified address '{ip_address}' was blocked.")

    if is_numeric_loopback_ip(clean):
        return ("localhost", [], [clean])

    msg = (
        f"Tsukiko Offline Privacy Contract Violation: "
        f"Reverse DNS lookup for IP '{ip_address}' was strictly blocked by in-process network guard."
    )
    logger.error(msg)
    raise PrivacyViolationError(msg)


def _guarded_getnameinfo(sockaddr: Tuple[Any, ...], flags: int) -> Tuple[str, str]:
    """Interception hook for socket.getnameinfo to prevent reverse name resolution leaks."""
    if not isinstance(sockaddr, tuple) or len(sockaddr) < 2:
        raise PrivacyViolationError(f"Malformed sockaddr: '{sockaddr}'")

    host = sockaddr[0]
    clean = str(host).strip().lower().rstrip(".")
    if clean in ("0.0.0.0", "::"):
        raise PrivacyViolationError(f"Reverse name lookup for unspecified address '{sockaddr}' was blocked.")

    if is_numeric_loopback_ip(clean) or clean == "localhost":
        return ("localhost", str(sockaddr[1]))

    msg = (
        f"Tsukiko Offline Privacy Contract Violation: "
        f"Reverse name lookup for address '{sockaddr}' was strictly blocked by in-process network guard."
    )
    logger.error(msg)
    raise PrivacyViolationError(msg)


def enable_offline_guard() -> None:
    """Installs in-process network interception hooks atomically.

    If installation fails partway through, rolls back all socket functions to original state.
    """
    global _GUARD_ACTIVE
    with _GUARD_LOCK:
        if _GUARD_ACTIVE:
            return

        try:
            socket.socket.connect = _guarded_socket_connect  # type: ignore
            socket.socket.connect_ex = _guarded_socket_connect_ex  # type: ignore
            socket.socket.send = _guarded_socket_send  # type: ignore
            socket.socket.sendall = _guarded_socket_sendall  # type: ignore
            if _ORIGINAL_SOCKET_SENDMSG is not None:
                socket.socket.sendmsg = _guarded_socket_sendmsg  # type: ignore
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
            socket.socket.send = _ORIGINAL_SOCKET_SEND  # type: ignore
            socket.socket.sendall = _ORIGINAL_SOCKET_SENDALL  # type: ignore
            if _ORIGINAL_SOCKET_SENDMSG is not None:
                socket.socket.sendmsg = _ORIGINAL_SOCKET_SENDMSG  # type: ignore
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
        socket.socket.send = _ORIGINAL_SOCKET_SEND  # type: ignore
        socket.socket.sendall = _ORIGINAL_SOCKET_SENDALL  # type: ignore
        if _ORIGINAL_SOCKET_SENDMSG is not None:
            socket.socket.sendmsg = _ORIGINAL_SOCKET_SENDMSG  # type: ignore
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
