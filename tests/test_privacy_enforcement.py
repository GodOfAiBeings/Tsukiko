"""
Comprehensive regression tests for Tsukiko Offline Privacy Guard.
Covers all 14 audit criteria:
1. IPv4 loopback TCP.
2. IPv6 loopback TCP.
3. IPv4 connected UDP.
4. UDP sendto.
5. Both sendto signatures.
6. External connect, connect_ex, and create_connection.
7. External send, sendall, and sendmsg.
8. External DNS and reverse DNS requests.
9. Unspecified addresses (0.0.0.0, ::).
10. Empty and malformed addresses.
11. AF_UNIX local IPC where supported or simulated.
12. Guard activation failure and atomic rollback.
13. Repeated guard activation.
14. Explicit test teardown and restoration.
All tests use controlled local loopback sockets or mocks. Zero external Internet requests.
"""

from __future__ import annotations

import socket
import threading
from unittest.mock import MagicMock, patch
import pytest

from app.core.privacy.enforcement import (
    AF_UNIX,
    PrivacyViolationError,
    _is_allowed_destination,
    disable_offline_guard,
    enable_offline_guard,
    is_loopback_address,
    is_offline_guard_active,
    is_valid_loopback_ip,
)


@pytest.fixture(autouse=True)
def guard_test_lifecycle():
    """Ensures offline guard is enabled for test and cleanly disabled afterwards."""
    enable_offline_guard()
    yield
    disable_offline_guard()


# 1. IPv4 Loopback TCP
def test_ipv4_loopback_tcp_allowed():
    """Permits local IPv4 TCP connections and data exchange on 127.0.0.1."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    conn, _ = server.accept()

    try:
        client.sendall(b"ping")
        data = conn.recv(1024)
        assert data == b"ping"
        conn.sendall(b"pong")
        data2 = client.recv(1024)
        assert data2 == b"pong"
    finally:
        client.close()
        conn.close()
        server.close()


# 2. IPv6 Loopback TCP
def test_ipv6_loopback_tcp_allowed():
    """Permits local IPv6 TCP connections on ::1 if supported by host networking."""
    if not socket.has_ipv6:
        pytest.skip("IPv6 not supported on this platform.")

    try:
        server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        server.bind(("::1", 0))
        server.listen(1)
        port = server.getsockname()[1]
    except OSError:
        pytest.skip("IPv6 loopback bind failed on host.")

    client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        client.connect(("::1", port))
        conn, _ = server.accept()
        client.send(b"ping6")
        data = conn.recv(1024)
        assert data == b"ping6"
        conn.close()
    finally:
        client.close()
        server.close()


# 3. IPv4 Connected UDP
def test_ipv4_connected_udp_allowed():
    """Permits connected UDP sending to local loopback 127.0.0.1."""
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    port = receiver.getsockname()[1]

    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.connect(("127.0.0.1", port))

    try:
        sender.send(b"udp-packet")
        data, _ = receiver.recvfrom(1024)
        assert data == b"udp-packet"
    finally:
        sender.close()
        receiver.close()


# 4. UDP sendto (Signature 1: data, address)
def test_udp_sendto_signature_1_allowed():
    """Permits UDP sendto(data, address) to 127.0.0.1."""
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    port = receiver.getsockname()[1]

    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        bytes_sent = sender.sendto(b"msg1", ("127.0.0.1", port))
        assert bytes_sent == 4
        data, addr = receiver.recvfrom(1024)
        assert data == b"msg1"
    finally:
        sender.close()
        receiver.close()


# 5. UDP sendto (Signature 2: data, flags, address)
def test_udp_sendto_signature_2_allowed():
    """Permits UDP sendto(data, flags, address) to 127.0.0.1."""
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    port = receiver.getsockname()[1]

    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        bytes_sent = sender.sendto(b"msg2", 0, ("127.0.0.1", port))
        assert bytes_sent == 4
        data, addr = receiver.recvfrom(1024)
        assert data == b"msg2"
    finally:
        sender.close()
        receiver.close()


# 6. External connect, connect_ex, create_connection
def test_external_connect_methods_strictly_blocked():
    """Blocks external connect, connect_ex, and create_connection."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(PrivacyViolationError):
            s.connect(("8.8.8.8", 53))

        with pytest.raises(PrivacyViolationError):
            s.connect_ex(("1.1.1.1", 443))

        with pytest.raises(PrivacyViolationError):
            socket.create_connection(("9.9.9.9", 80), timeout=0.1)
    finally:
        s.close()


# 7. External send, sendall, and sendmsg
def test_external_send_methods_strictly_blocked():
    """Blocks send, sendall, and sendmsg when peer destination is non-loopback."""
    # Simulate a connected socket pointing to an external address
    mock_sock = MagicMock(spec=socket.socket)
    mock_sock.family = socket.AF_INET
    mock_sock.getpeername.return_value = ("8.8.8.8", 443)

    from app.core.privacy.enforcement import (
        _guarded_socket_send,
        _guarded_socket_sendall,
        _guarded_socket_sendmsg,
    )

    with pytest.raises(PrivacyViolationError):
        _guarded_socket_send(mock_sock, b"data")

    with pytest.raises(PrivacyViolationError):
        _guarded_socket_sendall(mock_sock, b"data")

    with pytest.raises(PrivacyViolationError):
        _guarded_socket_sendmsg(mock_sock, [b"data"])

    # sendmsg with explicit external address argument
    with pytest.raises(PrivacyViolationError):
        _guarded_socket_sendmsg(mock_sock, [b"data"], address=("1.1.1.1", 80))


# 8. External DNS and reverse DNS requests
def test_external_dns_requests_strictly_blocked():
    """Blocks forward and reverse DNS requests targeting external names or IPs."""
    with pytest.raises(PrivacyViolationError):
        socket.getaddrinfo("api.anthropic.com", 443)

    with pytest.raises(PrivacyViolationError):
        socket.gethostbyname("api.openai.com")

    with pytest.raises(PrivacyViolationError):
        socket.gethostbyname_ex("huggingface.co")

    with pytest.raises(PrivacyViolationError):
        socket.gethostbyaddr("8.8.4.4")

    with pytest.raises(PrivacyViolationError):
        socket.getnameinfo(("8.8.8.8", 53), 0)


# 9. Unspecified addresses
def test_unspecified_addresses_strictly_rejected():
    """Rejects 0.0.0.0 and :: explicitly."""
    assert is_valid_loopback_ip("0.0.0.0") is False
    assert is_valid_loopback_ip("::") is False

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(PrivacyViolationError):
            s.connect(("0.0.0.0", 80))
    finally:
        s.close()


# 10. Empty and malformed addresses
def test_empty_and_malformed_addresses_rejected():
    """Fails closed on None, empty string, malformed tuples, and invalid types."""
    assert is_valid_loopback_ip(None) is False
    assert is_valid_loopback_ip("") is False
    assert is_valid_loopback_ip("   ") is False
    assert is_valid_loopback_ip("not-an-ip") is False

    assert _is_allowed_destination(None, None) is False
    assert _is_allowed_destination(None, ("127.0.0.1",)) is False  # tuple too short
    assert _is_allowed_destination(None, ("127.0.0.1", "invalid_port")) is False
    assert _is_allowed_destination(None, 12345) is False  # invalid type


# 11. AF_UNIX communication where supported or simulated
def test_af_unix_local_ipc_validation():
    """Permits local filesystem paths for AF_UNIX sockets and rejects them on Internet sockets."""
    mock_unix_sock = MagicMock()
    mock_unix_sock.family = 1  # Standard AF_UNIX family value

    with patch("app.core.privacy.enforcement.AF_UNIX", 1):
        # Local filesystem path or abstract socket must be permitted for AF_UNIX
        assert _is_allowed_destination(mock_unix_sock, "/tmp/tsukiko_local.sock") is True
        assert _is_allowed_destination(mock_unix_sock, b"/tmp/tsukiko_bytes.sock") is True
        assert _is_allowed_destination(mock_unix_sock, "") is False  # Empty path rejected

    # On an Internet socket (AF_INET), a filesystem path is NOT a valid destination
    mock_inet_sock = MagicMock()
    mock_inet_sock.family = socket.AF_INET
    assert _is_allowed_destination(mock_inet_sock, "/tmp/tsukiko_local.sock") is False


# 12. Guard activation failure and atomic rollback
def test_guard_activation_failure_atomic_rollback():
    """If an exception occurs during guard installation, all socket functions must be rolled back."""
    from app.core.privacy.enforcement import _ORIGINAL_SOCKET_CONNECT

    disable_offline_guard()
    assert is_offline_guard_active() is False

    with patch("app.core.privacy.enforcement.logger.info", side_effect=RuntimeError("Simulated activation failure")):
        with pytest.raises(RuntimeError) as exc_info:
            enable_offline_guard()
        assert "Simulated activation failure" in str(exc_info.value)

        # Guard state must remain False and not corrupted
        assert is_offline_guard_active() is False
        # Verify original socket connect was restored by atomic rollback
        assert socket.socket.connect == _ORIGINAL_SOCKET_CONNECT


# 13. Repeated guard activation
def test_repeated_guard_activation_is_idempotent():
    """Repeated calls to enable_offline_guard do not double-wrap or fail."""
    enable_offline_guard()
    enable_offline_guard()
    enable_offline_guard()
    assert is_offline_guard_active() is True


# 14. Explicit test teardown and restoration
def test_explicit_teardown_restores_original_functions():
    """Calling disable_offline_guard cleanly restores standard socket functions."""
    enable_offline_guard()
    assert is_offline_guard_active() is True

    disable_offline_guard()
    assert is_offline_guard_active() is False

    # Under disabled guard, external gethostbyname does not raise PrivacyViolationError
    # (may succeed or raise socket.gaierror depending on network, but not PrivacyViolationError)
    try:
        # Resolve localhost
        res = socket.gethostbyname("localhost")
        assert res in ("127.0.0.1", "::1")
    except PrivacyViolationError:
        pytest.fail("PrivacyViolationError raised after disable_offline_guard!")
