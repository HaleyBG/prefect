"""
prefect-network-guard: Outbound request whitelist proxy for Prefect.

Auto-loaded via .pth file when installed as a wheel (``pip install prefect-network-guard``).
For manual use, import this module **before** ``import prefect``.

Configuration via environment variables:
    PREFECT_OUTBOUND_ALLOWED_HOSTS   - comma-separated, e.g. "host1,host2"
    PREFECT_OUTBOUND_ALLOWED_CIDRS   - comma-separated, e.g. "10.0.0.0/8,172.16.0.0/12"
    PREFECT_OUTBOUND_BLOCKED_HOSTS   - comma-separated extra blocked hosts
    PREFECT_OUTBOUND_BLOCK_LOG_LEVEL - "DEBUG" to log all decisions (default "WARNING")

How it works:
    1. Monkey-patches ``socket.getaddrinfo`` — the low-level DNS resolution function
       that every Python network library (httpx, requests, websockets, amplitude, etc.)
       ultimately calls. This catches ALL outbound TCP/UDP connections.
    2. Monkey-patches ``httpx.Client.send`` / ``httpx.AsyncClient.send`` — adds a second
       guard layer with full URL context in error messages.
    3. Whitelist priority: explicit BLOCK > explicit ALLOW > CIDR match > default DENY.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from typing import ClassVar
from urllib.parse import urlparse

__all__: ClassVar[list[str]] = []

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Hosts that are always explicitly blocked (Prefect telemetry / Cloud endpoints).
_DEFAULT_BLOCKED_HOSTS: set[str] = {
    "sens-o-matic.prefect.io",
    "api2.amplitude.com",
    "api.prefect.cloud",
    "raw.githubusercontent.com",
}

# Hosts that are always allowed.
_DEFAULT_ALLOWED_HOSTS: set[str] = {
    "localhost",
    "127.0.0.1",
    "::1",
}

# CIDRs that are always allowed.
_DEFAULT_ALLOWED_CIDRS: set[str] = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
}


def _env_set(name: str) -> set[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return set()
    return {s.strip() for s in raw.split(",") if s.strip()}


BLOCKED_HOSTS: set[str] = (
    _DEFAULT_BLOCKED_HOSTS | _env_set("PREFECT_OUTBOUND_BLOCKED_HOSTS")
)
ALLOWED_HOSTS: set[str] = (
    _DEFAULT_ALLOWED_HOSTS | _env_set("PREFECT_OUTBOUND_ALLOWED_HOSTS")
)
ALLOWED_CIDRS: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
for _cidr_str in _DEFAULT_ALLOWED_CIDRS | _env_set("PREFECT_OUTBOUND_ALLOWED_CIDRS"):
    ALLOWED_CIDRS.add(ipaddress.ip_network(_cidr_str))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_log_level_str = os.environ.get(
    "PREFECT_OUTBOUND_BLOCK_LOG_LEVEL", "WARNING"
).upper()
_log_level = getattr(logging, _log_level_str, logging.WARNING)

logger = logging.getLogger("prefect_network_guard")
logger.setLevel(_log_level)
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(name)s] %(levelname)s %(message)s"))
    logger.addHandler(_h)
logger.propagate = False

# ---------------------------------------------------------------------------
# Guard / re-entrancy check
# ---------------------------------------------------------------------------

# We need the resolver itself to bypass the guard, otherwise _resolve_host's
# internal call to socket.getaddrinfo would trigger the guard recursively.
_inside_guard: bool = False

# ---------------------------------------------------------------------------
# Resolver cache
# ---------------------------------------------------------------------------

_resolve_cache: dict[str, str | None] = {}

# Snapshot the original now, before we patch socket.
_original_getaddrinfo = socket.getaddrinfo


def _resolve_host(hostname: str) -> str | None:
    """Resolve hostname → IP string.  Cached per-process.

    Uses _original_getaddrinfo with _inside_guard set so it never triggers
    the patched guard during its own lookups.
    """
    if hostname in _resolve_cache:
        return _resolve_cache[hostname]

    # Raw IP addresses don't need DNS.
    try:
        ipaddress.ip_address(hostname)
        _resolve_cache[hostname] = hostname
        return hostname
    except ValueError:
        pass

    global _inside_guard
    try:
        _inside_guard = True
        addrs = _original_getaddrinfo(
            hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.gaierror:
        _resolve_cache[hostname] = None
        return None
    finally:
        _inside_guard = False

    if addrs:
        ip = addrs[0][4][0]
        _resolve_cache[hostname] = ip
        return ip

    _resolve_cache[hostname] = None
    return None


def _ip_in_any_cidr(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in ALLOWED_CIDRS)


# ---------------------------------------------------------------------------
# Core decision function
# ---------------------------------------------------------------------------

def is_allowed(hostname: str) -> bool:
    """Return True if *hostname* is allowed to be contacted.

    Priority: explicit BLOCK > explicit ALLOW > CIDR match > default DENY.
    """
    # 1. Explicit block list takes absolute priority.
    if hostname in BLOCKED_HOSTS:
        logger.debug("hostname=%r in BLOCKED_HOSTS → DENY", hostname)
        return False

    # 2. Explicit allow list.
    if hostname in ALLOWED_HOSTS:
        logger.debug("hostname=%r in ALLOWED_HOSTS → ALLOW", hostname)
        return True

    # 3. CIDR match (requires DNS resolution).
    ip = _resolve_host(hostname)
    if ip is not None and _ip_in_any_cidr(ip):
        logger.debug("hostname=%r ip=%r in ALLOWED_CIDRS → ALLOW", hostname, ip)
        return True

    logger.debug(
        "hostname=%r ip=%r NOT in any whitelist → DENY",
        hostname,
        ip if ip else "unresolvable",
    )
    return False


# ---------------------------------------------------------------------------
# Layer 1: socket.getaddrinfo guard
# ---------------------------------------------------------------------------

def _guarded_getaddrinfo(
    host: str | bytes | None,
    port: int | str | None,
    family: int = socket.AF_UNSPEC,
    type: int = socket.SOCK_STREAM,
    proto: int = 0,
    flags: int = 0,
) -> list[
    tuple[
        socket.AddressFamily,
        socket.SocketKind,
        int,
        str,
        tuple[str, int] | tuple[str, int, int, int],
    ]
]:
    # Normalize host argument.
    hostname: str | None = None
    if isinstance(host, bytes):
        hostname = host.decode("ascii")
    elif isinstance(host, str):
        hostname = host

    # Pass-through: internal resolution, raw IPs, or port-only lookups.
    if _inside_guard or hostname is None:
        return _original_getaddrinfo(host, port, family, type, proto, flags)

    if not is_allowed(hostname):
        raise ConnectionRefusedError(
            f"[SECURITY] Outbound connection to '{hostname}' is blocked by "
            f"the outbound whitelist. Add it to "
            f"PREFECT_OUTBOUND_ALLOWED_HOSTS to permit this connection."
        )

    return _original_getaddrinfo(host, port, family, type, proto, flags)


socket.getaddrinfo = _guarded_getaddrinfo

# ---------------------------------------------------------------------------
# Layer 2: httpx guard (provides full-URL context in error messages)
# ---------------------------------------------------------------------------

try:
    import httpx

    _original_async_send = httpx.AsyncClient.send
    _original_sync_send = httpx.Client.send

    async def _guarded_async_send(self, request, *args, **kwargs):
        parsed = urlparse(str(request.url))
        hostname = parsed.hostname
        if hostname and not is_allowed(hostname):
            raise ConnectionRefusedError(
                f"[SECURITY] HTTP request to '{request.url}' is blocked by "
                f"the outbound whitelist. Host '{hostname}' is not allowed."
            )
        return await _original_async_send(self, request, *args, **kwargs)

    def _guarded_sync_send(self, request, *args, **kwargs):
        parsed = urlparse(str(request.url))
        hostname = parsed.hostname
        if hostname and not is_allowed(hostname):
            raise ConnectionRefusedError(
                f"[SECURITY] HTTP request to '{request.url}' is blocked by "
                f"the outbound whitelist. Host '{hostname}' is not allowed."
            )
        return _original_sync_send(self, request, *args, **kwargs)

    httpx.AsyncClient.send = _guarded_async_send  # type: ignore[method-assign]
    httpx.Client.send = _guarded_sync_send  # type: ignore[method-assign]

    logger.info("httpx Client/AsyncClient.send patched successfully")

except ImportError:
    logger.warning("httpx not available - skipping httpx-level guard")

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

logger.info(
    "Outbound whitelist loaded: blocked=%d hosts, allowed=%d hosts, allowed=%d CIDRs",
    len(BLOCKED_HOSTS),
    len(ALLOWED_HOSTS),
    len(ALLOWED_CIDRS),
)
