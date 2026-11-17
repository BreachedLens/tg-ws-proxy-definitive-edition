"""Core transport interface for the bypass package.

``bypass/`` is fully decoupled from ``proxy/``, ``ui/`` and ``utils/`` on
purpose: only the Python standard library is imported here, so the whole
folder can be dropped into another host project (for example a fork of
Flowseal/zapret-discord-youtube) without touching a single import.

A *transport* is one strategy for reaching a destination that the local
network otherwise blocks. The host application asks :class:`BypassManager`
for a connection; the manager walks registered transports in priority order
and returns the first successful result, applying per-transport health
backoff so a dead strategy is not retried on every single connection.
"""
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional

log = logging.getLogger("bypass")

DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_BACKOFF_INITIAL = 30.0
DEFAULT_BACKOFF_MAX = 900.0


class BypassError(Exception):
    """Base class for every error raised by this package."""


class BypassUnavailable(BypassError):
    """The transport cannot be used at all (missing binary, bad config...)."""


class BypassConnectError(BypassError):
    """A connect attempt through a working transport failed."""


@dataclass
class ConnectRequest:
    """What the host application wants to reach."""

    host: str
    port: int
    sni: Optional[str] = None
    timeout: float = DEFAULT_CONNECT_TIMEOUT


@dataclass
class ConnectResult:
    """An established stream plus metadata about how it was reached.

    ``sni`` and ``host_header`` are populated by fronting transports so the
    caller knows which hostname the TLS stream pretends to be and which
    Host header to use in the application-level request.
    """

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    transport: str
    sni: Optional[str] = None
    host_header: Optional[str] = None


class BypassTransport(ABC):
    """Base class for a single bypass strategy.

    Subclasses implement :meth:`is_configured`, :meth:`is_available` and
    :meth:`connect`; health tracking (exponential backoff after failures)
    is provided here so every transport behaves the same way.
    """

    name = "base"
    #: lower value = tried earlier in the fallback chain
    priority = 100

    def __init__(
        self,
        *,
        backoff_initial: float = DEFAULT_BACKOFF_INITIAL,
        backoff_max: float = DEFAULT_BACKOFF_MAX,
    ) -> None:
        self.backoff_initial = backoff_initial
        self.backoff_max = backoff_max
        self._failures = 0
        self._retry_at = 0.0

    def is_configured(self) -> bool:
        """False when required files/binary/settings are missing."""
        return True

    async def is_available(self) -> bool:
        """Cheap runtime check; may return False without side effects."""
        return True

    @abstractmethod
    async def connect(self, request: ConnectRequest) -> ConnectResult:
        """Open a stream to ``request.host:port`` or raise BypassError."""
        raise NotImplementedError

    async def start(self) -> None:
        """Optional lifecycle hook (e.g. bring a tunnel up)."""

    async def stop(self) -> None:
        """Optional lifecycle hook (e.g. tear a tunnel down)."""

    # health tracking ------------------------------------------------

    def mark_success(self) -> None:
        self._failures = 0

    def mark_failure(self, exc: Optional[BaseException] = None) -> None:
        self._failures += 1
        backoff = min(
            self.backoff_initial * (2 ** (self._failures - 1)),
            self.backoff_max,
        )
        self._retry_at = time.monotonic() + backoff
        log.debug(
            "%s: failure #%d, cooling down for %.0fs (%r)",
            self.name, self._failures, backoff, exc,
        )

    @property
    def is_healthy(self) -> bool:
        return time.monotonic() >= self._retry_at

    def backoff_remaining(self) -> float:
        return max(0.0, self._retry_at - time.monotonic())


class BypassManager:
    """Ordered fallback chain over registered transports.

    Usage::

        manager = build_default_manager(BypassConfig(...))
        result = await manager.connect("149.154.167.220", 443)
        # result.reader / result.writer - established stream
    """

    def __init__(self) -> None:
        self._transports: Dict[str, BypassTransport] = {}

    def register(self, transport: BypassTransport) -> None:
        self._transports[transport.name] = transport

    def unregister(self, name: str) -> None:
        self._transports.pop(name, None)

    def get(self, name: str) -> Optional[BypassTransport]:
        return self._transports.get(name)

    @property
    def transports(self) -> List[BypassTransport]:
        return sorted(self._transports.values(), key=lambda t: t.priority)

    async def start_all(self) -> None:
        for transport in self.transports:
            if transport.is_configured():
                await transport.start()

    async def stop_all(self) -> None:
        for transport in reversed(self.transports):
            try:
                await transport.stop()
            except Exception:
                log.exception("%s: clean stop failed", transport.name)

    async def connect(
        self,
        host: str,
        port: int,
        *,
        sni: Optional[str] = None,
        timeout: float = DEFAULT_CONNECT_TIMEOUT,
    ) -> ConnectResult:
        """Try every configured, available, healthy transport in order."""
        request = ConnectRequest(host=host, port=port, sni=sni, timeout=timeout)
        failures: List[tuple] = []
        for transport in self.transports:
            if not transport.is_configured():
                continue
            if not transport.is_healthy:
                log.debug(
                    "%s: skipping, backoff for another %.0fs",
                    transport.name, transport.backoff_remaining(),
                )
                continue
            if not await transport.is_available():
                log.debug("%s: skipping, not available", transport.name)
                continue
            try:
                result = await transport.connect(request)
            except BypassError as exc:
                transport.mark_failure(exc)
                failures.append((transport.name, exc))
                log.warning(
                    "bypass transport %s failed for %s:%d: %r",
                    transport.name, host, port, exc,
                )
            except (asyncio.TimeoutError, OSError) as exc:
                transport.mark_failure(exc)
                failures.append((transport.name, exc))
                log.warning(
                    "bypass transport %s failed for %s:%d: %r",
                    transport.name, host, port, exc,
                )
            else:
                transport.mark_success()
                log.info("Connected to %s:%d via bypass/%s", host, port, transport.name)
                return result
        raise BypassConnectError(
            "all bypass transports failed for {}:{} ({})".format(
                host, port,
                "; ".join("{}: {!r}".format(n, e) for n, e in failures)
                or "no transports registered",
            )
        )

    async def check_all(self) -> Dict[str, Dict[str, object]]:
        """Diagnostics snapshot for the UI / logs."""
        report: Dict[str, Dict[str, object]] = {}
        for transport in self.transports:
            report[transport.name] = {
                "configured": transport.is_configured(),
                "available": await transport.is_available(),
                "healthy": transport.is_healthy,
                "backoff_remaining": transport.backoff_remaining(),
            }
        return report
