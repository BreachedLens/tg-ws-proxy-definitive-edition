"""Alternative CDN / domain-fronting transport.

Replaces (or supplements) dead Cloudflare endpoints with configurable
fronting providers: another CDN (Fastly, Google frontends), a custom SNI,
or a custom Host header override.

How fronting works here:

1. The TCP connection is opened to the provider's edge — ``connect_ip``
   when set, otherwise plain DNS resolution of the fronting domain.
2. The TLS ClientHello carries the *fronting* SNI (``provider.sni``).
3. Application-level traffic (the WebSocket upgrade path and the Host
   header) carries the real destination, so the CDN edge routes it onwards
   to Telegram.

Whether a given CDN honours Host-based routing depends entirely on the
provider — that is exactly why the provider list is configurable. The two
stock providers below are starting points, not guarantees: modern Google
GFE rejects cross-host routing in most cases, while custom SNI entries
(owned domains, zapret-style frontends) are the reliable path. The
transport rotates through providers automatically after each failure.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Sequence

from .base import BypassConnectError, BypassTransport, ConnectRequest, ConnectResult

log = logging.getLogger("bypass.cdn")

WS_PATH = "/apiws"


@dataclass
class FrontingProvider:
    """One fronting endpoint.

    ``sni`` is the hostname placed into the TLS ClientHello. ``connect_ip``
    is an optional edge IP to connect to instead of DNS. ``host_header``
    is an optional Host header override; when None the caller should use
    the real target domain for the Host header (standard domain fronting) —
    this is what Phase 2 wires into the WS upgrade handshake.
    """

    name: str
    sni: str
    connect_ip: Optional[str] = None
    host_header: Optional[str] = None
    tls: bool = True
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, mapping: Dict[str, Any]) -> "FrontingProvider":
        data = dict(mapping)
        name = str(data.pop("name", "")).strip()
        sni = str(data.pop("sni", "")).strip()
        if not name or not sni:
            raise ValueError("fronting provider needs at least 'name' and 'sni'")
        connect_ip = data.pop("connect_ip", None)
        host_header = data.pop("host_header", None)
        tls = bool(data.pop("tls", True))
        notes = str(data.pop("notes", ""))
        if data:
            raise ValueError(
                "unknown fronting provider keys: {}".format(sorted(data))
            )
        return cls(
            name=name,
            sni=sni,
            connect_ip=connect_ip,
            host_header=host_header,
            tls=tls,
            notes=notes,
        )


#: Stock fronting endpoints. Extend via BypassConfig.cdn_providers.
BUILTIN_PROVIDERS = {
    "fastly": FrontingProvider(
        name="fastly",
        sni="www.fastly.com",
        notes="Fastly edge; Host-based routing is backend-dependent",
    ),
    "google-gfe": FrontingProvider(
        name="google-gfe",
        sni="www.gstatic.com",
        notes="Google frontend; modern GFE often rejects cross-host routing",
    ),
}

#: Default rotation order when the user supplies no custom providers.
DEFAULT_PROVIDER_NAMES = ("fastly", "google-gfe")


def default_providers() -> List[FrontingProvider]:
    return [BUILTIN_PROVIDERS[n] for n in DEFAULT_PROVIDER_NAMES if n in BUILTIN_PROVIDERS]


class CdnFrontingTransport(BypassTransport):
    """TLS connections via alternative CDN fronting endpoints.

    The stream returned by :meth:`connect` is an established TLS session
    with the *fronting* SNI; the caller performs the application-level
    handshake (WebSocket upgrade, HTTP/2, ...) on top of it.

    Note on TLS verification: fronting means the certificate will not match
    the fronting SNI, so with ``insecure_tls=True`` (default, the same
    approach as the proxy's own fronting code) certificate validation is
    disabled. The carried payload is end-to-end encrypted by Telegram
    (MTProto), so this does not expose message contents.
    """

    name = "cdn-fronting"
    priority = 10

    def __init__(
        self,
        providers: Optional[Sequence[FrontingProvider]] = None,
        *,
        insecure_tls: bool = True,
    ) -> None:
        super().__init__()
        self.providers: List[FrontingProvider] = (
            default_providers() if providers is None else list(providers)
        )
        self.insecure_tls = insecure_tls
        self._index = 0

    @property
    def current_provider(self) -> Optional[FrontingProvider]:
        if not self.providers:
            return None
        return self.providers[self._index % len(self.providers)]

    def rotate(self) -> None:
        self._index += 1

    def is_configured(self) -> bool:
        return bool(self.providers)

    async def connect(self, request: ConnectRequest) -> ConnectResult:
        provider = self.current_provider
        if provider is None:
            raise BypassConnectError("no fronting providers configured")
        target = provider.connect_ip or provider.sni
        try:
            reader, writer = await asyncio.wait_for(
                self._open_tls(target, request.port, provider.sni),
                timeout=request.timeout,
            )
        except (asyncio.TimeoutError, OSError, ssl.SSLError) as exc:
            self.rotate()
            raise BypassConnectError(
                "fronting via {} failed: {!r}".format(provider.name, exc)
            ) from exc
        return ConnectResult(
            reader=reader,
            writer=writer,
            transport=self.name,
            sni=provider.sni,
            host_header=provider.host_header,
        )

    async def _open_tls(self, ip: str, port: int, sni: str):
        ctx = ssl.create_default_context()
        if self.insecure_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return await asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni)

    def websocket_connect_kwargs(
        self,
        target_ip: str,
        path: str = WS_PATH,
        timeout: float = 10.0,
        target_domain: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Kwargs for ``proxy.raw_websocket.RawWebSocket.connect`` (Phase 2).

        The returned dict mirrors the existing call signature so the proxy
        fallback code can switch transports with a one-line change::

            kwargs = cdn_transport.websocket_connect_kwargs(dc_ip, path=path)
            ws = await RawWebSocket.connect(**kwargs)
        """
        provider = self.current_provider
        if provider is None:
            raise BypassConnectError("no fronting providers configured")
        return {
            "target_ip": provider.connect_ip or provider.sni,
            "domain": provider.host_header or target_domain or provider.sni,
            "path": path,
            "sni": provider.sni,
            "timeout": timeout,
            "secure": provider.tls,
        }
