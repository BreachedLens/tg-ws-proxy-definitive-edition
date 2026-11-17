"""bypass — alternative transports for reaching Telegram.

Two modes plus automatic fallback:

* ``cdn``          (``bypass.cdn``)          — alternative CDN / domain fronting
* ``amneziawg``    (``bypass.amneziawg``)   — embedded userspace tunnel with Quad9 DNS

The package is decoupled by design: it imports nothing from ``proxy``,
``ui`` or ``utils``, so the folder can be copied verbatim into another
host project (e.g. a fork of Flowseal/zapret-discord-youtube). Phase 2
wires ``proxy/`` and ``ui/`` to :func:`build_default_manager` and
:meth:`BypassManager.connect`.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .amneziawg import (
    QUAD9_DOH,
    QUAD9_DOT,
    QUAD9_IPV4,
    QUAD9_IPV6,
    AmneziaConfig,
    AmneziaWGTransport,
    apply_system_dns,
    revert_system_dns,
)
from .base import (
    BypassConnectError,
    BypassError,
    BypassManager,
    BypassTransport,
    BypassUnavailable,
    ConnectRequest,
    ConnectResult,
)
from .cdn import (
    BUILTIN_PROVIDERS,
    DEFAULT_PROVIDER_NAMES,
    CdnFrontingTransport,
    FrontingProvider,
)

__version__ = "0.1.0"

__all__ = [
    "BypassConfig",
    "BypassConnectError",
    "BypassError",
    "BypassManager",
    "BypassTransport",
    "BypassUnavailable",
    "AmneziaConfig",
    "AmneziaWGTransport",
    "CdnFrontingTransport",
    "ConnectRequest",
    "ConnectResult",
    "FrontingProvider",
    "BUILTIN_PROVIDERS",
    "DEFAULT_PROVIDER_NAMES",
    "QUAD9_IPV4",
    "QUAD9_IPV6",
    "QUAD9_DOH",
    "QUAD9_DOT",
    "apply_system_dns",
    "revert_system_dns",
    "build_default_manager",
]


@dataclass
class BypassConfig:
    """Flat, JSON-friendly settings block for the whole package.

    Designed to be merged into the tray config (``utils.tray_config``) in
    Phase 2 — the keys are stable strings so ``validate_config_form`` can
    pick them up the same way it handles the CF-proxy keys today.
    """

    cdn_enabled: bool = True
    cdn_providers: List[Dict[str, Any]] = field(default_factory=list)
    mode: Optional[str] = None
    amneziawg_enabled: bool = False
    amneziawg_config_path: str = ""
    amneziawg_binary_path: str = ""
    amneziawg_manage_dns: bool = True
    amneziawg_network_interface: str = ""
    dns: List[str] = field(default_factory=lambda: list(QUAD9_IPV4))

    @classmethod
    def from_mapping(cls, mapping: Optional[Dict[str, Any]]) -> "BypassConfig":
        if not mapping:
            return cls()
        kwargs = asdict(cls())
        for key, value in mapping.items():
            if key in kwargs:
                kwargs[key] = value
        return cls(**kwargs)


def build_default_manager(config: Optional[BypassConfig] = None) -> BypassManager:
    """Assemble the fallback chain: cdn fronting first, AmneziaWG second.

    Priority: ``cdn-fronting`` (10) < ``amneziawg`` (20) < stock routes of
    the host app (100+). Add custom providers or reorder via ``priority``.
    """
    cfg = config if config is not None else BypassConfig()
    manager = BypassManager()
    mode = cfg.mode
    cdn_enabled = cfg.cdn_enabled if mode is None else mode in ("alt_cdn", "auto")
    awg_enabled = cfg.amneziawg_enabled if mode is None else mode in ("amneziawg", "auto")
    if mode not in (None, "legacy", "alt_cdn", "amneziawg", "auto"):
        raise BypassError("unknown bypass mode: {}".format(mode))
    if cdn_enabled:
        custom: List[FrontingProvider] = []
        for raw in cfg.cdn_providers:
            try:
                custom.append(FrontingProvider.from_dict(raw))
            except (TypeError, ValueError) as exc:
                raise BypassError(
                    "invalid cdn provider entry: {}".format(exc)
                ) from exc
        manager.register(CdnFrontingTransport(custom or None))
    if awg_enabled:
        manager.register(
            AmneziaWGTransport(
                cfg.amneziawg_config_path,
                binary_path=cfg.amneziawg_binary_path or None,
                dns=tuple(cfg.dns) if cfg.dns else QUAD9_IPV4,
                manage_dns=cfg.amneziawg_manage_dns,
                network_interface=cfg.amneziawg_network_interface or None,
            )
        )
    if mode == "auto":
        awg = manager.get("amneziawg")
        cdn = manager.get("cdn-fronting")
        if awg is not None:
            awg.priority = 10
        if cdn is not None:
            cdn.priority = 20
    return manager
