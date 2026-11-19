"""Portable userspace transports for alternative CDN/SNI routing.

The package imports nothing from ``proxy``, ``ui`` or ``utils``, keeping
it reusable by other host applications.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

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
    CDN_PROVIDER_IDS,
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
    "CdnFrontingTransport",
    "ConnectRequest",
    "ConnectResult",
    "FrontingProvider",
    "BUILTIN_PROVIDERS",
    "DEFAULT_PROVIDER_NAMES",
    "build_default_manager",
]


@dataclass
class BypassConfig:
    """Flat, JSON-friendly settings for the alternative CDN transport."""

    cdn_enabled: bool = True
    cdn_providers: List[Dict[str, Any]] = field(default_factory=list)
    mode: Optional[str] = None
    cdn_provider: str = "google-gfe"
    cdn_custom_sni: str = ""
    cdn_custom_host: str = ""
    cdn_custom_connect_ip: str = ""

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
    """Assemble the optional alternative CDN/SNI transport."""
    cfg = config if config is not None else BypassConfig()
    manager = BypassManager()
    mode = cfg.mode
    cdn_enabled = cfg.cdn_enabled if mode is None else mode == "alt_cdn"
    if mode not in (None, "legacy", "alt_cdn"):
        raise BypassError("unknown bypass mode: {}".format(mode))
    if cdn_enabled and cfg.cdn_provider != "cloudflare":
        custom: List[FrontingProvider] = []
        if cfg.cdn_provider in BUILTIN_PROVIDERS:
            custom.append(BUILTIN_PROVIDERS[cfg.cdn_provider])
        elif cfg.cdn_provider == "custom":
            if not cfg.cdn_custom_sni.strip():
                raise BypassError("custom CDN provider requires a TLS SNI")
            custom.append(FrontingProvider(
                name="custom",
                sni=cfg.cdn_custom_sni.strip(),
                host_header=cfg.cdn_custom_host.strip() or None,
                connect_ip=cfg.cdn_custom_connect_ip.strip() or None,
            ))
        elif cfg.cdn_provider not in ("", "rotate"):
            raise BypassError("unknown CDN provider: {}".format(cfg.cdn_provider))
        for raw in cfg.cdn_providers:
            try:
                custom.append(FrontingProvider.from_dict(raw))
            except (TypeError, ValueError) as exc:
                raise BypassError(
                    "invalid cdn provider entry: {}".format(exc)
                ) from exc
        manager.register(CdnFrontingTransport(custom or None))
    return manager
