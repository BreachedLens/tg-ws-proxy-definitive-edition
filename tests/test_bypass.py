"""Unit tests for the portable bypass package."""
import asyncio
import unittest
from unittest import mock

from bypass import (
    BUILTIN_PROVIDERS,
    BypassConnectError,
    BypassConfig,
    BypassManager,
    BypassTransport,
    ConnectRequest,
    ConnectResult,
    CdnFrontingTransport,
    FrontingProvider,
    build_default_manager,
)


class FakeTransport(BypassTransport):
    def __init__(self, name, *, exc=None, priority=50, configured=True):
        super().__init__()
        self.name = name
        self.priority = priority
        self._exc = exc
        self._configured = configured
        self.calls = 0

    def is_configured(self):
        return self._configured

    async def connect(self, request):
        self.calls += 1
        if self._exc is not None:
            raise self._exc
        return ConnectResult(reader=mock.Mock(), writer=mock.Mock(), transport=self.name)


class FrontingProviderTest(unittest.TestCase):
    def test_from_dict_roundtrip(self):
        provider = FrontingProvider.from_dict({
            "name": "myedge", "sni": "cdn.example.com", "connect_ip": "1.2.3.4",
        })
        self.assertEqual(provider.name, "myedge")
        self.assertEqual(provider.sni, "cdn.example.com")
        self.assertEqual(provider.to_dict()["connect_ip"], "1.2.3.4")

    def test_from_dict_requires_name_and_sni(self):
        with self.assertRaises(ValueError):
            FrontingProvider.from_dict({"sni": "x"})
        with self.assertRaises(ValueError):
            FrontingProvider.from_dict({"name": "x"})

    def test_from_dict_rejects_unknown_keys(self):
        with self.assertRaises(ValueError):
            FrontingProvider.from_dict({"name": "x", "sni": "y", "bogus": 1})

    def test_builtin_providers_present(self):
        self.assertTrue({
            "fastly", "google-gfe", "akamai", "cloudfront", "bunny", "gcore", "vercel",
        }.issubset(BUILTIN_PROVIDERS))


class CdnTransportTest(unittest.TestCase):
    def test_default_rotation_includes_all_builtin_fronting_providers(self):
        transport = CdnFrontingTransport()
        self.assertEqual(transport.current_provider.name, "google-gfe")
        self.assertEqual(
            [provider.name for provider in transport.providers],
            ["google-gfe", "fastly", "akamai", "cloudfront", "bunny", "gcore", "vercel"],
        )
        transport.rotate()
        self.assertEqual(transport.current_provider.name, "fastly")

    def test_selected_builtin_and_custom_cdn_provider(self):
        for provider_name in (
            "google-gfe", "fastly", "akamai", "cloudfront", "bunny", "gcore", "vercel",
        ):
            with self.subTest(provider=provider_name):
                manager = build_default_manager(BypassConfig(
                    mode="alt_cdn", cdn_provider=provider_name,
                ))
                self.assertEqual(manager.get("cdn-fronting").current_provider.name, provider_name)
        custom_manager = build_default_manager(BypassConfig(
            mode="alt_cdn", cdn_provider="custom", cdn_custom_sni="edge.example.com",
            cdn_custom_host="app.example.com",
        ))
        provider = custom_manager.get("cdn-fronting").current_provider
        self.assertEqual(provider.sni, "edge.example.com")
        self.assertEqual(provider.host_header, "app.example.com")

    def test_cloudflare_uses_native_fallback_instead_of_fronting_transport(self):
        manager = build_default_manager(BypassConfig(mode="alt_cdn", cdn_provider="cloudflare"))
        self.assertIsNone(manager.get("cdn-fronting"))

    def test_custom_provider_accepts_connect_ip(self):
        manager = build_default_manager(BypassConfig(
            mode="alt_cdn", cdn_provider="custom", cdn_custom_sni="edge.example.com",
            cdn_custom_connect_ip="192.0.2.44",
        ))
        self.assertEqual(manager.get("cdn-fronting").current_provider.connect_ip, "192.0.2.44")

    def test_not_configured_without_providers(self):
        self.assertFalse(CdnFrontingTransport(providers=[]).is_configured())

    def test_selected_provider_exposes_fronting_parameters(self):
        provider = CdnFrontingTransport().current_provider
        self.assertEqual(provider.name, "google-gfe")
        self.assertEqual(provider.sni, "www.gstatic.com")


class CdnConnectTest(unittest.IsolatedAsyncioTestCase):
    async def test_connect_rotates_provider_on_failure(self):
        transport = CdnFrontingTransport()
        first = transport.current_provider
        transport._open_tls = mock.AsyncMock(side_effect=[OSError("down"), (mock.Mock(), mock.Mock())])
        with self.assertRaises(BypassConnectError):
            await transport.connect(ConnectRequest(host="1.2.3.4", port=443))
        self.assertNotEqual(transport.current_provider, first)
        result = await transport.connect(ConnectRequest(host="1.2.3.4", port=443))
        self.assertEqual(result.sni, transport.current_provider.sni)
        self.assertEqual(transport._open_tls.await_count, 2)


class ManagerFallbackTest(unittest.IsolatedAsyncioTestCase):
    async def test_falls_back_to_next_transport(self):
        manager = BypassManager()
        failing = FakeTransport("first", exc=BypassConnectError("dead"), priority=10)
        working = FakeTransport("second", priority=20)
        manager.register(failing)
        manager.register(working)
        result = await manager.connect("149.154.167.220", 443)
        self.assertEqual(result.transport, "second")
        self.assertEqual(failing.calls, 1)
        self.assertEqual(working.calls, 1)

    async def test_all_failures_raise(self):
        manager = BypassManager()
        manager.register(FakeTransport("a", exc=BypassConnectError("dead"), priority=10))
        manager.register(FakeTransport("b", exc=asyncio.TimeoutError(), priority=20))
        with self.assertRaises(BypassConnectError) as ctx:
            await manager.connect("1.1.1.1", 443)
        self.assertIn("all bypass transports failed", str(ctx.exception))

    async def test_unconfigured_and_unavailable_are_skipped(self):
        manager = BypassManager()
        skip_cfg = FakeTransport("no-config", priority=10, configured=False)
        skip_avail = FakeTransport("no-availability", priority=20)
        skip_avail.is_available = mock.AsyncMock(return_value=False)
        working = FakeTransport("ok", priority=30)
        for transport in (skip_cfg, skip_avail, working):
            manager.register(transport)
        result = await manager.connect("1.1.1.1", 443)
        self.assertEqual(result.transport, "ok")
        self.assertEqual(skip_cfg.calls, 0)
        self.assertEqual(skip_avail.calls, 0)

    async def test_backoff_skips_broken_transport(self):
        manager = BypassManager()
        broken = FakeTransport("flaky", exc=BypassConnectError("dead"), priority=10)
        broken.backoff_initial = 60.0
        manager.register(broken)
        with self.assertRaises(BypassConnectError):
            await manager.connect("1.1.1.1", 443)
        self.assertEqual(broken.calls, 1)
        self.assertFalse(broken.is_healthy)
        with self.assertRaises(BypassConnectError):
            await manager.connect("1.1.1.1", 443)
        self.assertEqual(broken.calls, 1)

    async def test_check_all_reports_diagnostics(self):
        manager = BypassManager()
        manager.register(FakeTransport("a", priority=10, configured=False))
        report = await manager.check_all()
        self.assertFalse(report["a"]["configured"])
        self.assertTrue(report["a"]["healthy"])


class BuildManagerTest(unittest.TestCase):
    def test_default_manager_uses_google_fronting_provider(self):
        cfg = BypassConfig()
        self.assertEqual(cfg.cdn_provider, "google-gfe")
        manager = build_default_manager(cfg)
        self.assertEqual(manager.get("cdn-fronting").current_provider.name, "google-gfe")

    def test_legacy_mode_registers_no_alt_cdn_transport(self):
        manager = build_default_manager(BypassConfig(mode="legacy"))
        self.assertEqual(manager.transports, [])

    def test_config_from_mapping_ignores_unknown_keys(self):
        cfg = BypassConfig.from_mapping({"cdn_enabled": False, "unknown": 1})
        self.assertFalse(cfg.cdn_enabled)
        self.assertNotIn("unknown", cfg.__dict__)


if __name__ == "__main__":
    unittest.main()
