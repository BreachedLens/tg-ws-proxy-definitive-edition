"""Integration-facing tests for bypass configuration and connection kwargs."""
import unittest
from types import SimpleNamespace
from unittest import mock

from bypass import (
    BypassConfig, BypassManager, CdnFrontingTransport, ConnectResult,
    build_default_manager,
)
from proxy import bridge


class BypassModeIntegrationTest(unittest.TestCase):
    def test_auto_mode_prioritizes_amneziawg_then_cdn(self):
        manager = build_default_manager(BypassConfig(mode="auto"))
        self.assertEqual(
            [(t.name, t.priority) for t in manager.transports],
            [("amneziawg", 10), ("cdn-fronting", 20)],
        )

    def test_alt_cdn_mode_does_not_create_tunnel(self):
        manager = build_default_manager(BypassConfig(mode="alt_cdn"))
        self.assertEqual([t.name for t in manager.transports], ["cdn-fronting"])

    def test_legacy_mode_disables_new_transports(self):
        manager = build_default_manager(BypassConfig(mode="legacy"))
        self.assertEqual(manager.transports, [])

    def test_cdn_kwargs_preserve_target_host_and_fronting_sni(self):
        transport = CdnFrontingTransport()
        kwargs = transport.websocket_connect_kwargs(
            "149.154.167.220", target_domain="kws2.web.telegram.org"
        )
        self.assertEqual(kwargs["domain"], "kws2.web.telegram.org")
        self.assertEqual(kwargs["sni"], transport.current_provider.sni)
        self.assertEqual(kwargs["target_ip"], "www.fastly.com")


class BypassBridgeIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def test_awg_failure_uses_cdn_websocket_handshake_not_manager_stream(self):
        awg = mock.Mock()
        awg.name = "amneziawg"
        awg.priority = 10
        awg.is_configured.return_value = True
        awg.is_healthy = True
        awg.connect = mock.AsyncMock(side_effect=OSError("tunnel unavailable"))
        cdn = CdnFrontingTransport()
        manager = BypassManager()
        manager.register(awg)
        manager.register(cdn)
        manager.connect = mock.AsyncMock(
            side_effect=AssertionError("generic manager.connect must not be used")
        )
        ws = mock.Mock()
        ws.send = mock.AsyncMock()
        ws.close = mock.AsyncMock()
        reader, writer = mock.Mock(), mock.Mock()
        ctx = SimpleNamespace()

        with mock.patch.object(bridge, "DC_DEFAULT_IPS", {2: "149.154.167.220"}), \
                mock.patch.object(bridge.proxy_config, "fallback_cfproxy", False), \
                mock.patch.object(bridge.proxy_config, "cfproxy_worker_domains", []), \
                mock.patch.object(bridge.RawWebSocket, "connect", new=mock.AsyncMock(return_value=ws)) as connect_ws, \
                mock.patch.object(bridge, "bridge_ws_reencrypt", new=mock.AsyncMock()) as relay_ws:
            result = await bridge.do_fallback(
                reader, writer, b"relay-init", "test", 2, False, False, "", ctx,
                manager=manager,
            )

        self.assertTrue(result)
        manager.connect.assert_not_awaited()
        awg.connect.assert_awaited_once()
        connect_ws.assert_awaited_once()
        args, kwargs = connect_ws.await_args
        self.assertEqual(args[0], "www.fastly.com")
        self.assertEqual(args[1], "kws2.web.telegram.org")
        self.assertEqual(kwargs["sni"], "www.fastly.com")
        self.assertEqual(kwargs["path"], "/apiws")
        ws.send.assert_awaited_once_with(b"relay-init")
        relay_ws.assert_awaited_once()
        awg.mark_failure.assert_called_once()


if __name__ == "__main__":
    unittest.main()
