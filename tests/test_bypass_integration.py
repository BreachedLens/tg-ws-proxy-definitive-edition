"""Integration-facing tests for bypass configuration and connection kwargs."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bypass import (
    BypassConfig, BypassManager, CdnFrontingTransport, ConnectResult,
    build_default_manager,
)
from bypass.cdn import BUILTIN_PROVIDERS, CDN_PROVIDER_IDS
from proxy import bridge
from proxy.raw_websocket import WsHandshakeError
from utils import tray_common


class BypassModeIntegrationTest(unittest.TestCase):
    def test_old_config_with_profile_keeps_explicit_amneziawg_mode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            with open(Path(temp_dir) / "profile.conf", "w", encoding="utf-8") as profile:
                profile.write("test profile")
            config_file.write_text(json.dumps({
                "bypass_mode": "amneziawg",
                "bypass_amneziawg_config_path": str(Path(temp_dir) / "profile.conf"),
            }), encoding="utf-8")
            with (
                mock.patch.object(tray_common, "CONFIG_FILE", config_file),
                mock.patch.object(tray_common, "ensure_dirs"),
                mock.patch.object(tray_common, "_apply_ui_language"),
            ):
                config = tray_common.load_config()

        self.assertEqual(config["bypass_mode"], "amneziawg")
        self.assertEqual(config["bypass_cdn_provider"], "google-gfe")
        self.assertFalse(config["bypass_amneziawg_enabled"])
        self.assertEqual(
            config["bypass_amneziawg_config_path"], str(Path(temp_dir) / "profile.conf")
        )
        self.assertEqual(config["bypass_dns"], [])
        self.assertTrue(config["bypass_amneziawg_split_tunnel"])

    def test_amneziawg_without_profile_migrates_to_google_cdn(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            config_file.write_text(json.dumps({"bypass_mode": "amneziawg"}), encoding="utf-8")
            with (
                mock.patch.object(tray_common, "CONFIG_FILE", config_file),
                mock.patch.object(tray_common, "ensure_dirs"),
                mock.patch.object(tray_common, "_apply_ui_language"),
            ):
                config = tray_common.load_config()
        self.assertEqual(config["bypass_mode"], "alt_cdn")
        self.assertEqual(config["bypass_cdn_provider"], "google-gfe")
        self.assertFalse(config["bypass_amneziawg_enabled"])
        self.assertEqual(config["bypass_amneziawg_config_path"], "")

    def test_legacy_config_missing_bypass_defaults_to_google_cdn(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            config_file.write_text(json.dumps({}), encoding="utf-8")
            with (
                mock.patch.object(tray_common, "CONFIG_FILE", config_file),
                mock.patch.object(tray_common, "ensure_dirs"),
                mock.patch.object(tray_common, "_apply_ui_language"),
            ):
                config = tray_common.load_config()
        self.assertEqual(config["bypass_mode"], "alt_cdn")
        self.assertEqual(config["bypass_cdn_provider"], "google-gfe")
        self.assertFalse(config["bypass_amneziawg_enabled"])
        self.assertEqual(config["bypass_amneziawg_config_path"], "")
        self.assertNotIn("check_updates", config)

    def test_legacy_config_aliases_are_migrated(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            with open(Path(temp_dir) / "profile.conf", "w", encoding="utf-8") as profile:
                profile.write("test profile")
            config_file.write_text(json.dumps({
                "bypass_mode": "auto",
                "bypass_amneziawg_conf_path": str(Path(temp_dir) / "profile.conf"),
                "bypass_dns_servers": ["1.1.1.1"],
            }), encoding="utf-8")
            with (
                mock.patch.object(tray_common, "CONFIG_FILE", config_file),
                mock.patch.object(tray_common, "ensure_dirs"),
                mock.patch.object(tray_common, "_apply_ui_language"),
            ):
                config = tray_common.load_config()

        self.assertEqual(config["bypass_mode"], "alt_cdn")
        self.assertEqual(
            config["bypass_amneziawg_config_path"],
            str(Path(temp_dir) / "profile.conf"),
        )
        self.assertEqual(config["bypass_dns"], ["1.1.1.1"])

    def test_default_bypass_manager_uses_google_cdn_alt_mode(self):
        self.assertEqual(
            CDN_PROVIDER_IDS,
            ("google-gfe", "cloudflare", "fastly", "akamai", "cloudfront",
             "bunny", "gcore", "vercel", "custom"),
        )
        self.assertIsNone(BypassConfig().mode)
        self.assertEqual(BypassConfig().cdn_provider, "google-gfe")
        manager = build_default_manager()
        self.assertEqual(
            manager.get("cdn-fronting").current_provider.name, "google-gfe"
        )

    def test_auto_mode_prioritizes_amneziawg_then_cdn(self):
        manager = build_default_manager(BypassConfig(
            mode="auto", cdn_provider="google-gfe",
        ))
        self.assertEqual(
            [(t.name, t.priority) for t in manager.transports],
            [("amneziawg", 10), ("cdn-fronting", 20)],
        )

    def test_alt_cdn_mode_does_not_create_tunnel(self):
        manager = build_default_manager(BypassConfig(
            mode="alt_cdn", cdn_provider="google-gfe",
        ))
        self.assertEqual([t.name for t in manager.transports], ["cdn-fronting"])

    def test_selected_cdn_provider_is_used(self):
        manager = build_default_manager(BypassConfig(
            mode="alt_cdn", cdn_provider="fastly",
        ))
        self.assertEqual(manager.get("cdn-fronting").current_provider.name, "fastly")
        custom = build_default_manager(BypassConfig(
            mode="alt_cdn", cdn_provider="custom", cdn_custom_sni="edge.example",
        ))
        self.assertEqual(custom.get("cdn-fronting").current_provider.sni, "edge.example")

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
        self.assertEqual(kwargs["target_ip"], "www.gstatic.com")


class BypassBridgeIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def test_cdn_404_falls_back_to_cf_proxy_then_ws_pool(self):
        cdn = CdnFrontingTransport([BUILTIN_PROVIDERS["fastly"]])
        manager = BypassManager()
        manager.register(cdn)
        pooled_ws = mock.Mock(send=mock.AsyncMock())
        reader, writer, ctx = mock.Mock(), mock.Mock(), SimpleNamespace()
        calls = []

        async def cloudflare_fallback(*_args, **_kwargs):
            calls.append("cloudflare")
            return False

        with mock.patch.object(bridge, "DC_DEFAULT_IPS", {2: "149.154.167.220"}), \
                mock.patch.object(bridge.proxy_config, "bypass_mode", "alt_cdn"), \
                mock.patch.object(bridge.proxy_config, "bypass_cdn_provider", "fastly"), \
                mock.patch.object(bridge.proxy_config, "fallback_cfproxy", False), \
                mock.patch.object(bridge.proxy_config, "cfproxy_worker_domains", []), \
                mock.patch.object(bridge, "_cfproxy_fallback", side_effect=cloudflare_fallback), \
                mock.patch.object(bridge.ws_pool, "get", new=mock.AsyncMock(
                    side_effect=lambda *_args, **_kwargs: calls.append("ws_pool") or pooled_ws
                )), \
                mock.patch.object(bridge.RawWebSocket, "connect", new=mock.AsyncMock(
                    side_effect=WsHandshakeError(404, "HTTP/1.1 404 Not Found")
                )) as connect_ws, \
                mock.patch.object(bridge, "bridge_ws_reencrypt", new=mock.AsyncMock()):
            result = await bridge.do_fallback(
                reader, writer, b"relay-init", "test", 2, False, False, "", ctx,
                manager=manager,
            )

        self.assertTrue(result)
        self.assertEqual(calls, ["cloudflare", "ws_pool"])
        self.assertEqual(connect_ws.await_count, 1)
        pooled_ws.send.assert_awaited_once_with(b"relay-init")

    async def test_cdn_failure_falls_through_ws_and_tcp_fallbacks(self):
        cdn = CdnFrontingTransport([BUILTIN_PROVIDERS["google-gfe"]])
        manager = BypassManager()
        manager.register(cdn)
        calls = []

        async def fail_cdn(target_ip, *_args, **_kwargs):
            calls.append("cdn" if target_ip == "www.gstatic.com" else "direct_ws")
            raise WsHandshakeError(404, "HTTP/1.1 404 Not Found")

        async def fail_cf(*_args, **_kwargs):
            calls.append("cf_proxy")
            return False

        async def no_ws_pool(*_args, **_kwargs):
            calls.append("ws_pool")
            return None

        async def fail_direct_ws(*_args, **_kwargs):
            calls.append("direct_ws")
            raise WsHandshakeError(404, "HTTP/1.1 404 Not Found")

        async def tcp_fallback(*_args, **_kwargs):
            calls.append("tcp")
            return True

        with mock.patch.object(bridge, "DC_DEFAULT_IPS", {2: "149.154.167.220"}), \
                mock.patch.object(bridge.proxy_config, "bypass_mode", "alt_cdn"), \
                mock.patch.object(bridge.proxy_config, "bypass_cdn_provider", "google-gfe"), \
                mock.patch.object(bridge.proxy_config, "fallback_cfproxy", False), \
                mock.patch.object(bridge.proxy_config, "cfproxy_worker_domains", []), \
                mock.patch.object(bridge, "ws_domains", return_value=["kws2.web.telegram.org"]), \
                mock.patch.object(bridge, "_cfproxy_fallback", side_effect=fail_cf), \
                mock.patch.object(bridge.ws_pool, "get", side_effect=no_ws_pool), \
                mock.patch.object(bridge.RawWebSocket, "connect", side_effect=fail_cdn) as connect_ws, \
                mock.patch.object(bridge, "_tcp_fallback", side_effect=tcp_fallback):
            result = await bridge.do_fallback(
                mock.Mock(), mock.Mock(), b"relay-init", "test", 2, False, False, "",
                SimpleNamespace(), manager=manager,
            )

        self.assertTrue(result)
        self.assertEqual(calls, ["cdn", "cf_proxy", "ws_pool", "direct_ws", "tcp"])
        self.assertEqual(connect_ws.await_count, 2)

    async def test_awg_failure_uses_cdn_websocket_handshake_not_manager_stream(self):
        awg = mock.Mock()
        awg.name = "amneziawg"
        awg.priority = 10
        awg.is_configured.return_value = True
        awg.is_healthy = True
        awg.connect = mock.AsyncMock(side_effect=OSError("tunnel unavailable"))
        cdn = CdnFrontingTransport([BUILTIN_PROVIDERS["google-gfe"]])
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
                mock.patch.object(bridge.proxy_config, "bypass_mode", "auto"), \
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
        self.assertEqual(args[0], "www.gstatic.com")
        self.assertEqual(args[1], "kws2.web.telegram.org")
        self.assertEqual(kwargs["sni"], "www.gstatic.com")
        self.assertEqual(kwargs["path"], "/apiws")
        ws.send.assert_awaited_once_with(b"relay-init")
        relay_ws.assert_awaited_once()
        awg.mark_failure.assert_called_once()


if __name__ == "__main__":
    unittest.main()
