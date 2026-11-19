"""Integration-facing tests for bypass configuration and connection kwargs."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bypass import BypassConfig, BypassManager, CdnFrontingTransport, build_default_manager
from bypass.cdn import BUILTIN_PROVIDERS, CDN_PROVIDER_IDS
from proxy import bridge
from proxy.raw_websocket import WsHandshakeError
from utils import tray_common


class BypassModeIntegrationTest(unittest.TestCase):
    def _load(self, value):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            config_file.write_text(json.dumps(value), encoding="utf-8")
            with (
                mock.patch.object(tray_common, "CONFIG_FILE", config_file),
                mock.patch.object(tray_common, "ensure_dirs"),
                mock.patch.object(tray_common, "_apply_ui_language"),
            ):
                return tray_common.load_config()

    def test_removed_mode_and_obsolete_fields_migrate_cleanly(self):
        obsolete_keys = (
            "bypass_amneziawg_conf_path", "bypass_amneziawg_config_path",
            "bypass_amneziawg_enabled", "bypass_amneziawg_binary_path",
            "bypass_amneziawg_manage_dns", "bypass_amneziawg_network_interface",
            "bypass_amneziawg_split_tunnel", "bypass_dns", "bypass_dns_servers",
        )
        config = self._load({
            "bypass_mode": "amneziawg",
            **{key: "obsolete" for key in obsolete_keys},
        })
        self.assertEqual(config["bypass_mode"], "alt_cdn")
        self.assertEqual(config["bypass_cdn_provider"], "google-gfe")
        self.assertFalse(set(obsolete_keys) & set(config))

    def test_auto_and_unknown_modes_migrate_to_alt_cdn(self):
        for mode in ("auto", "unsupported"):
            with self.subTest(mode=mode):
                self.assertEqual(self._load({"bypass_mode": mode})["bypass_mode"], "alt_cdn")

    def test_legacy_mode_is_preserved(self):
        self.assertEqual(self._load({"bypass_mode": "legacy"})["bypass_mode"], "legacy")

    def test_missing_bypass_mode_defaults_to_google_cdn(self):
        config = self._load({})
        self.assertEqual(config["bypass_mode"], "alt_cdn")
        self.assertEqual(config["bypass_cdn_provider"], "google-gfe")
        self.assertNotIn("check_updates", config)

    def test_default_bypass_manager_uses_google_cdn_alt_mode(self):
        self.assertEqual(
            CDN_PROVIDER_IDS,
            ("google-gfe", "cloudflare", "fastly", "akamai", "cloudfront",
             "bunny", "gcore", "vercel", "custom"),
        )
        self.assertIsNone(BypassConfig().mode)
        self.assertEqual(BypassConfig().cdn_provider, "google-gfe")
        manager = build_default_manager()
        self.assertEqual(manager.get("cdn-fronting").current_provider.name, "google-gfe")

    def test_alt_cdn_mode_registers_only_fronting_transport(self):
        manager = build_default_manager(BypassConfig(mode="alt_cdn", cdn_provider="google-gfe"))
        self.assertEqual([transport.name for transport in manager.transports], ["cdn-fronting"])

    def test_selected_cdn_provider_is_used(self):
        manager = build_default_manager(BypassConfig(mode="alt_cdn", cdn_provider="fastly"))
        self.assertEqual(manager.get("cdn-fronting").current_provider.name, "fastly")
        custom = build_default_manager(BypassConfig(
            mode="alt_cdn", cdn_provider="custom", cdn_custom_sni="edge.example",
        ))
        self.assertEqual(custom.get("cdn-fronting").current_provider.sni, "edge.example")

    def test_legacy_mode_disables_new_transports(self):
        manager = build_default_manager(BypassConfig(mode="legacy"))
        self.assertEqual(manager.transports, [])

    def test_cdn_transport_exposes_provider_without_host_application_coupling(self):
        provider = CdnFrontingTransport().current_provider
        self.assertEqual(provider.sni, "www.gstatic.com")
        self.assertIsNone(provider.host_header)


class BypassBridgeIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def test_cdn_404_falls_back_to_cf_proxy_then_ws_pool(self):
        cdn = CdnFrontingTransport([BUILTIN_PROVIDERS["fastly"]])
        manager = BypassManager()
        manager.register(cdn)
        pooled_ws = mock.Mock(send=mock.AsyncMock())
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
                mock.Mock(), mock.Mock(), b"relay-init", "test", 2, False, False, "",
                SimpleNamespace(), manager=manager,
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


if __name__ == "__main__":
    unittest.main()
