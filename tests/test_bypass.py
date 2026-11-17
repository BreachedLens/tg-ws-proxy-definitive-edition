"""Unit tests for the bypass package (stdlib only, like the rest of the repo).

Run from the repository root::

    python -m unittest discover -s tests -t .
"""
import asyncio
import os
import tempfile
import unittest
from unittest import mock

from bypass import (
    BUILTIN_PROVIDERS,
    AmneziaConfig,
    AmneziaWGTransport,
    BypassConnectError,
    BypassConfig,
    BypassManager,
    BypassTransport,
    BypassUnavailable,
    ConnectRequest,
    ConnectResult,
    CdnFrontingTransport,
    FrontingProvider,
    QUAD9_IPV4,
    build_default_manager,
)
from bypass import amneziawg as amneziawg_mod

VALID_PROFILE = """
[Interface]
PrivateKey = yAnz5TFELXXJZK1y0+vAT0TP9b9W3DtHBBZX4PLobF0=
Address = 10.8.1.2/32
DNS = 1.1.1.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 86
S2 = 142
H1 = 1234567891
H2 = 1234567892
H3 = 1234567893
H4 = 1234567894
MTU = 1280

[Peer]
PublicKey = 5N31vULj6TdbKUX+u9XCV/3F4iBLPsAiF/4tSBMKIkg=
Endpoint = 203.0.113.7:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""


def _write_profile(text, directory=None):
    fd, path = tempfile.mkstemp(suffix=".conf", dir=directory)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class FakeTransport(BypassTransport):
    def __init__(self, name, *, result=None, exc=None, priority=50, configured=True):
        super().__init__()
        self.name = name
        self.priority = priority
        self._result = result
        self._exc = exc
        self._configured = configured
        self.calls = 0

    def is_configured(self):
        return self._configured

    async def connect(self, request):
        self.calls += 1
        if self._exc is not None:
            raise self._exc
        return ConnectResult(
            reader=mock.Mock(), writer=mock.Mock(), transport=self.name
        )


class AmneziaConfigTest(unittest.TestCase):
    def test_parse_full_awg_profile(self):
        cfg = AmneziaConfig.parse(VALID_PROFILE)
        self.assertEqual(cfg.interface.dns, ["1.1.1.1"])
        self.assertEqual(cfg.interface.mtu, 1280)
        obf = cfg.interface.obfuscation
        for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
            self.assertIn(key, obf)
        self.assertEqual(obf["Jc"], 4)
        self.assertEqual(obf["S1"], 86)
        self.assertEqual(obf["H1"], 1234567891)
        self.assertEqual(cfg.peer.endpoint, "203.0.113.7:51820")
        self.assertEqual(cfg.peer.keepalive, 25)
        self.assertFalse(cfg.validate())

    def test_validate_missing_obfuscation_fields(self):
        broken = VALID_PROFILE.replace(
            "H1 = 1234567891\n", ""
        ).replace("H4 = 1234567894\n", "")
        cfg = AmneziaConfig.parse(broken)
        errors = cfg.validate()
        self.assertTrue(any("obfuscation incomplete" in e for e in errors))

    def test_validate_bad_private_key(self):
        broken = VALID_PROFILE.replace(
            "PrivateKey = yAnz5TFELXXJZK1y0+vAT0TP9b9W3DtHBBZX4PLobF0=",
            "PrivateKey = not-a-key",
        )
        cfg = AmneziaConfig.parse(broken)
        errors = cfg.validate()
        self.assertTrue(any("PrivateKey" in e for e in errors))

    def test_validate_h_values_must_be_distinct(self):
        broken = VALID_PROFILE.replace("H3 = 1234567893", "H3 = 1234567892")
        cfg = AmneziaConfig.parse(broken)
        errors = cfg.validate()
        self.assertTrue(any("distinct" in e for e in errors))

    def test_validate_accepts_ipv6_addresses_and_zero_obfuscation_values(self):
        profile = VALID_PROFILE.replace(
            "Address = 10.8.1.2/32", "Address = 10.8.1.2/32, fd00::2/128"
        ).replace("Jc = 4", "Jc = 0").replace("Jmin = 40", "Jmin = 0")
        cfg = AmneziaConfig.parse(profile)
        self.assertEqual(cfg.interface.addresses, ["10.8.1.2/32", "fd00::2/128"])
        self.assertEqual(cfg.peer.allowed_ips, ["0.0.0.0/0", "::/0"])
        self.assertFalse(cfg.validate())

    def test_validate_rejects_invalid_address_and_allowed_ip(self):
        profile = VALID_PROFILE.replace("Address = 10.8.1.2/32", "Address = bad/32")
        profile = profile.replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = not-an-ip")
        errors = AmneziaConfig.parse(profile).validate()
        self.assertTrue(any("Interface/Address" in e for e in errors))
        self.assertTrue(any("Peer/AllowedIPs" in e for e in errors))

    def test_validate_rejects_malformed_numeric_obfuscation_value(self):
        profile = VALID_PROFILE.replace("Jc = 4", "Jc = invalid")
        errors = AmneziaConfig.parse(profile).validate()
        self.assertTrue(any("Interface/Jc" in e for e in errors))

    def test_validate_rejects_out_of_range_mtu(self):
        profile = VALID_PROFILE.replace("MTU = 1280", "MTU = 10")
        errors = AmneziaConfig.parse(profile).validate()
        self.assertTrue(any("Interface/MTU" in e for e in errors))

    def test_render_replaces_dns_with_quad9(self):
        cfg = AmneziaConfig.parse(VALID_PROFILE)
        rendered = cfg.render(dns=QUAD9_IPV4)
        self.assertIn("DNS = 9.9.9.9, 149.112.112.112", rendered)
        self.assertIn("Endpoint = 203.0.113.7:51820", rendered)
        self.assertIn("Jc = 4", rendered)
        # round-trip stability: re-parsing the render yields the same object
        reparsed = AmneziaConfig.parse(rendered)
        self.assertEqual(reparsed.interface.dns, list(QUAD9_IPV4))


class FrontingProviderTest(unittest.TestCase):
    def test_from_dict_roundtrip(self):
        raw = {"name": "myedge", "sni": "cdn.example.com", "connect_ip": "1.2.3.4"}
        provider = FrontingProvider.from_dict(raw)
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
        self.assertIn("fastly", BUILTIN_PROVIDERS)
        self.assertIn("google-gfe", BUILTIN_PROVIDERS)


class CdnTransportTest(unittest.TestCase):
    def test_default_rotation_order(self):
        transport = CdnFrontingTransport()
        self.assertEqual(transport.current_provider.name, "fastly")
        transport.rotate()
        self.assertEqual(transport.current_provider.name, "google-gfe")

    def test_not_configured_without_providers(self):
        transport = CdnFrontingTransport(providers=[])
        self.assertFalse(transport.is_configured())

    def test_websocket_connect_kwargs_shape(self):
        transport = CdnFrontingTransport()
        kwargs = transport.websocket_connect_kwargs("149.154.167.220", path="/api")
        self.assertEqual(kwargs["path"], "/api")
        self.assertEqual(kwargs["target_ip"], "www.fastly.com")
        self.assertIn("domain", kwargs)
        self.assertIn("sni", kwargs)


class CdnConnectTest(unittest.IsolatedAsyncioTestCase):
    async def test_connect_rotates_provider_on_failure(self):
        transport = CdnFrontingTransport()
        first = transport.current_provider
        stream = (mock.Mock(), mock.Mock())
        transport._open_tls = mock.AsyncMock(
            side_effect=[OSError("down"), stream]
        )
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
        skip_cfg = FakeTransport("no-conf", priority=10, configured=False)
        skip_avail = FakeTransport("no-avail", priority=20)
        skip_avail.is_available = mock.AsyncMock(return_value=False)
        working = FakeTransport("ok", priority=30)
        for t in (skip_cfg, skip_avail, working):
            manager.register(t)
        result = await manager.connect("1.1.1.1", 443)
        self.assertEqual(result.transport, "ok")
        self.assertEqual(skip_cfg.calls, 0)
        self.assertEqual(skip_avail.calls, 0)

    async def test_backoff_skips_broken_transport(self):
        manager = BypassManager()
        broken = FakeTransport(
            "flaky", exc=BypassConnectError("dead"), priority=10,
        )
        broken.backoff_initial = 60.0
        manager.register(broken)
        with self.assertRaises(BypassConnectError):
            await manager.connect("1.1.1.1", 443)
        self.assertEqual(broken.calls, 1)
        self.assertFalse(broken.is_healthy)
        # second attempt must not even try the cooling-down transport
        with self.assertRaises(BypassConnectError):
            await manager.connect("1.1.1.1", 443)
        self.assertEqual(broken.calls, 1)

    async def test_check_all_reports_diagnostics(self):
        manager = BypassManager()
        manager.register(FakeTransport("a", priority=10, configured=False))
        report = await manager.check_all()
        self.assertFalse(report["a"]["configured"])
        self.assertTrue(report["a"]["healthy"])


class AmneziaWGTransportTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def _transport(self, conf_text=VALID_PROFILE, **kwargs):
        path = _write_profile(conf_text, directory=self.tmpdir.name)
        return AmneziaWGTransport(path, **kwargs)

    def test_not_configured_without_binary(self):
        transport = self._transport()
        with mock.patch.object(amneziawg_mod, "find_tunnel_binary", return_value=None):
            self.assertIsNone(transport.find_binary())
            self.assertFalse(transport.is_configured())

    def test_configured_when_binary_found(self):
        transport = self._transport()
        with mock.patch.object(
            amneziawg_mod, "find_tunnel_binary",
            return_value=("/usr/bin/amneziawg-go", "go"),
        ):
            found = transport.find_binary()
            self.assertEqual(found, ("/usr/bin/amneziawg-go", "go"))
            self.assertTrue(transport.is_configured())

    def test_not_configured_without_profile(self):
        transport = AmneziaWGTransport(os.path.join(self.tmpdir.name, "missing.conf"))
        with mock.patch.object(amneziawg_mod, "_which", return_value="/usr/bin/amneziawg-go"):
            self.assertFalse(transport.is_configured())

    def test_load_config_rejects_invalid_profile(self):
        broken = VALID_PROFILE.replace("Endpoint = 203.0.113.7:51820", "Endpoint = 203.0.113.7")
        transport = self._transport(conf_text=broken)
        with self.assertRaises(BypassUnavailable):
            transport.load_config()

    def test_build_command_go_quick_and_windows_service_styles(self):
        transport = self._transport()
        self.assertEqual(
            transport._build_command("/usr/bin/amneziawg-go", "go", "/tmp/x.conf"),
            ["/usr/bin/amneziawg-go", "-f", transport._iface_name(), "/tmp/x.conf"],
        )
        self.assertEqual(
            transport._build_command("/usr/bin/awg-quick", "quick", "/tmp/x.conf"),
            ["/usr/bin/awg-quick", "up", "/tmp/x.conf"],
        )
        self.assertEqual(
            transport._build_command("C:\\awg\\amneziawg.exe", "windows-service", "C:\\tmp\\awg-tgproxy.conf"),
            ["C:\\awg\\amneziawg.exe", "/installtunnelservice", "C:\\tmp\\awg-tgproxy.conf"],
        )

    def test_find_binary_prioritizes_bundled_windows_service_binary(self):
        with mock.patch.object(amneziawg_mod.sys, "platform", "win32"), mock.patch.object(
            amneziawg_mod.os.path, "isfile", return_value=True
        ), mock.patch.object(amneziawg_mod, "_which") as which:
            result = amneziawg_mod.find_tunnel_binary()
        self.assertEqual(result, (amneziawg_mod._bundled_windows_awg(), "windows-service"))
        which.assert_not_called()

    def test_find_binary_falls_back_to_installed_windows_binary_then_path(self):
        installed = os.path.join(amneziawg_mod._WIN_DIRS[0], "amneziawg.exe")
        with mock.patch.object(amneziawg_mod.sys, "platform", "win32"), mock.patch.object(
            amneziawg_mod.os.path, "isfile", side_effect=lambda p: p == installed
        ), mock.patch.object(amneziawg_mod, "_which") as which:
            result = amneziawg_mod.find_tunnel_binary()
        self.assertEqual(result, (installed, "windows-service"))
        which.assert_not_called()

        with mock.patch.object(amneziawg_mod.sys, "platform", "win32"), mock.patch.object(
            amneziawg_mod.os.path, "isfile", return_value=False
        ), mock.patch.object(
            amneziawg_mod, "_which",
            side_effect=lambda n: "C:\\tools\\amneziawg.exe" if n == "amneziawg.exe" else None,
        ):
            self.assertEqual(
                amneziawg_mod.find_tunnel_binary(),
                ("C:\\tools\\amneziawg.exe", "windows-service"),
            )

    def test_windows_service_installs_and_uninstalls_managed_temp_profile(self):
        binary = os.path.join(self.tmpdir.name, "amneziawg.exe")
        with open(binary, "wb") as fh:
            fh.write(b"test binary placeholder")
        transport = self._transport(binary_path=binary, manage_dns=False)

        async def exercise():
            with mock.patch.object(amneziawg_mod.sys, "platform", "win32"), mock.patch.object(
                amneziawg_mod, "_run_quiet", return_value=True
            ) as run_quiet, mock.patch.object(
                transport, "_windows_service_running", return_value=True
            ):
                await transport.start()
                conf_file = transport._conf_file
                self.assertTrue(os.path.isfile(conf_file))
                with open(conf_file, "r", encoding="utf-8") as fh:
                    rendered = fh.read()
                self.assertIn("DNS = 9.9.9.9, 149.112.112.112", rendered)
                self.assertTrue(transport._service_installed)
                self.assertEqual(transport._service_name(), "awg-tgproxy")
                await transport.stop()

            self.assertEqual(run_quiet.call_args_list[0].args[0], [
                binary, "/installtunnelservice", conf_file,
            ])
            self.assertEqual(run_quiet.call_args_list[1].args[0], [
                binary, "/uninstalltunnelservice", "awg-tgproxy",
            ])
            self.assertFalse(os.path.exists(conf_file))
            self.assertFalse(transport._service_installed)

        asyncio.run(exercise())

    def test_binary_path_style_detection(self):
        transport = self._transport(binary_path="C:\\tools\\awg-quick.exe")
        found = transport.find_binary()
        if found is not None:  # on POSIX this path may not exist
            self.assertEqual(found[1], "quick")

    def test_rendered_conf_contains_quad9_dns(self):
        transport = self._transport()
        profile = transport.load_config()
        rendered = profile.render(dns=transport.dns)
        self.assertIn("DNS = 9.9.9.9, 149.112.112.112", rendered)


class BuildManagerTest(unittest.TestCase):
    def test_default_manager_registers_cdn_only(self):
        manager = build_default_manager(BypassConfig())
        self.assertEqual(
            [t.name for t in manager.transports], ["cdn-fronting"]
        )

    def test_amneziawg_registered_when_enabled(self):
        path = _write_profile(VALID_PROFILE)
        cfg = BypassConfig(amneziawg_enabled=True, amneziawg_config_path=path)
        with mock.patch.object(amneziawg_mod, "_which", return_value="/usr/bin/amneziawg-go"):
            manager = build_default_manager(cfg)
        self.assertEqual(
            [t.name for t in manager.transports], ["cdn-fronting", "amneziawg"]
        )
        transport = manager.get("amneziawg")
        self.assertEqual(transport.dns, QUAD9_IPV4)

    def test_config_from_mapping_ignores_unknown_keys(self):
        cfg = BypassConfig.from_mapping({"cdn_enabled": False, "unknown": 1})
        self.assertFalse(cfg.cdn_enabled)
        self.assertEqual(cfg.amneziawg_config_path, "")


if __name__ == "__main__":
    unittest.main()
