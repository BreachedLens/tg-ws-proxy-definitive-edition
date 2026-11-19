import unittest
from types import SimpleNamespace
from unittest import mock

from bypass import BypassConnectError, BypassUnavailable
from ui.settings import prepare_settings
from ui.settings_form import TrayConfigFormWidgets, validate_config_form
from utils.default_config import default_tray_config
from utils import diagnostics, tray_common


class ListenErrorDiagnosticsTest(unittest.TestCase):
    def test_bypass_errors_return_safe_unrecognized_diagnosis(self):
        for error in (
            BypassUnavailable("profile invalid"),
            BypassConnectError("tunnel unavailable"),
        ):
            with self.subTest(error=type(error).__name__):
                self.assertEqual(diagnostics.diagnose_listen_error(error), (None, None))

    def test_proxy_thread_tolerates_none_diagnosis(self):
        async def fail_run(*args, **kwargs):
            raise BypassUnavailable("invalid profile")

        show_error = mock.Mock()
        with (
            mock.patch.object(tray_common, "_run", side_effect=fail_run),
            mock.patch.object(tray_common, "diagnose_listen_error", return_value=None),
        ):
            tray_common._run_proxy_thread(show_error)
        show_error.assert_not_called()


class BypassSettingsFormTest(unittest.TestCase):
    class Value:
        def __init__(self, value):
            self.value = value

        def get(self):
            return self.value

    class Text:
        def get(self, *_args):
            return "2:149.154.167.220\n4:149.154.167.220"

    def _widgets(self, mode="alt_cdn"):
        from ui.i18n import t

        return TrayConfigFormWidgets(
            host_var=self.Value("127.0.0.1"),
            port_var=self.Value("1443"),
            secret_var=self.Value("0123456789abcdef0123456789abcdef"),
            dc_textbox=self.Text(), verbose_var=self.Value(False),
            no_secure_var=self.Value(False),
            advanced_vars={
                "buf_kb": self.Value("256"),
                "pool_size": self.Value("4"),
                "log_max_mb": self.Value("5"),
            },
            autostart_var=None,
            cfproxy_var=self.Value(True), h2_var=self.Value(True),
            cfproxy_user_domain_enabled_var=self.Value(False),
            cfproxy_user_domain_var=self.Value(""),
            cfproxy_worker_enabled_var=self.Value(False),
            cfproxy_worker_domain_var=self.Value(""),
            bypass_mode_var=self.Value(t("bypass.mode_" + mode)),
            bypass_cdn_provider_var=self.Value(t("bypass.provider_google")),
            bypass_cdn_custom_sni_var=self.Value(""),
            bypass_cdn_custom_host_var=self.Value(""),
        )

    def test_bypass_fields_are_validated_and_saved(self):
        defaults = default_tray_config()
        current = dict(defaults)
        widgets = self._widgets()
        values = validate_config_form(widgets, defaults, include_autostart=False)
        self.assertIsInstance(values, dict)
        self.assertEqual(values["bypass_mode"], "alt_cdn")
        self.assertEqual(values["bypass_cdn_provider"], "google-gfe")
        self.assertEqual(values["bypass_cdn_custom_connect_ip"], "")

    def test_cdn_provider_and_custom_sni_are_persisted(self):
        from ui.i18n import t
        defaults = default_tray_config()
        widgets = self._widgets()
        widgets.bypass_mode_var.value = t("bypass.mode_alt_cdn")
        widgets.bypass_cdn_provider_var.value = t("bypass.provider_custom")
        widgets.bypass_cdn_custom_sni_var.value = "edge.example.com"
        widgets.bypass_cdn_custom_host_var.value = "telegram.example.com"
        values = validate_config_form(widgets, defaults, include_autostart=False)
        self.assertIsInstance(values, dict)
        self.assertEqual(values["bypass_cdn_provider"], "custom")
        self.assertEqual(values["bypass_cdn_custom_sni"], "edge.example.com")
        self.assertEqual(values["bypass_cdn_custom_host"], "telegram.example.com")
        changed = prepare_settings(defaults, values, defaults)
        self.assertIn("bypass_cdn_provider", changed.changed_keys)

    def test_all_builtin_cdn_providers_are_valid(self):
        from ui.i18n import t
        defaults = default_tray_config()
        widgets = self._widgets()
        for provider, expected in (
            ("bypass.provider_cloudflare", "cloudflare"),
            ("bypass.provider_akamai", "akamai"),
            ("bypass.provider_cloudfront", "cloudfront"),
            ("bypass.provider_bunny", "bunny"),
            ("bypass.provider_gcore", "gcore"),
            ("bypass.provider_vercel", "vercel"),
        ):
            widgets.bypass_cdn_provider_var.value = t(provider)
            values = validate_config_form(widgets, defaults, include_autostart=False)
            self.assertIsInstance(values, dict)
            self.assertEqual(values["bypass_cdn_provider"], expected)

    def test_custom_connect_ip_is_validated_and_saved(self):
        defaults = default_tray_config()
        widgets = self._widgets()
        widgets.bypass_cdn_custom_connect_ip_var = self.Value("192.0.2.15")
        values = validate_config_form(widgets, defaults, include_autostart=False)
        self.assertIsInstance(values, dict)
        self.assertEqual(values["bypass_cdn_custom_connect_ip"], "192.0.2.15")
        widgets.bypass_cdn_custom_connect_ip_var.value = "not-an-ip"
        self.assertIsInstance(
            validate_config_form(widgets, defaults, include_autostart=False), str
        )


class ProxyRestartTest(unittest.TestCase):
    def test_restart_waits_for_old_proxy_thread_before_starting(self):
        old_thread = mock.Mock()
        old_thread.is_alive.side_effect = [True, False]
        events = []

        def stop_proxy(*, timeout):
            events.append(("stop", timeout))
            tray_common._proxy_thread = None

        def start_proxy(cfg, on_error):
            events.append(("start", cfg, on_error))

        with (
            mock.patch.object(tray_common, "_restart_lock", tray_common.threading.Lock()),
            mock.patch.object(tray_common, "_proxy_thread", old_thread),
            mock.patch.object(tray_common, "stop_proxy", side_effect=stop_proxy) as stop,
            mock.patch.object(tray_common, "start_proxy", side_effect=start_proxy),
        ):
            error_handler = mock.Mock()
            tray_common._restart_proxy_worker({"port": 1234}, error_handler)

        stop.assert_called_once_with(timeout=None)
        self.assertEqual(events[0], ("stop", None))
        self.assertEqual(events[1], ("start", {"port": 1234}, error_handler))

    def test_restart_runs_stop_and_start_work_off_caller_thread(self):
        entered = tray_common.threading.Event()
        release = tray_common.threading.Event()

        def blocked_worker(_cfg, _on_error):
            entered.set()
            release.wait(timeout=2)

        with mock.patch.object(tray_common, "_restart_proxy_worker", side_effect=blocked_worker):
            thread = tray_common.restart_proxy({}, mock.Mock())
            self.assertIsInstance(thread, tray_common.threading.Thread)
            self.assertTrue(entered.wait(timeout=1))
            self.assertTrue(thread.is_alive())
            release.set()
            thread.join(timeout=1)
        self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main()
