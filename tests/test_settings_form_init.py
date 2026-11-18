import unittest
from unittest import mock

from ui.ctk_theme import CtkTheme
from ui.settings_dialog import SettingsDialog
from ui.settings_form import install_tray_config_form
from utils.default_config import default_tray_config


class _Var:
    def __init__(self, master=None, value=None):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value

    def trace_add(self, *_args):
        return "trace"


class _Widget:
    def __init__(self, *args, **kwargs):
        self.options = kwargs
        self.text = ""

    def pack(self, **_kwargs):
        return None

    def pack_forget(self):
        return None

    def configure(self, **kwargs):
        self.options.update(kwargs)

    config = configure

    def bind(self, *_args, **_kwargs):
        return None

    def insert(self, _index, value):
        self.text += value

    def get(self, *_args):
        return self.text

    def winfo_toplevel(self):
        return self

    def after(self, _delay, callback=None):
        if callback:
            callback()
        return "after"

    def protocol(self, *_args):
        return None


class _Ctk:
    CTkFrame = _Widget
    CTkLabel = _Widget
    CTkButton = _Widget
    CTkTextbox = _Widget
    CTkEntry = _Widget
    CTkCheckBox = _Widget
    CTkComboBox = _Widget
    StringVar = _Var
    BooleanVar = _Var
    set_appearance_mode = mock.Mock()


class SettingsFormInitializationTest(unittest.TestCase):
    def test_settings_dialog_initializes_with_corrupt_legacy_domains(self):
        defaults = default_tray_config()
        config = dict(defaults)
        config.update({
            "cfproxy_user_domain": "['broken..example', None]",
            "cfproxy_worker_domain": "['also..broken', '']",
            "cfproxy_user_domain_enabled": True,
            "cfproxy_worker_enabled": True,
        })
        root = _Widget()

        widgets = install_tray_config_form(
            _Ctk, root, CtkTheme(), config, defaults,
        )
        dialog = SettingsDialog(
            ctk=_Ctk, root=root, widgets=widgets, config=config,
            defaults=defaults, persist=mock.Mock(), refresh_menu=mock.Mock(),
            finish=mock.Mock(), restart=mock.Mock(),
        )

        self.assertEqual(widgets.cfproxy_user_domain_var.get(), "")
        self.assertEqual(widgets.cfproxy_worker_domain_var.get(), "")
        self.assertEqual(widgets.bypass_cdn_provider_var.get(), "Google CDN (google-gfe)")
        dialog.cancel()
        self.assertTrue(dialog.closed)
