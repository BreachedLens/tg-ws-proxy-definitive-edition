import logging
import unittest
from unittest import mock

import windows
from utils import tray_common


class SettingsTrayCallbackTest(unittest.TestCase):
    def test_tray_click_logs_and_starts_protected_settings_worker(self):
        worker = mock.Mock()
        worker.start = mock.Mock()
        with (
            mock.patch.object(windows.threading, "Thread", return_value=worker) as thread,
            self.assertLogs("tg-ws-tray", level="INFO") as captured,
        ):
            windows._on_edit_config()

        self.assertTrue(any("Opening settings dialog..." in line for line in captured.output))
        thread.assert_called_once()
        self.assertIs(thread.call_args.kwargs["target"], windows._open_settings_dialog)
        worker.start.assert_called_once_with()

    def test_tray_click_logs_thread_start_base_exception(self):
        with (
            mock.patch.object(windows.threading, "Thread", side_effect=KeyboardInterrupt),
            self.assertLogs("tg-ws-tray", level="INFO") as captured,
        ):
            windows._on_edit_config()

        self.assertTrue(any("Opening settings dialog..." in line for line in captured.output))
        self.assertTrue(any("Settings dialog failed" in line for line in captured.output))

    def test_ctk_queue_exception_is_logged_and_releases_waiter(self):
        root = mock.Mock()
        tray_common._ctk_root = root
        root.after.side_effect = lambda _delay, callback: callback()
        failed = KeyboardInterrupt("callback failure")

        with (
            mock.patch.object(tray_common, "_ctk_root_stopped", tray_common.threading.Event()),
            self.assertLogs("tg-ws-tray", level="ERROR") as captured,
        ):
            tray_common.ctk_run_dialog(lambda _done: (_ for _ in ()).throw(failed))

        self.assertTrue(any("Settings dialog failed" in line for line in captured.output))

    def test_ctk_root_initialization_base_exception_is_logged(self):
        ready = tray_common.threading.Event()
        errors = []

        class FailedCtk:
            @staticmethod
            def set_appearance_mode(_mode):
                return None

            @staticmethod
            def set_default_color_theme(_theme):
                return None

            @staticmethod
            def CTk():
                raise KeyboardInterrupt("root construction failed")

        with (
            mock.patch.object(tray_common, "_ctk_root", None),
            mock.patch.object(tray_common, "_ctk_root_ready", ready),
            mock.patch.object(tray_common, "_ctk_root_stopped", tray_common.threading.Event()),
            mock.patch.object(tray_common, "_ctk_root_init_lock", tray_common.threading.Lock()),
            self.assertLogs("tg-ws-tray", level="ERROR") as captured,
        ):
            self.assertFalse(tray_common.ensure_ctk_thread(FailedCtk, "auto"))

        self.assertTrue(ready.is_set())
        self.assertTrue(any("Settings dialog failed" in line for line in captured.output))


if __name__ == "__main__":
    unittest.main()
