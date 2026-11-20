import os
import sys
import ctypes
import subprocess

# ═══════════════════════════════════════════════════════════════════════
#  PATH SETUP
# ═══════════════════════════════════════════════════════════════════════
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT_DIR, "data")

OPS_DIR = os.path.join(DATA_DIR, "Operations")
INTERFACE_DIR = os.path.join(DATA_DIR, "Interface")
COMMON_DIR = os.path.join(DATA_DIR, "Common")

for d in (OPS_DIR, INTERFACE_DIR, COMMON_DIR):
    if d not in sys.path:
        sys.path.insert(0, d)


# ═══════════════════════════════════════════════════════════════════════
#  ADMIN PRIVILEGES
# ═══════════════════════════════════════════════════════════════════════
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


if os.name == "nt" and not is_admin():
    try:
        script_and_args = [os.path.abspath(__file__)] + sys.argv[1:]
        params = subprocess.list2cmdline(script_and_args)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, ROOT_DIR, 1)
    except Exception:
        pass
    sys.exit()


# ═══════════════════════════════════════════════════════════════════════
#  IMPORTS
# ═══════════════════════════════════════════════════════════════════════
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

from clamavnet_engine import RAntiVirusEngine
from bridge import EngineBridge
from interface import RAntivirusWindow


# ═══════════════════════════════════════════════════════════════════════
#  CONTROLLER
# ═══════════════════════════════════════════════════════════════════════
class AppController:
    def __init__(self, app):
        self.app = app
        self.bridge = EngineBridge()

        self.engine = RAntiVirusEngine(
            base_dir=DATA_DIR,
            log_callback=lambda msg, tag=None: self.bridge.log_signal.emit(str(msg), str(tag or "")),
            notify_callback=lambda t, m, a=True: self.bridge.notify_signal.emit(str(t), str(m), bool(a)),
            threat_callback=lambda: self.bridge.threat_signal.emit(),
        )

        self.win = RAntivirusWindow(self.engine, self.bridge)
        self._connect_signals()

    def _connect_signals(self):
        self.win.theme_changed.connect(self._on_theme_changed)
        self.win.rtl_changed.connect(self._on_rtl_changed)
        self.win.scan_requested.connect(self._run_scan)
        self.win.stop_requested.connect(self.engine.stop_active_process)
        self.win.update_defs_requested.connect(self.engine.run_freshclam)
        self.win.full_scan_requested.connect(self._start_full_disk_scan)
        self.win.settings_saved.connect(self._save_settings)
        self.win.schedule_saved.connect(self._save_schedule)
        self.win.exclusions_changed.connect(self._refresh_exclusions)
        self.win.quarantine_action.connect(self._handle_quarantine)

    def _on_theme_changed(self, theme):
        if "ui" not in self.engine.config or not isinstance(self.engine.config["ui"], dict):
            self.engine.config["ui"] = {}
        self.engine.config["ui"]["theme"] = theme
        self.engine.save_config()

    def _on_rtl_changed(self, rtl):
        if "ui" not in self.engine.config or not isinstance(self.engine.config["ui"], dict):
            self.engine.config["ui"] = {}
        self.engine.config["ui"]["rtl"] = rtl
        self.engine.save_config()
        self.app.setLayoutDirection(Qt.RightToLeft if rtl else Qt.LeftToRight)

    def _run_scan(self, target, is_clam, opts):
        if is_clam:
            self.engine.run_clamav_scan(
                target=target,
                recursive=opts.get("recursive", True),
                infected_only=opts.get("infected", True),
                archive=opts.get("archive", True),
                auto_quarantine=opts.get("quarantine", False),
                source_label="ClamAV Local Scan",
                progress_callback=lambda p, c, t: self.bridge.progress_signal.emit(p, c, t),
            )
            self.win.start_scan_polling()
        else:
            self.engine.check_virustotal(
                target,
                on_result=lambda ok, info: self.bridge.scan_result_signal.emit(f"VirusTotal: {info}", bool(ok))
            )

    def _start_full_disk_scan(self):
        self.engine.run_full_system_scan(
            auto_quarantine=False,
            archive=True,
            progress_callback=lambda p, c, t: self.bridge.progress_signal.emit(p, c, t),
            on_complete=lambda n, th: self.bridge.scan_result_signal.emit(f"Full scan: {n} drives, {th} threats", True)
        )
        self.win.start_scan_polling()

    def _save_settings(self, config_data):
        for k, v in (config_data or {}).items():
            if k == "ui" and isinstance(v, dict):
                existing_ui = self.engine.config.get("ui")
                if not isinstance(existing_ui, dict):
                    existing_ui = {}
                existing_ui.update(v)
                self.engine.config["ui"] = existing_ui
            else:
                self.engine.config[k] = v
        self.engine.save_config()
        self.bridge.popup_signal.emit("Success", "Settings saved successfully.")

    def _save_schedule(self, schedule_data):
        self.engine.config["schedule"] = schedule_data
        self.engine.save_config()
        self.bridge.popup_signal.emit("Success", "Schedule saved.")

    def _refresh_exclusions(self):
        exclusions = self.engine.config.get("exclusions", [])
        for exc in exclusions:
            self.engine.clear_threat_for_target(exc)
        self.win.refresh_exclusions(exclusions)

    def _handle_quarantine(self, action, filename):
        if action == "restore":
            self.engine.restore_quarantined_file(filename)
        elif action == "delete":
            fpath = os.path.join(self.engine.quarantine_dir, filename)
            if os.path.isfile(fpath):
                os.remove(fpath)
            self.engine.remove_quarantine_entry(filename)
            self.engine.clear_threat_for_target(filename)
        self.win.refresh_quarantine()


# ═══════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("R Antivirus")

    controller = AppController(app)

    rtl_pref = controller.engine.config.get("ui", {}).get("rtl", False)
    if rtl_pref:
        app.setLayoutDirection(Qt.RightToLeft)
        controller.win.set_rtl_state(True)

    controller.win.show()
    sys.exit(app.exec())
