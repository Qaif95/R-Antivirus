"""
data/Operations/boot_scanner.py
Boot-Time / Startup Scan module for R antivirus
"""

import os
import subprocess


class BootScanner:
    TASK_NAME = "RAntiVirusBootScan"

    def __init__(self, clamscan_path, log_callback):
        self.clamscan_path = clamscan_path
        self.log = log_callback

    def _hidden_startupinfo(self):
        if os.name == "nt":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            return si
        return None

    @staticmethod
    def _ps_single_quote(value: str) -> str:
        return str(value).replace("'", "''")

    @staticmethod
    def _format_task_target_arg(target_path: str) -> str:
        cleaned = os.path.normpath(str(target_path).strip())
        if len(cleaned) == 2 and cleaned[1] == ":":
            cleaned = cleaned + "\\"
        elif len(cleaned) > 3 and cleaned.endswith("\\"):
            cleaned = cleaned.rstrip("\\")
        escaped_dq = cleaned.replace('"', '""')
        return f'-r --infected --no-warnings "{escaped_dq}"'

    def is_boot_scan_scheduled(self):
        """Checks whether RAntiVirusBootScan is currently registered in Windows Task Scheduler."""
        if os.name != "nt":
            return False
        try:
            ps_cmd = (
                f"Get-ScheduledTask -TaskName '{self._ps_single_quote(self.TASK_NAME)}' "
                f"-ErrorAction SilentlyContinue | Select-Object -ExpandProperty TaskName"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                startupinfo=self._hidden_startupinfo(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            return self.TASK_NAME.lower() in (res.stdout or "").strip().lower()
        except Exception:
            return False

    def schedule_boot_scan(self, target_path="C:\\"):
        exe_path = str(self.clamscan_path or "").strip()
        if not exe_path or not os.path.isfile(exe_path):
            self.log(f"[BOOT SCAN ERROR] ClamAV executable not found at: {exe_path}", "threat")
            return False

        try:
            safe_target = target_path.strip() if target_path and target_path.strip() else "C:\\"
            arg_str = self._format_task_target_arg(safe_target)
            self.log(f"[BOOT SCAN] Configuring startup scan task for target: {safe_target}", "shield")

            escaped_exe = self._ps_single_quote(exe_path)
            escaped_args = self._ps_single_quote(arg_str)
            escaped_task = self._ps_single_quote(self.TASK_NAME)

            ps_cmd = f"""
            $Action = New-ScheduledTaskAction -Execute '{escaped_exe}' -Argument '{escaped_args}'
            $Trigger = New-ScheduledTaskTrigger -AtStartup
            $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 4)
            Register-ScheduledTask -TaskName '{escaped_task}' -Action $Action -Trigger $Trigger -Settings $Settings -Force | Out-Null
            """
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                check=True,
                startupinfo=self._hidden_startupinfo(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            self.log("[BOOT SCAN] Successfully scheduled Boot-Time Scan for next system startup.", "ok")
            return True
        except Exception as e:
            self.log(f"[BOOT SCAN ERROR] {e}", "threat")
            return False

    def remove_boot_scan(self):
        try:
            escaped_task = self._ps_single_quote(self.TASK_NAME)
            ps_cmd = f"Unregister-ScheduledTask -TaskName '{escaped_task}' -Confirm:$false -ErrorAction SilentlyContinue"
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                startupinfo=self._hidden_startupinfo(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            self.log("[BOOT SCAN] Boot scan schedule removed successfully.", "ok")
            return True
        except Exception as e:
            self.log(f"[BOOT SCAN ERROR] Failed to remove task: {e}", "threat")
            return False
