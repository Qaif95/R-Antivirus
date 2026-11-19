#!/usr/bin/env python3
"""
tools/boot_scanner.py
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

    def is_boot_scan_scheduled(self):
        """Checks whether RAntiVirusBootScan is currently registered in Windows Task Scheduler."""
        if os.name != "nt":
            return False
        try:
            ps_cmd = f"Get-ScheduledTask -TaskName '{self.TASK_NAME}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TaskName"
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
        if not os.path.exists(self.clamscan_path):
            self.log(f"[BOOT SCAN ERROR] ClamAV executable not found at: {self.clamscan_path}", "threat")
            return False

        try:
            clean_target = target_path.rstrip("\\/") + "\\" if len(target_path) <= 3 else target_path
            self.log(f"[BOOT SCAN] Configuring startup scan task for target: {clean_target}", "shield")
            escaped_exe = self.clamscan_path.replace("'", "''")
            escaped_target = clean_target.replace("'", "''")

            ps_cmd = f"""
            $Action = New-ScheduledTaskAction -Execute '{escaped_exe}' -Argument '-r --infected --no-warnings "{escaped_target}"'
            $Trigger = New-ScheduledTaskTrigger -AtStartup
            $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 4)
            Register-ScheduledTask -TaskName '{self.TASK_NAME}' -Action $Action -Trigger $Trigger -Settings $Settings -Force | Out-Null
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
            ps_cmd = f"Unregister-ScheduledTask -TaskName '{self.TASK_NAME}' -Confirm:$false -ErrorAction SilentlyContinue"
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