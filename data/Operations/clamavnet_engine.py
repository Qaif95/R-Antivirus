#!/usr/bin/env python3
"""
Operations/clamavnet_engine.py
Backend Engine for R antivirus
"""

import os
import json
import csv
import hashlib
import shutil
import subprocess
import threading
import time
import queue
import urllib.request
import urllib.error
from datetime import datetime
import psutil

from boot_scanner import BootScanner


class WindowsFolderWatcher:
    def __init__(self, folder_path, on_file_event, is_excluded_fn):
        self.folder_path = folder_path
        self.on_file_event = on_file_event
        self.is_excluded_fn = is_excluded_fn
        self.process = None
        self.running = False
        self._recent = {}
        self._lock = threading.Lock()

    def start(self):
        if self.running or not os.path.isdir(self.folder_path):
            return
        self.running = True
        threading.Thread(target=self._run_watcher, daemon=True).start()

    def stop(self):
        self.running = False
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass
            self.process = None

    def _run_watcher(self):
        escaped_path = self.folder_path.replace("'", "''")
        ps_script = f"""
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = '{escaped_path}'
        $watcher.IncludeSubdirectories = $true
        $watcher.EnableRaisingEvents = $true

        $action = {{
            $path = $Event.SourceEventArgs.FullPath
            Write-Output $path
        }}

        Register-ObjectEvent $watcher 'Created' -Action $action | Out-Null
        Register-ObjectEvent $watcher 'Changed' -Action $action | Out-Null
        Register-ObjectEvent $watcher 'Renamed' -Action $action | Out-Null

        while ($true) {{
            Start-Sleep -Milliseconds 500
        }}
        """
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        try:
            self.process = subprocess.Popen(
                ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                startupinfo=startupinfo,
            )
            for raw_line in self.process.stdout:
                if not self.running:
                    break
                filepath = raw_line.strip()
                if not filepath or not os.path.isfile(filepath):
                    continue
                if filepath.endswith((".tmp", ".crdownload", ".part")):
                    continue
                if self.is_excluded_fn(filepath):
                    continue

                now = time.time()
                with self._lock:
                    if now - self._recent.get(filepath, 0) < 3.0:
                        continue
                    self._recent[filepath] = now

                self.on_file_event(filepath)
        except Exception:
            pass


class RAntiVirusEngine:
    def __init__(self, base_dir, log_callback, notify_callback, threat_callback):
        self.base_dir = base_dir
        self.log = log_callback
        self.notify = notify_callback
        self.on_threat = threat_callback

        self.quarantine_dir = os.path.join(self.base_dir, "Quarantine")
        self.restored_dir = os.path.join(self.base_dir, "Restored")
        self.reports_dir = os.path.join(self.base_dir, "Reports")
        self.config_path = os.path.join(self.base_dir, "r_antivirus_config.json")

        os.makedirs(self.quarantine_dir, exist_ok=True)
        os.makedirs(self.restored_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)

        self.config = self._load_config()
        self.process = None
        self.is_busy = False
        self.incident_history = []
        self.last_scan_summary = "No recent scan summary available."
        self._last_gpu_poll = 0.0
        self._cached_gpu = "N/A"

        self.stats = {
            "total_scanned": 0,
            "threats_blocked": 0,
            "last_update": "Never"
        }

        self.boot_scanner = BootScanner(
            clamscan_path=self.config.get("clamscan_path"),
            log_callback=self.log
        )

        self.realtime_active = False
        self.watcher = None
        self.realtime_queue = queue.Queue()

        threading.Thread(target=self._realtime_worker, daemon=True).start()

    def _load_config(self):
        default_cfg = {
            "clamscan_path": self.find_executable("clamscan"),
            "freshclam_path": self.find_executable("freshclam"),
            "vt_api_key": "",
            "max_filesize": "250M",
            "max_scansize": "500M",
            "exclusions": [self.quarantine_dir, self.restored_dir, self.reports_dir],
            "schedule": {"enabled": False, "frequency": "Daily", "time": "14:00", "target": ""},
        }
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    default_cfg.update(loaded)
            except Exception:
                pass
        return default_cfg

    def save_config(self):
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.log(f"[ERROR] Failed to save config: {e}", "threat")

    def find_executable(self, name):
        exe = name + ".exe" if os.name == "nt" else name
        found = shutil.which(name)
        if found:
            return found
        candidates = [
            os.path.join(r"C:\Program Files\ClamAV", exe),
            os.path.join(r"C:\Program Files\ClamAV\bin", exe),
            os.path.join(r"C:\Program Files (x86)\ClamAV", exe),
            os.path.join(r"C:\Program Files (x86)\ClamAV\bin", exe),
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return name

    def is_excluded(self, path):
        norm_target = os.path.normcase(os.path.abspath(path))
        for exc in self.config.get("exclusions", []):
            norm_exc = os.path.normcase(os.path.abspath(exc))
            if norm_target == norm_exc or norm_target.startswith(norm_exc + os.sep):
                return True
        return False

    def add_exclusion(self, path):
        abs_path = os.path.abspath(path)
        if abs_path not in self.config["exclusions"]:
            self.config["exclusions"].append(abs_path)
            self.save_config()

    def remove_exclusion(self, path):
        if path in self.config["exclusions"]:
            self.config["exclusions"].remove(path)
            self.save_config()

    def record_incident(self, source, target, status, details):
        self.incident_history.append(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source": source,
                "target": target,
                "status": status,
                "details": details,
            }
        )
        if status == "THREAT":
            self.stats["threats_blocked"] += 1

    def _get_gpu_usage_cached(self):
        if os.name != "nt":
            return "N/A"
        now = time.time()
        if now - self._last_gpu_poll < 4.0:
            return self._cached_gpu
        self._last_gpu_poll = now

        def _poll_gpu():
            try:
                ps_cmd = (
                    "$c = Get-Counter '\\GPU Engine(*)\\Utilization Percentage' -ErrorAction SilentlyContinue; "
                    "if ($c) { "
                    "$sum = ($c.CounterSamples | Measure-Object -Property CookedValue -Sum).Sum; "
                    "[math]::Round([math]::Min(100, $sum), 1) "
                    "}"
                )
                res = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    startupinfo=self._hidden_startupinfo(),
                    timeout=5,
                )
                val = (res.stdout or "").strip()
                if val:
                    self._cached_gpu = f"{val}%"
            except Exception:
                pass

        threading.Thread(target=_poll_gpu, daemon=True).start()
        return self._cached_gpu

    def get_system_performance(self):
        try:
            cpu_usage = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            ram_usage = mem.percent
            ram_used_gb = round(mem.used / (1024**3), 1)
            ram_total_gb = round(mem.total / (1024**3), 1)
            gpu_text = self._get_gpu_usage_cached()
            return {
                "cpu": cpu_usage,
                "ram_pct": ram_usage,
                "ram_text": f"{ram_used_gb} GB / {ram_total_gb} GB ({ram_usage}%)",
                "gpu_text": gpu_text,
            }
        except Exception:
            return {"cpu": 0, "ram_pct": 0, "ram_text": "N/A", "gpu_text": "N/A"}

    def is_boot_scan_scheduled(self):
        return self.boot_scanner.is_boot_scan_scheduled()

    def schedule_boot_scan(self, target_path="C:\\"):
        self.boot_scanner.clamscan_path = self.config.get("clamscan_path")
        return self.boot_scanner.schedule_boot_scan(target_path)

    def remove_boot_scan(self):
        return self.boot_scanner.remove_boot_scan()

    def restore_quarantined_file(self, quarantine_filename):
        src_path = os.path.join(self.quarantine_dir, quarantine_filename)
        if not os.path.isfile(src_path):
            return None
        try:
            clean_name = quarantine_filename
            if clean_name.endswith(".quarantine"):
                clean_name = clean_name[: -len(".quarantine")]
            if len(clean_name) > 16 and clean_name[8] == "_" and clean_name[15] == "_":
                clean_name = clean_name[16:]

            dest_path = os.path.join(self.restored_dir, clean_name)
            shutil.move(src_path, dest_path)
            self.log(f"[RESTORED] Moved {quarantine_filename} -> {dest_path}", "ok")
            return dest_path
        except Exception as e:
            self.log(f"[ERROR] Restore failed: {e}", "threat")
            return None

    def get_file_sha256(self, file_path):
        if not os.path.isfile(file_path):
            return None
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def export_report(self, fmt="html"):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if fmt == "csv":
            out_path = os.path.join(self.reports_dir, f"R_antivirus_Report_{ts}.csv")
            with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=["timestamp", "source", "target", "status", "details"])
                writer.writeheader()
                writer.writerows(self.incident_history)
            return out_path

        out_path = os.path.join(self.reports_dir, f"R_antivirus_Report_{ts}.html")
        rows_html = ""
        for item in self.incident_history:
            color = "#ffebee" if item["status"] == "THREAT" else "#e8f5e9"
            badge = "#c62828" if item["status"] == "THREAT" else "#2e7d32"
            rows_html += f"""
            <tr style="background:{color};">
                <td>{item['timestamp']}</td>
                <td>{item['source']}</td>
                <td>{item['target']}</td>
                <td style="color:{badge};font-weight:bold;">{item['status']}</td>
                <td>{item['details']}</td>
            </tr>"""
        if not rows_html:
            rows_html = "<tr><td colspan='5' style='text-align:center;'>No events recorded yet.</td></tr>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>R antivirus Report</title>
<style>
body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; background: #f4f6f8; }}
h1 {{ color: #4a148c; }}
table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 6px rgba(0,0,0,0.1); }}
th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 13px; }}
th {{ background: #263238; color: white; }}
</style></head>
<body>
<h1>R antivirus - Security Audit Report</h1>
<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Total Events: {len(self.incident_history)}</p>
<table>
<tr><th>Timestamp</th><th>Engine</th><th>Target File</th><th>Status</th><th>Details</th></tr>
{rows_html}
</table></body></html>"""
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)
        return out_path

    def quarantine_file(self, file_path, signature="Malware"):
        if not os.path.isfile(file_path):
            return None
        try:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = os.path.basename(file_path)
            dest_name = f"{ts}_{fname}.quarantine"
            dest_path = os.path.join(self.quarantine_dir, dest_name)
            shutil.move(file_path, dest_path)
            self.log(f"[QUARANTINED] Isolated: {dest_name}", "threat")
            return dest_name
        except Exception as e:
            self.log(f"[ERROR] Quarantine failed: {e}", "threat")
            return None

    def _hidden_startupinfo(self):
        if os.name == "nt":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            return si
        return None

    def _build_clamscan_cmd(self, target, recursive=True, infected_only=True, archive=True):
        cmd = [self.config["clamscan_path"]]
        if recursive:
            cmd.append("-r")
        if infected_only:
            cmd.append("--infected")
        if not archive:
            cmd.append("--scan-archive=no")

        max_fs = str(self.config.get("max_filesize", "")).strip()
        max_ss = str(self.config.get("max_scansize", "")).strip()
        if max_fs:
            cmd.append(f"--max-filesize={max_fs}")
        if max_ss:
            cmd.append(f"--max-scansize={max_ss}")

        cmd.append("--bell")

        for exc in self.config.get("exclusions", []):
            if os.path.isdir(exc):
                cmd.append(f"--exclude-dir={exc}")
            elif os.path.isfile(exc):
                cmd.append(f"--exclude={exc}")

        cmd.append(target)
        return cmd

    def run_clamav_scan(self, target, recursive=True, infected_only=True, archive=True, auto_quarantine=False, source_label="ClamAV Scan", progress_callback=None):
        if self.is_busy:
            self.log("[BUSY] Another task is already running.", "threat")
            return

        def task():
            self.is_busy = True
            threats = 0
            scan_summary_lines = []
            capturing_summary = False

            try:
                total_files = 1
                if os.path.isdir(target):
                    total_files = max(1, sum(len(files) for _, _, files in os.walk(target)))
                elif os.path.isfile(target):
                    total_files = 1

                cmd = self._build_clamscan_cmd(
                    target=target,
                    recursive=recursive,
                    infected_only=infected_only,
                    archive=archive,
                )
                self.log(f"\n[{source_label}] Scanning: {target} (Total items: {total_files})", "shield")

                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    startupinfo=self._hidden_startupinfo(),
                )

                scanned_count = 0
                for raw in self.process.stdout:
                    line = raw.strip()
                    if not line:
                        continue

                    if "Known viruses:" in line or capturing_summary:
                        capturing_summary = True
                        scan_summary_lines.append(line)
                        continue

                    scanned_count += 1
                    self.stats["total_scanned"] += 1

                    if progress_callback and total_files > 0:
                        percent = min(int((scanned_count / total_files) * 100), 100)
                        progress_callback(percent, scanned_count, total_files)

                    if line.endswith("FOUND"):
                        threats += 1
                        parts = line.rsplit(":", 1)
                        fpath = parts[0].strip()
                        sig = parts[1].replace("FOUND", "").strip() if len(parts) > 1 else "Threat"
                        self.log(f"[THREAT] {line}", "threat")
                        self.record_incident(source_label, fpath, "THREAT", sig)
                        self.notify("R antivirus Threat Alert", f"{os.path.basename(fpath)} ({sig})", True)
                        if auto_quarantine:
                            self.quarantine_file(fpath, sig)
                        self.on_threat()
                    else:
                        if not line.startswith("/") and not line.startswith("C:\\") and not line.startswith("D:\\"):
                            self.log(line)

                self.process.wait()
                self.last_scan_summary = "\n".join(scan_summary_lines) if scan_summary_lines else f"Scan completed. Threats found: {threats}"

                if progress_callback:
                    progress_callback(100, total_files, total_files)

                if threats == 0 and self.process.returncode == 0:
                    self.record_incident(source_label, target, "CLEAN", "No threats detected")
                    self.log(f"[{source_label}] Completed cleanly.", "ok")
                else:
                    self.log(f"[{source_label}] Finished (Threats: {threats}).", "ok")
            except Exception as e:
                self.log(f"[ERROR] Scan failed: {e}", "threat")
            finally:
                self.is_busy = False
                self.process = None

        threading.Thread(target=task, daemon=True).start()

    def run_full_system_scan(self, auto_quarantine=False, archive=True, progress_callback=None, on_complete=None):
        if self.is_busy:
            self.log("[BUSY] Another task is already running.", "threat")
            return

        def task():
            self.is_busy = True
            total_threats = 0
            try:
                drives = [f"{d}:\\" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
                if not drives:
                    self.log("[FULL SCAN] No drives detected.", "threat")
                    return

                self.log(f"\n[FULL SCAN] Starting full scan across drives: {', '.join(drives)}", "shield")
                num_drives = len(drives)

                for idx, drive in enumerate(drives):
                    if not self.is_busy:
                        break
                    self.log(f"[FULL SCAN] Scanning drive {drive} ({idx + 1}/{num_drives})...", "shield")
                    cmd = self._build_clamscan_cmd(
                        target=drive,
                        recursive=True,
                        infected_only=True,
                        archive=archive,
                    )
                    self.process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        startupinfo=self._hidden_startupinfo(),
                    )

                    drive_items = 0
                    for raw in self.process.stdout:
                        line = raw.strip()
                        if not line:
                            continue
                        drive_items += 1
                        self.stats["total_scanned"] += 1

                        if progress_callback:
                            overall_pct = min(100, int(((idx + min(0.95, drive_items / 5000.0)) / num_drives) * 100))
                            progress_callback(overall_pct, idx + 1, num_drives)

                        if line.endswith("FOUND"):
                            total_threats += 1
                            parts = line.rsplit(":", 1)
                            fpath = parts[0].strip()
                            sig = parts[1].replace("FOUND", "").strip() if len(parts) > 1 else "Threat"
                            self.log(f"[FULL SCAN THREAT] {line}", "threat")
                            self.record_incident("Full System Scan", fpath, "THREAT", sig)
                            self.notify("R antivirus Full Scan Alert", f"{os.path.basename(fpath)} ({sig})", True)
                            if auto_quarantine:
                                self.quarantine_file(fpath, sig)
                            self.on_threat()

                    self.process.wait()
                    self.process = None

                if progress_callback:
                    progress_callback(100, num_drives, num_drives)

                self.log(f"[FULL SCAN] Completed. Total threats found: {total_threats}", "ok")
                if on_complete:
                    on_complete(num_drives, total_threats)
            except Exception as e:
                self.log(f"[FULL SCAN ERROR] {e}", "threat")
            finally:
                self.is_busy = False
                self.process = None

        threading.Thread(target=task, daemon=True).start()

    def scan_startup_items(self, auto_quarantine=False, on_complete=None):
        if self.is_busy:
            self.log("[BUSY] Another scan is running.", "threat")
            return

        def task():
            self.is_busy = True
            try:
                self.log("\n[STARTUP SCAN] Inspecting Windows startup registries & folders...", "shield")
                ps_cmd = """
                $paths = @()
                $regPaths = @(
                    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                )
                foreach ($rp in $regPaths) {
                    if (Test-Path $rp) {
                        Get-ItemProperty $rp | Select-Object -Property * -ExcludeProperty PSChildName,PSPath,PSParentPath,PSProvider,PSIsContainer | ForEach-Object {
                            $_.PSObject.Properties | Where-Object { $_.Value -is [string] } | ForEach-Object {
                                if (Test-Path $_.Value) { $paths += $_.Value }
                            }
                        }
                    }
                }
                $startupDirs = @(
                    "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                    "$env:PROGRAMDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
                )
                foreach ($sd in $startupDirs) {
                    if (Test-Path $sd) {
                        Get-ChildItem $sd -File | ForEach-Object { $paths += $_.FullName }
                    }
                }
                $paths | Select-Object -Unique
                """
                res = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    startupinfo=self._hidden_startupinfo(),
                )
                startup_files = [p.strip() for p in res.stdout.splitlines() if p.strip() and os.path.isfile(p.strip()) and not self.is_excluded(p.strip())]
                self.log(f"[STARTUP SCAN] Found {len(startup_files)} startup executable items.", "shield")

                threats = 0
                for exe_path in startup_files:
                    if not self.is_busy:
                        break
                    self.stats["total_scanned"] += 1
                    scan_res = subprocess.run(
                        [self.config["clamscan_path"], "--no-summary", exe_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        startupinfo=self._hidden_startupinfo(),
                    )
                    out = scan_res.stdout.strip()
                    if "FOUND" in out:
                        threats += 1
                        sig = out.rsplit(":", 1)[-1].replace("FOUND", "").strip()
                        self.log(f"[STARTUP THREAT] {out}", "threat")
                        self.record_incident("Startup Scan", exe_path, "THREAT", sig)
                        self.notify("Startup Threat Detected!", f"{os.path.basename(exe_path)}", True)
                        if auto_quarantine:
                            self.quarantine_file(exe_path, sig)
                        self.on_threat()
                    else:
                        self.log(f"[STARTUP OK] {os.path.basename(exe_path)}", "shield")

                self.log(f"[STARTUP SCAN] Finished. Threats found: {threats}", "ok")
                if on_complete:
                    on_complete(len(startup_files), threats)
            except Exception as e:
                self.log(f"[STARTUP ERROR] {e}", "threat")
            finally:
                self.is_busy = False

        threading.Thread(target=task, daemon=True).start()

    def run_freshclam(self):
        if self.is_busy:
            self.log("[BUSY] Engine is busy.", "threat")
            return

        def task():
            self.is_busy = True
            try:
                self.log("\n[UPDATE] Updating definitions via freshclam...", "shield")
                self.process = subprocess.Popen(
                    [self.config["freshclam_path"]],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    startupinfo=self._hidden_startupinfo(),
                )
                for raw in self.process.stdout:
                    if raw.strip():
                        self.log(raw.strip())
                self.process.wait()
                self.stats["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M")
                self.log(f"[UPDATE] Finished with exit code: {self.process.returncode}", "ok")
            except Exception as e:
                self.log(f"[ERROR] freshclam failed: {e}", "threat")
            finally:
                self.is_busy = False
                self.process = None

        threading.Thread(target=task, daemon=True).start()

    def stop_active_process(self):
        if self.process and self.is_busy:
            try:
                self.process.terminate()
                self.log("[STOPPED] Process terminated.", "threat")
            except Exception as e:
                self.log(f"[ERROR] {e}", "threat")

    def scan_running_processes(self, auto_quarantine=False, on_complete=None):
        if self.is_busy:
            self.log("[BUSY] Another scan is running.", "threat")
            return

        def task():
            self.is_busy = True
            try:
                self.log("\n[MEMORY SCAN] Enumerating active processes...", "shield")
                ps_cmd = "Get-Process | Where-Object {$_.Path -ne $null} | Select-Object -ExpandProperty Path -Unique"
                res = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    startupinfo=self._hidden_startupinfo(),
                )
                exe_paths = [p.strip() for p in res.stdout.splitlines() if p.strip() and os.path.isfile(p.strip()) and not self.is_excluded(p.strip())]
                self.log(f"[MEMORY SCAN] Inspecting {len(exe_paths)} unique executables...", "shield")

                threats = 0
                for exe_path in exe_paths:
                    if not self.is_busy:
                        break
                    self.stats["total_scanned"] += 1
                    scan_res = subprocess.run(
                        [self.config["clamscan_path"], "--no-summary", exe_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        startupinfo=self._hidden_startupinfo(),
                    )
                    out = scan_res.stdout.strip()
                    if "FOUND" in out:
                        threats += 1
                        sig = out.rsplit(":", 1)[-1].replace("FOUND", "").strip()
                        self.log(f"[MEMORY THREAT] {out}", "threat")
                        self.record_incident("Memory Scan", exe_path, "THREAT", sig)
                        self.notify("Running Process Threat!", f"{os.path.basename(exe_path)}", True)
                        if auto_quarantine:
                            self.quarantine_file(exe_path, sig)
                        self.on_threat()

                self.log(f"[MEMORY SCAN] Finished. Threats found: {threats}", "ok")
                if on_complete:
                    on_complete(len(exe_paths), threats)
            except Exception as e:
                self.log(f"[MEMORY ERROR] {e}", "threat")
            finally:
                self.is_busy = False

        threading.Thread(target=task, daemon=True).start()

    def check_virustotal(self, file_path, on_result=None):
        api_key = self.config.get("vt_api_key", "").strip()
        if not api_key:
            self.log("[VT ERROR] API Key not set in Settings.", "threat")
            if on_result:
                on_result(False, "VirusTotal API Key is not set in Settings.")
            return

        def task():
            try:
                self.log(f"\n[VT] Hashing {os.path.basename(file_path)}...", "vt")
                sha256 = self.get_file_sha256(file_path)

                url = f"https://www.virustotal.com/api/v3/files/{sha256}"
                req = urllib.request.Request(url, headers={"x-apikey": api_key})
                with urllib.request.urlopen(req, timeout=12) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) if stats else 0
                    status = "THREAT" if malicious > 0 else "CLEAN"
                    detail = f"Detections: {malicious}/{total} engines"
                    self.record_incident("VirusTotal Cloud", file_path, status, detail)
                    if malicious > 0:
                        self.log(f"[VT ALERT] {os.path.basename(file_path)} -> {detail}", "threat")
                    else:
                        self.log(f"[VT CLEAN] {os.path.basename(file_path)} -> {detail}", "ok")
                    if on_result:
                        on_result(True, f"{detail}\nSHA-256: {sha256}")
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    self.log("[VT] File hash not found in VirusTotal database.", "vt")
                    if on_result:
                        on_result(False, "Hash not found in VirusTotal database (New or Private file).")
                else:
                    self.log(f"[VT ERROR] HTTP {e.code}", "threat")
                    if on_result:
                        on_result(False, f"HTTP Error {e.code}")
            except Exception as e:
                self.log(f"[VT ERROR] {e}", "threat")
                if on_result:
                    on_result(False, str(e))

        threading.Thread(target=task, daemon=True).start()

    def start_realtime(self, watch_dir, auto_quarantine=True):
        if self.realtime_active:
            return
        self.realtime_active = True
        self.rt_auto_quarantine = auto_quarantine
        self.watcher = WindowsFolderWatcher(watch_dir, self.realtime_queue.put, self.is_excluded)
        self.watcher.start()
        self.log(f"[SHIELD ON] Guarding: {watch_dir}", "shield")

    def stop_realtime(self):
        self.realtime_active = False
        if self.watcher:
            self.watcher.stop()
            self.watcher = None
        self.log("[SHIELD OFF] Shield stopped.", "shield")

    def _realtime_worker(self):
        while True:
            filepath = self.realtime_queue.get()
            if not self.realtime_active or not os.path.isfile(filepath) or self.is_excluded(filepath):
                continue
            time.sleep(0.6)
            if not os.path.isfile(filepath):
                continue

            try:
                res = subprocess.run(
                    [self.config["clamscan_path"], "--no-summary", "--no-warnings", filepath],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    startupinfo=self._hidden_startupinfo(),
                )
                self.stats["total_scanned"] += 1
                out = res.stdout.strip()
                if "FOUND" in out:
                    sig = out.rsplit(":", 1)[-1].replace("FOUND", "").strip()
                    self.log(f"[SHIELD BLOCKED] {out}", "threat")
                    self.record_incident("Real-Time Shield", filepath, "THREAT", sig)
                    self.notify("R antivirus Blocked Threat!", f"{os.path.basename(filepath)}", True)
                    if getattr(self, "rt_auto_quarantine", True):
                        self.quarantine_file(filepath, sig)
                    self.on_threat()
                else:
                    self.log(f"[SHIELD OK] {os.path.basename(filepath)}", "shield")
            except Exception as e:
                self.log(f"[SHIELD ERROR] {e}", "threat")