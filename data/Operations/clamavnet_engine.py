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
        self._thread = None

    def start(self):
        if self.running or not os.path.isdir(self.folder_path):
            return
        self.running = True
        self._thread = threading.Thread(target=self._run_watcher, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        proc = self.process
        self.process = None
        if proc is not None:
            try:
                if proc.stdout and not proc.stdout.closed:
                    proc.stdout.close()
            except Exception:
                pass
            try:
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

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
        startupinfo = None
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        try:
            proc = subprocess.Popen(
                ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                startupinfo=startupinfo,
            )
            self.process = proc
            if proc.stdout is None:
                return
            for raw_line in proc.stdout:
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
        finally:
            self.running = False


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
        self.manifest_path = os.path.join(self.quarantine_dir, "manifest.json")
        self.state_path = os.path.join(self.base_dir, "incidents_state.json")

        os.makedirs(self.quarantine_dir, exist_ok=True)
        os.makedirs(self.restored_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)

        self._state_lock = threading.Lock()
        self._proc_lock = threading.Lock()
        self._stop_requested = False

        self.config = self._load_config()
        self.quarantine_meta = self._load_quarantine_manifest()
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
        self._load_persistent_state()

        self.boot_scanner = BootScanner(
            clamscan_path=self.config.get("clamscan_path"),
            log_callback=self.log
        )

        self.realtime_active = False
        self.watcher = None
        self.watchers = []
        self.realtime_queue = queue.Queue()

        threading.Thread(target=self._realtime_worker, daemon=True).start()

    def _load_persistent_state(self):
        if not os.path.isfile(self.state_path):
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                loaded_stats = data.get("stats")
                if isinstance(loaded_stats, dict):
                    self.stats["total_scanned"] = int(loaded_stats.get("total_scanned", 0) or 0)
                    self.stats["threats_blocked"] = int(loaded_stats.get("threats_blocked", 0) or 0)
                    self.stats["last_update"] = str(loaded_stats.get("last_update", "Never") or "Never")
                loaded_inc = data.get("incident_history")
                if isinstance(loaded_inc, list):
                    self.incident_history = [x for x in loaded_inc if isinstance(x, dict)][-500:]
        except Exception:
            pass

    def _save_persistent_state(self):
        try:
            payload = {
                "stats": dict(self.stats),
                "incident_history": list(self.incident_history)[-500:],
            }
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.log(f"[ERROR] Failed to persist state: {e}", "threat")

    @staticmethod
    def _normalize_clean_name(hint: str) -> str:
        raw = str(hint or "").strip().replace("\\", "/")
        base = os.path.basename(raw)
        if base.lower().endswith(".quarantine"):
            base = base[:-len(".quarantine")]
        if len(base) > 16 and base[8] == "_" and base[15] == "_":
            base = base[16:]
        return base.lower()

    @staticmethod
    def _normalize_path_lower(path_str: str) -> str:
        return os.path.normpath(str(path_str or "").strip()).replace("\\", "/").lower()

    def _load_quarantine_manifest(self):
        if os.path.isfile(self.manifest_path):
            try:
                with open(self.manifest_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
        return {}

    def _save_quarantine_manifest(self):
        try:
            with open(self.manifest_path, "w", encoding="utf-8") as f:
                json.dump(self.quarantine_meta, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.log(f"[ERROR] Failed to save quarantine manifest: {e}", "threat")

    def remove_quarantine_entry(self, quarantine_filename):
        with self._state_lock:
            if quarantine_filename in self.quarantine_meta:
                del self.quarantine_meta[quarantine_filename]
                self._save_quarantine_manifest()

    def clear_threat_for_target(self, target_hint: str):
        if not target_hint:
            return
        norm_hint = self._normalize_path_lower(target_hint)
        clean_hint = self._normalize_clean_name(target_hint)

        with self._state_lock:
            remaining = []
            cleared_count = 0
            for inc in self.incident_history:
                inc_target = self._normalize_path_lower(inc.get("target", ""))
                inc_clean = self._normalize_clean_name(inc_target)
                matched = False
                if inc.get("status") == "THREAT":
                    if norm_hint and (
                        inc_target == norm_hint
                        or inc_target.startswith(norm_hint + "/")
                        or (clean_hint and inc_clean == clean_hint)
                    ):
                        matched = True
                if matched:
                    cleared_count += 1
                else:
                    remaining.append(inc)

            if cleared_count > 0:
                self.incident_history = remaining
                self.stats["threats_blocked"] = max(0, int(self.stats.get("threats_blocked", 0)) - cleared_count)
            else:
                self.stats["threats_blocked"] = max(0, int(self.stats.get("threats_blocked", 0)) - 1)
            self._save_persistent_state()

    def _has_valid_clamscan(self):
        exe_path = str(self.config.get("clamscan_path", "")).strip()
        if not exe_path:
            self.log("[ERROR] clamscan path is not configured.", "threat")
            return False
        if not os.path.isfile(exe_path):
            resolved = shutil.which(exe_path)
            if resolved and os.path.isfile(resolved):
                self.config["clamscan_path"] = resolved
                return True
            self.log(f"[ERROR] clamscan executable not found: {exe_path}", "threat")
            return False
        return True

    def _increment_scanned(self, count=1):
        with self._state_lock:
            self.stats["total_scanned"] += count

    def _estimate_target_items(self, target_path, cap=25000):
        if not os.path.exists(target_path):
            return 1
        if os.path.isfile(target_path):
            return 1
        total = 0
        try:
            for root, dirs, files in os.walk(target_path):
                if self.is_excluded(root):
                    dirs[:] = []
                    continue
                total += len(files)
                if total >= cap:
                    return cap
        except Exception:
            pass
        return max(1, total)

    def _load_config(self):
        downloads_dir = os.path.join(os.path.expanduser("~"), "Downloads")
        default_shield = downloads_dir if os.path.isdir(downloads_dir) else os.path.expanduser("~")
        default_cfg = {
            "clamscan_path": self.find_executable("clamscan"),
            "freshclam_path": self.find_executable("freshclam"),
            "vt_api_key": "",
            "max_filesize": "250M",
            "max_scansize": "500M",
            "shield_target": default_shield,
            "shield_targets": [default_shield],
            "exclusions": [self.quarantine_dir, self.restored_dir, self.reports_dir],
            "schedule": {"enabled": False, "frequency": "Daily", "time": "14:00", "target": ""},
        }
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    if isinstance(loaded, dict):
                        default_cfg.update(loaded)
            except Exception:
                pass
        if not str(default_cfg.get("shield_target", "")).strip():
            sched_target = str(default_cfg.get("schedule", {}).get("target", "")).strip()
            default_cfg["shield_target"] = sched_target or default_shield
        if not isinstance(default_cfg.get("shield_targets"), list) or not default_cfg["shield_targets"]:
            default_cfg["shield_targets"] = [default_cfg["shield_target"]]
        return default_cfg

    def save_config(self):
        try:
            with self._state_lock:
                cfg_snapshot = json.loads(json.dumps(self.config))
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(cfg_snapshot, f, indent=2, ensure_ascii=False)
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
        if not path:
            return False
        norm_target = os.path.normcase(os.path.abspath(path))
        if norm_target == os.path.normcase(os.path.abspath(self.manifest_path)):
            return True
        with self._state_lock:
            exclusions = list(self.config.get("exclusions", []))
        for exc in exclusions:
            norm_exc = os.path.normcase(os.path.abspath(exc))
            if norm_target == norm_exc or norm_target.startswith(norm_exc + os.sep):
                return True
        return False

    def add_exclusion(self, path):
        abs_path = os.path.abspath(path)
        with self._state_lock:
            if abs_path not in self.config["exclusions"]:
                self.config["exclusions"].append(abs_path)
        self.save_config()

    def remove_exclusion(self, path):
        abs_path = os.path.abspath(path)
        with self._state_lock:
            if path in self.config["exclusions"]:
                self.config["exclusions"].remove(path)
            elif abs_path in self.config["exclusions"]:
                self.config["exclusions"].remove(abs_path)
        self.save_config()

    def record_incident(self, source, target, status, details):
        with self._state_lock:
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
            self._save_persistent_state()

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
                    with self._state_lock:
                        self._cached_gpu = f"{val}%"
            except Exception:
                pass

        threading.Thread(target=_poll_gpu, daemon=True).start()
        with self._state_lock:
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
            with self._state_lock:
                meta_entry = self.quarantine_meta.get(quarantine_filename)

            orig_path = ""
            if isinstance(meta_entry, dict):
                orig_path = str(meta_entry.get("original_path", "")).strip()
            elif isinstance(meta_entry, str):
                orig_path = meta_entry.strip()

            clean_name = quarantine_filename
            if clean_name.endswith(".quarantine"):
                clean_name = clean_name[: -len(".quarantine")]
            if len(clean_name) > 16 and clean_name[8] == "_" and clean_name[15] == "_":
                clean_name = clean_name[16:]

            if orig_path:
                parent_dir = os.path.dirname(orig_path)
                if parent_dir and os.path.isdir(parent_dir):
                    dest_path = orig_path
                    if os.path.exists(dest_path):
                        base, ext = os.path.splitext(dest_path)
                        dest_path = f"{base}_restored_{datetime.now().strftime('%H%M%S')}{ext}"
                    shutil.move(src_path, dest_path)
                    self.remove_quarantine_entry(quarantine_filename)
                    self.clear_threat_for_target(orig_path or clean_name)
                    self.log(f"[RESTORED] Moved {quarantine_filename} -> {dest_path}", "ok")
                    return dest_path

            os.makedirs(self.restored_dir, exist_ok=True)
            dest_path = os.path.join(self.restored_dir, clean_name)
            shutil.move(src_path, dest_path)
            self.remove_quarantine_entry(quarantine_filename)
            self.clear_threat_for_target(clean_name)
            self.log(f"[RESTORED] Moved {quarantine_filename} -> {dest_path}", "ok")
            return dest_path
        except Exception as e:
            self.log(f"[ERROR] Restore failed: {e}", "threat")
            return None

    def get_file_sha256(self, file_path):
        if not file_path or not os.path.isfile(file_path):
            return None
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def export_report(self, fmt="html"):
        with self._state_lock:
            history_snapshot = list(self.incident_history)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if fmt == "csv":
            out_path = os.path.join(self.reports_dir, f"R_antivirus_Report_{ts}.csv")
            with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=["timestamp", "source", "target", "status", "details"])
                writer.writeheader()
                writer.writerows(history_snapshot)
            return out_path

        out_path = os.path.join(self.reports_dir, f"R_antivirus_Report_{ts}.html")
        rows_html = ""
        for item in history_snapshot:
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
<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Total Events: {len(history_snapshot)}</p>
<table>
<tr><th>Timestamp</th><th>Engine</th><th>Target File</th><th>Status</th><th>Details</th></tr>
{rows_html}
</table></body></html>"""
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)
        return out_path

    def quarantine_file(self, file_path, signature="Malware"):
        if not file_path or not os.path.isfile(file_path):
            return None
        try:
            abs_orig = os.path.abspath(file_path)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = os.path.basename(abs_orig)
            dest_name = f"{ts}_{fname}.quarantine"
            dest_path = os.path.join(self.quarantine_dir, dest_name)
            shutil.move(abs_orig, dest_path)

            with self._state_lock:
                self.quarantine_meta[dest_name] = {
                    "original_path": abs_orig,
                    "filename": fname,
                    "signature": signature,
                    "quarantined_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
                self._save_quarantine_manifest()

            self.log(f"[QUARANTINED] Isolated: {dest_name} (from {abs_orig})", "threat")
            return dest_name
        except PermissionError as e:
            self.log(
                f"[LOCKED/DENIED] Cannot move '{file_path}' ({e}). Close locking apps or exclude trusted system folders.",
                "threat",
            )
            return None
        except OSError as e:
            if getattr(e, "winerror", None) == 5:
                self.log(
                    f"[LOCKED/DENIED] Access denied (WinError 5) on '{file_path}'. File may be in use or protected.",
                    "threat",
                )
            else:
                self.log(f"[ERROR] Quarantine failed: {e}", "threat")
            return None
        except Exception as e:
            self.log(f"[ERROR] Quarantine failed: {e}", "threat")
            return None

    def _hidden_startupinfo(self):
        if os.name == "nt":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            return si
        return None

    def _set_active_process(self, proc):
        with self._proc_lock:
            self.process = proc

    def _clear_active_process(self, proc=None):
        with self._proc_lock:
            if proc is None or self.process is proc:
                self.process = None

    def _begin_task(self):
        with self._proc_lock:
            if self.is_busy:
                return False
            self.is_busy = True
            self._stop_requested = False
            self.process = None
            return True

    def _end_task(self):
        with self._proc_lock:
            self.is_busy = False
            self._stop_requested = False
            self.process = None

    def _is_stop_requested(self):
        with self._proc_lock:
            return self._stop_requested

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

        with self._state_lock:
            exclusions = list(self.config.get("exclusions", []))

        for exc in exclusions:
            if os.path.isdir(exc):
                cmd.append(f"--exclude-dir={exc}")
            elif os.path.isfile(exc):
                cmd.append(f"--exclude={exc}")

        cmd.append(target)
        return cmd

    def run_clamav_scan(self, target, recursive=True, infected_only=True, archive=True, auto_quarantine=False, source_label="ClamAV Scan", progress_callback=None):
        if not target or not os.path.exists(target):
            self.log(f"[ERROR] Target path does not exist: {target}", "threat")
            return
        if not self._has_valid_clamscan():
            return
        if not self._begin_task():
            self.log("[BUSY] Another task is already running.", "threat")
            return

        def task():
            threats = 0
            scan_summary_lines = []
            capturing_summary = False
            proc = None

            try:
                total_files = self._estimate_target_items(target)
                cmd = self._build_clamscan_cmd(
                    target=target,
                    recursive=recursive,
                    infected_only=infected_only,
                    archive=archive,
                )
                self.log(f"\n[{source_label}] Scanning: {target} (Estimated items: {total_files})", "shield")

                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    startupinfo=self._hidden_startupinfo(),
                )
                self._set_active_process(proc)

                scanned_count = 0
                last_ui_emit = 0.0
                if proc.stdout is not None:
                    for raw in proc.stdout:
                        if self._is_stop_requested():
                            break
                        line = raw.strip()
                        if not line:
                            continue

                        if "Known viruses:" in line or capturing_summary:
                            capturing_summary = True
                            scan_summary_lines.append(line)
                            continue

                        scanned_count += 1
                        self._increment_scanned(1)

                        now = time.monotonic()
                        if progress_callback and total_files > 0 and (now - last_ui_emit >= 0.12 or scanned_count == total_files):
                            last_ui_emit = now
                            percent = min(int((scanned_count / max(total_files, scanned_count)) * 99), 99)
                            progress_callback(percent, scanned_count, max(total_files, scanned_count))

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
                            is_drive_path = len(line) >= 3 and line[1] == ":" and line[2] in ("\\", "/")
                            if not line.startswith("/") and not is_drive_path:
                                self.log(line)

                proc.wait()
                self.last_scan_summary = "\n".join(scan_summary_lines) if scan_summary_lines else f"Scan completed. Threats found: {threats}"

                final_total = max(total_files, scanned_count, 1)
                if progress_callback:
                    progress_callback(100, final_total, final_total)

                if self._is_stop_requested():
                    self.log(f"[{source_label}] Stopped by user (Threats: {threats}).", "threat")
                elif threats == 0 and proc.returncode == 0:
                    self.record_incident(source_label, target, "CLEAN", "No threats detected")
                    self.log(f"[{source_label}] Completed cleanly.", "ok")
                else:
                    self.log(f"[{source_label}] Finished (Threats: {threats}).", "ok")
            except Exception as e:
                self.log(f"[ERROR] Scan failed: {e}", "threat")
            finally:
                self._clear_active_process(proc)
                self._end_task()

        threading.Thread(target=task, daemon=True).start()

    def run_full_system_scan(self, auto_quarantine=False, archive=True, progress_callback=None, on_complete=None):
        if not self._has_valid_clamscan():
            return
        if not self._begin_task():
            self.log("[BUSY] Another task is already running.", "threat")
            return

        def task():
            total_threats = 0
            num_drives = 0
            try:
                drives = [f"{d}:\\" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
                if not drives:
                    self.log("[FULL SCAN] No drives detected.", "threat")
                    return

                self.log(f"\n[FULL SCAN] Starting full scan across drives: {', '.join(drives)}", "shield")
                num_drives = len(drives)

                for idx, drive in enumerate(drives):
                    if self._is_stop_requested():
                        break
                    self.log(f"[FULL SCAN] Scanning drive {drive} ({idx + 1}/{num_drives})...", "shield")
                    cmd = self._build_clamscan_cmd(
                        target=drive,
                        recursive=True,
                        infected_only=True,
                        archive=archive,
                    )
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        startupinfo=self._hidden_startupinfo(),
                    )
                    self._set_active_process(proc)

                    drive_items = 0
                    last_ui_emit = 0.0
                    try:
                        if proc.stdout is not None:
                            for raw in proc.stdout:
                                if self._is_stop_requested():
                                    break
                                line = raw.strip()
                                if not line:
                                    continue
                                drive_items += 1
                                self._increment_scanned(1)

                                now = time.monotonic()
                                if progress_callback and (now - last_ui_emit >= 0.15):
                                    last_ui_emit = now
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
                        proc.wait()
                    finally:
                        self._clear_active_process(proc)

                if progress_callback:
                    progress_callback(100, num_drives, num_drives)

                self.log(f"[FULL SCAN] Completed. Total threats found: {total_threats}", "ok")
                if on_complete:
                    on_complete(num_drives, total_threats)
            except Exception as e:
                self.log(f"[FULL SCAN ERROR] {e}", "threat")
            finally:
                self._end_task()

        threading.Thread(target=task, daemon=True).start()

    def scan_startup_items(self, auto_quarantine=False, on_complete=None):
        if not self._has_valid_clamscan():
            return
        if not self._begin_task():
            self.log("[BUSY] Another scan is running.", "threat")
            return

        def task():
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
                startup_files = [
                    p.strip()
                    for p in res.stdout.splitlines()
                    if p.strip() and os.path.isfile(p.strip()) and not self.is_excluded(p.strip())
                ]
                self.log(f"[STARTUP SCAN] Found {len(startup_files)} startup executable items.", "shield")

                threats = 0
                for exe_path in startup_files:
                    if self._is_stop_requested():
                        break
                    self._increment_scanned(1)
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
                self._end_task()

        threading.Thread(target=task, daemon=True).start()

    def run_freshclam(self):
        fresh_path = str(self.config.get("freshclam_path", "")).strip()
        if not fresh_path or (not os.path.isfile(fresh_path) and not shutil.which(fresh_path)):
            self.log(f"[ERROR] freshclam executable not found: {fresh_path}", "threat")
            return
        if not self._begin_task():
            self.log("[BUSY] Engine is busy.", "threat")
            return

        def task():
            proc = None
            try:
                self.log("\n[UPDATE] Updating definitions via freshclam...", "shield")
                proc = subprocess.Popen(
                    [self.config["freshclam_path"]],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    startupinfo=self._hidden_startupinfo(),
                )
                self._set_active_process(proc)
                if proc.stdout is not None:
                    for raw in proc.stdout:
                        if self._is_stop_requested():
                            break
                        if raw.strip():
                            self.log(raw.strip())
                proc.wait()
                with self._state_lock:
                    self.stats["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M")
                    self._save_persistent_state()
                self.log(f"[UPDATE] Finished with exit code: {proc.returncode}", "ok")
            except Exception as e:
                self.log(f"[ERROR] freshclam failed: {e}", "threat")
            finally:
                self._clear_active_process(proc)
                self._end_task()

        threading.Thread(target=task, daemon=True).start()

    def stop_active_process(self):
        with self._proc_lock:
            self._stop_requested = True
            proc = self.process
            busy = self.is_busy
        if proc and busy:
            try:
                if proc.poll() is None:
                    proc.terminate()
                self.log("[STOPPED] Process terminated.", "threat")
            except Exception as e:
                self.log(f"[ERROR] {e}", "threat")

    def scan_running_processes(self, auto_quarantine=False, on_complete=None):
        if not self._has_valid_clamscan():
            return
        if not self._begin_task():
            self.log("[BUSY] Another scan is running.", "threat")
            return

        def task():
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
                exe_paths = [
                    p.strip()
                    for p in res.stdout.splitlines()
                    if p.strip() and os.path.isfile(p.strip()) and not self.is_excluded(p.strip())
                ]
                self.log(f"[MEMORY SCAN] Inspecting {len(exe_paths)} unique executables...", "shield")

                threats = 0
                for exe_path in exe_paths:
                    if self._is_stop_requested():
                        break
                    self._increment_scanned(1)
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
                self._end_task()

        threading.Thread(target=task, daemon=True).start()

    def check_virustotal(self, file_path, on_result=None):
        api_key = str(self.config.get("vt_api_key", "")).strip()
        if not api_key:
            self.log("[VT ERROR] API Key not set in Settings.", "threat")
            if on_result:
                on_result(False, "VirusTotal API Key is not set in Settings.")
            return

        if not file_path or not os.path.isfile(file_path):
            self.log(f"[VT ERROR] Target file does not exist: {file_path}", "threat")
            if on_result:
                on_result(False, "Target file does not exist or is not a valid file.")
            return

        def task():
            try:
                self.log(f"\n[VT] Hashing {os.path.basename(file_path)}...", "vt")
                sha256 = self.get_file_sha256(file_path)
                if not sha256:
                    self.log("[VT ERROR] Failed to compute SHA-256 hash.", "threat")
                    if on_result:
                        on_result(False, "Failed to compute SHA-256 hash for file.")
                    return

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
        targets = []
        if isinstance(watch_dir, (list, tuple)):
            targets.extend(watch_dir)
        elif watch_dir:
            targets.append(watch_dir)

        cfg_targets = self.config.get("shield_targets")
        if isinstance(cfg_targets, list):
            for t in cfg_targets:
                if t and t not in targets:
                    targets.append(t)

        valid_dirs = [os.path.abspath(d) for d in targets if d and os.path.isdir(d)]
        if not valid_dirs:
            return

        self.realtime_active = True
        self.rt_auto_quarantine = auto_quarantine
        self.watchers = []
        for d in valid_dirs:
            w = WindowsFolderWatcher(d, self.realtime_queue.put, self.is_excluded)
            w.start()
            self.watchers.append(w)
        self.watcher = self.watchers[0] if self.watchers else None
        self.log(f"[SHIELD ON] Guarding: {', '.join(valid_dirs)}", "shield")

    def stop_realtime(self):
        self.realtime_active = False
        for w in getattr(self, "watchers", []):
            try:
                w.stop()
            except Exception:
                pass
        self.watchers = []
        if self.watcher:
            self.watcher.stop()
            self.watcher = None
        self.log("[SHIELD OFF] Shield stopped.", "shield")

    def _realtime_worker(self):
        while True:
            filepath = self.realtime_queue.get()
            if not self.realtime_active or not filepath or not os.path.isfile(filepath) or self.is_excluded(filepath):
                continue
            time.sleep(0.6)
            if not os.path.isfile(filepath):
                continue
            if not self._has_valid_clamscan():
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
                self._increment_scanned(1)
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
