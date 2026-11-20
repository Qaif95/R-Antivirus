# 🛡️ R Antivirus

**R Antivirus** is a modern Windows desktop antivirus and security control panel built with **Python (PySide6)**, powered by the local **ClamAV** scanning engine and **VirusTotal** cloud SHA-256 hash verification.

<img width="511" height="400" alt="Ricon" src="https://github.com/user-attachments/assets/cd981ca5-203f-4d89-afd0-9e57f7600d34" />

---

## ✨ Key Features

* **Dual-Engine Malware Detection**
  * **Local ClamAV Scanning:** Recursive folder and single-file scanning with deep archive inspection, infected-only filtering, and configurable file/scan size limits.
  * **VirusTotal Cloud Verification:** Instant SHA-256 hash lookups against VirusTotal's v3 API without uploading private files automatically.
* **Real-Time Shield (Multi-Folder Watch)**
  * Monitors configured directories (such as `Downloads`) in real time using Windows file-system events and automatically isolates threats.
* **Advanced System Scanners**
  * **Full Disk Scan:** Automatically enumerates and scans all available local drives.
  * **Active Memory Process Scanner:** Inspects currently running executables in memory.
  * **Startup & Boot-Time Protection:** Scans Windows startup registry keys/folders and schedules pre-session boot scans.
* **Quarantine Vault & Exclusions**
  * Safely isolates detected threats as `.quarantine` files alongside a `manifest.json` metadata tracker.
  * Supports **Restore**, **Trust & Exclude**, **SHA-256 Copy**, **Item Details**, and **Permanent Delete**.
* **Security Audit Reports & Persistent Incident History**
  * Tracks scan statistics and threat events across sessions (`incidents_state.json`) and exports formatted **HTML** or **CSV** security reports.
* **Modern Desktop UI**
  * Frameless custom title bar, **Light / Dark** themes, **English / Arabic (RTL)** localization, real-time CPU/RAM/GPU telemetry, live security console, and system tray integration.

---

## 🏗️ Project Structure

```text
R-Antivirus/
├── R_antivirus.py          # Main application entry point & signal bridge
├── interface.py            # PySide6 GUI, themes, RTL support, and dialogs
├── clamavnet_engine.py     # Core scanning engine, quarantine, shield & VT client
├── boot_scanner.py         # Windows boot-time scan scheduler
├── about.py                # About page & project metadata
└── Resources/
    └── Ricon.png           # Application & system tray icon
```

---

## ⚙️ Prerequisites

1. **Operating System:** Windows 10 / 11 (Administrator privileges recommended for full system, memory, and boot-time scans).
2. **Python:** Python 3.10 or newer.
3. **ClamAV for Windows:**
   * Download and install ClamAV, and ensure `clamscan.exe` and `freshclam.exe` are accessible (either in `PATH`, `C:\Program Files\ClamAV`, or configured inside **Reports & Settings**).
   * Run `freshclam` at least once to download initial virus signature databases.
4. **Python Dependencies:**
   ```bash
   pip install PySide6 psutil
   ```

---

## 🚀 Getting Started

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Qaif95/R-Antivirus.git
   cd R-Antivirus
   ```

2. **Install required packages:**
   ```bash
   pip install PySide6 psutil
   ```

3. **Run R Antivirus (as Administrator):**
   ```bash
   python R_antivirus.py
   ```

4. **Configure Paths & API Key (Optional):**
   * Open **Reports & Settings** inside the app to verify your `clamscan` and `freshclam` paths, add your **VirusTotal API Key**, and adjust max file/scan size thresholds.

---

## ⚠️ Disclaimer

This project is provided for educational and personal security utility purposes. Always verify detections before deleting files permanently—use the **Quarantine Vault** and **Trust & Exclude** workflow if a legitimate application triggers a false positive.

---

## 👤 Author

* **Developer:** Shafe'
* **GitHub:** [@Qaif95](https://github.com/Qaif95)
