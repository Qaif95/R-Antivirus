# 🛡️ R Antivirus

### Lightweight Desktop Antivirus Application Built with Python

**R Antivirus** is a Windows desktop antivirus application developed using Python and PySide6. It combines local malware scanning through ClamAV with VirusTotal integration, providing tools for threat detection, quarantine management, scan reporting, and system security operations.

The project focuses on building a practical, user-friendly antivirus application with a modular architecture and an easy-to-use graphical interface.

<p align="center">
  <strong>Protect • Detect • Manage</strong>
</p>

---

## ✨ Features

### 🔍 Malware Scanning
- Local malware scanning powered by ClamAV.
- Support for scanning files and directories.
- Recursive scanning options.
- Archive scanning support.
- Scan progress monitoring.
- Ability to stop active scanning operations.

### 🌐 VirusTotal Integration
- Integration with the VirusTotal service.
- File reputation checking.
- Additional threat intelligence through online analysis.

### 🔒 Quarantine Management
- Quarantine management functionality.
- Restore quarantined files.
- Delete quarantined files.
- Manage detected threats.

### 📊 Scan Reports
- Scan report storage.
- CSV report support.
- Organized report directory.

### ⏰ Scheduled Scanning
- Scan scheduling interface.
- Configurable scan frequency.
- Custom scan targets.
- Schedule configuration storage.

### ⚙️ Customization
- Customizable application theme.
- Right-to-left (RTL) and left-to-right (LTR) interface support.
- Application settings management.

### 🖥️ System Operations
- Administrator privilege support.
- Boot-scanning component.
- Full-system scanning functionality.

---

## 🧪 Testing Status

The core functionality of R Antivirus has been tested on the developer's Windows machine.

Tested operations include:

- Local malware scanning.
- VirusTotal file reputation checks.
- Quarantine operations.
- File restoration.
- Scan reporting.
- Application interface and controls.

Testing and development are ongoing. Results may vary depending on the Windows environment, ClamAV configuration, permissions, and external service availability.

---

## 🛠️ Built With

| Technology | Purpose |
|---|---|
| Python | Core application development |
| PySide6 | Desktop graphical interface |
| ClamAV | Local malware detection |
| VirusTotal API | Online file reputation analysis |
| CSV | Scan report storage |

---

## 📁 Project Structure

```text
R-Antivirus/
│
├── R_antivirus.py
│
└── data/
    │
    ├── Common/
    │   ├── about.py
    │   └── bridge.py
    │
    ├── Interface/
    │   └── interface.py
    │
    ├── Operations/
    │   ├── boot_scanner.py
    │   └── clamavnet_engine.py
    │
    ├── Quarantine/
    │
    ├── Reports/
    │
    ├── Resources/
    │   ├── Ricon.png
    │   └── icons/
    │
    └── Restored/
```

---

## ⚙️ Requirements

- Windows 10 or Windows 11.
- Python 3.10 or newer.
- PySide6.
- ClamAV installed and configured.
- Internet connection for VirusTotal functionality.
- VirusTotal API key, if required by your configuration.

---

## 📥 Installation

### 1. Clone the repository

```bash
git clone https://github.com/Qaif95/R-Antivirus.git
```

### 2. Navigate to the project directory

```bash
cd R-Antivirus
```

### 3. Install Python dependencies

```bash
pip install PySide6
```

Install any additional dependencies required by the application.

### 4. Configure ClamAV

Install ClamAV and configure its executable paths and signature database.

Make sure the ClamAV scanning engine and its definitions are available before using local scanning features.

### 5. Configure VirusTotal

Configure your VirusTotal API key if the online reputation functionality requires one.

**Important:** Never publish API keys, passwords, or other private credentials in your GitHub repository.

### 6. Run R Antivirus

```bash
python R_antivirus.py
```

The application may request administrator privileges for certain system operations.

---

## 🖼️ Screenshots

Screenshots of the application will be added here.

<!-- Add your application screenshots below.

![R Antivirus Main Interface](screenshots/main-interface.png)

![R Antivirus Scanning](screenshots/scanning.png)

![R Antivirus Quarantine](screenshots/quarantine.png)

-->

---

## 🗺️ Development Roadmap

- [x] Initial desktop application.
- [x] PySide6 graphical interface.
- [x] ClamAV integration.
- [x] VirusTotal integration.
- [x] Quarantine management.
- [x] Scan reporting.
- [x] Theme customization.
- [x] RTL/LTR interface support.
- [ ] Complete and validate the new modular project structure.
- [ ] Improve scheduled scanning reliability.
- [ ] Expand automated testing.
- [ ] Improve error handling and logging.
- [ ] Optimize scanning performance.
- [ ] Prepare a stable public release.

---

## 🔐 Security Notice

R Antivirus is an independent software development project.

Although its core features have been tested on the developer's machine, it has not been independently audited or certified as a commercial antivirus solution.

Please keep the following points in mind:

- Do not use R Antivirus as your only layer of system protection.
- Keep ClamAV and its malware definitions updated.
- Be careful when quarantining or deleting files.
- Maintain backups of important data.
- Use caution when testing malware samples.
- Protect your VirusTotal API credentials.
- Do not assume that any antivirus engine can detect every threat.

R Antivirus is not affiliated with or officially endorsed by ClamAV or VirusTotal.

---

## 🤝 Contributing

Contributions, suggestions, and bug reports are welcome.

If you encounter an issue or have an idea for improving R Antivirus:

1. Open the repository's Issues section.
2. Describe the problem or suggestion.
3. Include relevant error messages and system information.
4. Submit a pull request if you would like to contribute code.

---

## 📜 License

No open-source license has been selected for this project yet.

Until a license is added, the project remains subject to the default copyright rules. Please do not assume that public availability means permission to reuse, modify, or redistribute the code.

---

## 👨‍💻 Developer

**Qaif95**

GitHub: [@Qaif95](https://github.com/Qaif95)

Project: [R Antivirus](https://github.com/Qaif95/R-Antivirus)

---

<p align="center">
  <strong>R Antivirus</strong>
  <br>
  Building a safer digital environment, one step at a time. 🛡️
</p>
