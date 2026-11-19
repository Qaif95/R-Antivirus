# 🛡️ R Antivirus

**A Python-based antivirus application built with PySide6, featuring ClamAV integration and VirusTotal connectivity.**

R Antivirus is a desktop antivirus project developed in Python. It aims to provide a graphical interface for malware scanning, threat monitoring, quarantine management, and security-related operations.

> 🚧 **Project Status: In Development**
>
> R Antivirus is an ongoing project. Features and functionality are still being developed and tested.

## ✨ Features

- **Graphical User Interface** — Desktop interface built with PySide6.
- **ClamAV Integration** — Local malware scanning through ClamAV.
- **VirusTotal Integration** — Connectivity for file reputation checks.
- **Scan Management** — Scan controls and progress monitoring.
- **Quarantine Management** — Quarantine-related file operations.
- **Scheduled Scanning** — Interface and configuration support for scan scheduling.
- **Reports** — Storage for scan reports.
- **Customizable Interface** — Theme and layout direction settings.
- **Boot Scanning** — Boot-scanning component under development.

*Feature availability and reliability may vary as development continues.*

## 🛠️ Built With

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| PySide6 | Graphical user interface |
| ClamAV | Local malware scanning |
| VirusTotal | File reputation checks |

## 📁 Project Structure

```text
R-Antivirus/
│
├── R_antivirus.py
│
└── data/
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
    ├── Reports/
    ├── Resources/
    │   ├── Ricon.png
    │   └── icons/
    │
    └── Restored/
```

## ⚙️ Installation

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

Install and configure ClamAV separately if you want to use its scanning functionality.

### 4. Run the application

On Windows:

```bash
python R_antivirus.py
```

The application may request administrator privileges for certain operations.

## 🔐 Security Notice

R Antivirus is an experimental security project and is not intended to replace established antivirus software.

- Do not rely on it as your only layer of protection.
- Test scanning and quarantine operations carefully.
- Do not scan or delete important files without backups.
- Keep ClamAV and its signature databases updated.
- VirusTotal functionality may require an API key and appropriate configuration.

## 🗺️ Roadmap

- [ ] Complete application structure migration.
- [ ] Fix and validate scheduled scanning.
- [ ] Improve scan engine stability.
- [ ] Improve quarantine and restore operations.
- [ ] Enhance error handling and logging.
- [ ] Add automated tests.
- [ ] Prepare a stable release.

## 🤝 Contributing

Contributions, bug reports, and suggestions are welcome.

If you find a bug or have an idea for improvement, feel free to open an Issue.

## 📜 License

No license has been specified yet.

A license will be added once the project owner chooses the terms under which the project can be used and distributed.

---

**R Antivirus** — Building a safer digital environment, one step at a time. 🛡️
