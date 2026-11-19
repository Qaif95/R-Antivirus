# C:\R Antivirus\data\Common\bridge.py
from PySide6.QtCore import QObject, Signal

class EngineBridge(QObject):
    log_signal = Signal(str, str)
    notify_signal = Signal(str, str, bool)
    threat_signal = Signal()
    progress_signal = Signal(int, int, int)
    popup_signal = Signal(str, str)
    scan_finished_signal = Signal(str)