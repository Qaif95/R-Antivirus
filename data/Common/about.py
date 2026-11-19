# about.py
from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton
import os

class AboutPage(QWidget):
    def __init__(self, icon_path):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(12)

        # الشعار
        if os.path.isfile(icon_path):
            logo = QLabel()
            logo.setPixmap(QPixmap(icon_path).scaled(120, 120, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            logo.setAlignment(Qt.AlignCenter)
            layout.addWidget(logo)

        # اسم التطبيق
        title = QLabel("R Antivirus")
        title.setObjectName("HeroStatus") # سيأخذ التنسيق من الـ QSS
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # الإصدار
        version = QLabel("Version 2.1.3 — Stable")
        version.setObjectName("MutedText")
        version.setAlignment(Qt.AlignCenter)
        layout.addWidget(version)

        # معلوماتك الشخصية (عدل هذه النصوص كما تحب)
        info_text = (
            "ClamAV engine + VirusTotal cloud verification\n"
            "Built by vibe coding :)\n\n"
            "Developer: Shafe AbuAqel\n"
            "Contact: your.email@example.com\n"
            "GitHub: github.com/Qaif95"
        )
        info = QLabel(info_text)
        info.setObjectName("BodyText")
        info.setAlignment(Qt.AlignCenter)
        layout.addWidget(info)

        # زر اختياري لفتح رابط
        btn_link = QPushButton("Visit GitHub")
        btn_link.setObjectName("ActionBtn")
        btn_link.setCursor(Qt.PointingHandCursor)
        # btn_link.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://github.com/yourusername")))
        layout.addWidget(btn_link, alignment=Qt.AlignCenter)