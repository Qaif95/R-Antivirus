# about.py
import os
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QPixmap, QDesktopServices
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QFrame


class AboutPage(QWidget):
    def __init__(self, icon_path="", version_text="v0.3.1 — Stable"):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setAlignment(Qt.AlignCenter)

        card = QFrame()
        card.setObjectName("SoftCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(12)

        if icon_path and os.path.isfile(icon_path):
            logo = QLabel()
            logo.setPixmap(
                QPixmap(icon_path).scaled(112, 112, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            )
            logo.setAlignment(Qt.AlignCenter)
            layout.addWidget(logo)
        else:
            fallback = QLabel("🛡️")
            fallback.setStyleSheet("font-size: 56px;")
            fallback.setAlignment(Qt.AlignCenter)
            layout.addWidget(fallback)

        title = QLabel("R Antivirus")
        title.setObjectName("HeroStatus")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        version = QLabel(version_text)
        version.setObjectName("MutedText")
        version.setAlignment(Qt.AlignCenter)
        layout.addWidget(version)

        info_text = (
            "ClamAV engine + VirusTotal cloud verification\n"
            "Built by vibe coding :)\n\n"
            "Developer: Shafe'\n"
            "GitHub: github.com/Qaif95"
        )
        info = QLabel(info_text)
        info.setObjectName("BodyText")
        info.setAlignment(Qt.AlignCenter)
        layout.addWidget(info)

        btn_link = QPushButton("Visit GitHub")
        btn_link.setObjectName("ActionBtn")
        btn_link.setCursor(Qt.PointingHandCursor)
        btn_link.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl("https://github.com/Qaif95"))
        )
        layout.addWidget(btn_link, alignment=Qt.AlignCenter)

        outer.addWidget(card)
