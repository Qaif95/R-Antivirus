import os
import json
import time
from datetime import datetime

try:
    import shiboken6
except ImportError:
    import shiboken

from PySide6.QtCore import Qt, QTimer, Signal, QPoint, QEvent
from PySide6.QtGui import (
    QIcon, QPixmap, QAction, QPainter, QLinearGradient,
    QColor, QPen, QPainterPath
)
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QStackedWidget, QFrame, QLineEdit, QCheckBox,
    QRadioButton, QButtonGroup, QProgressBar, QTextEdit, QListWidget,
    QListWidgetItem, QComboBox, QFileDialog, QSystemTrayIcon, QMenu,
    QScrollArea, QDialog, QStatusBar, QToolButton, QApplication
)

try:
    from about import AboutPage
except ImportError:
    AboutPage = None

# ═══════════════════════════════════════════════════════════════════════
#  TRANSLATIONS
# ═══════════════════════════════════════════════════════════════════════
TRANS = {
    "en": {
        "nav": ["Overview", "Scan Options", "Startup & Boot", "Memory & Schedule", "Exclusions", "Quarantine", "Reports & Settings", "About"],
        "theme_dark": "🌙  Dark Mode", "theme_light": "☀️  Light Mode",
        "lang_ar": "🌐  العربية", "lang_en": "🌐  English",
        "min_tray": "🗕  Minimize to Tray", "exit": "⏻  Exit R Antivirus",
        "protected": "You're Protected", "protected_sub": "ClamAV local engine & VirusTotal hash verification ready",
        "alert_state": "Attention Needed", "alert_sub": "Threats were detected — review Quarantine or run a scan",
        "scan_now": "Scan Now", "update_defs": "🔄 Update Definitions", "full_disk": "🌍 Full Disk Scan", "view_quar": "📦 View Quarantine",
        "qc_shield_title": "Real-Time Shield", "qc_defs_title": "Virus Definitions", "qc_quar_title": "Quarantine Vault",
        "clam_local": "ClamAV Local (Folder / File)", "vt_cloud": "VirusTotal Cloud (Single File SHA-256)",
        "drop_here": "Drop a file/folder here, or use the buttons →", "folder_btn": "Folder...", "file_btn": "File...",
        "recursive": "Recursive", "infected_only": "Infected Only", "deep_arch": "Deep Archives", "auto_quar": "Auto-Quarantine",
        "run_scan": "🚀 Run Selected Scan", "stop": "⏹️ Stop",
        "win_startup": "<b>Windows Startup Programs Scan</b>", "auto_quar_startup": "Auto-quarantine malicious startup items",
        "scan_startup": "🚀 Scan Startup Items", "boot_task": "<b>Boot-Time Scan Task (Startup / Pre-Session)</b>",
        "status_unknown": "Status: Unknown", "status_sched": "Status: Scheduled on System Startup", "status_not_sched": "Status: Not Scheduled",
        "sched_boot": "💻 Schedule Boot Scan", "dis_boot": "🛑 Disable Boot Scan",
        "mem_scan": "<b>Active Memory Process Scanner</b>", "auto_quar_mem": "Auto-quarantine malicious active executables",
        "scan_mem": "🧠 Scan Running Processes", "frequency": "Frequency:", "time_hhmm": "Time (HH:MM):", "target_folder": "Target Folder:", "save_sched": "💾 Save Schedule",
        "whitelisted": "<b>Whitelisted Folders & Files</b>", "search_excl": "Search exclusions...", "no_excl": "No exclusions yet",
        "excl_folder": "➕ Exclude Folder", "excl_file": "➕ Exclude File", "rem_selected": "➖ Remove Selected",
        "quar_vault": "<b>Quarantine Vault</b>", "search_quar": "Search quarantined files...", "quar_empty": "Quarantine is empty",
        "refresh": "🔄 Refresh", "restore": "♻️ Restore", "trust_exclude": "🛡️ Trust & Exclude", "sha256": "🔑 SHA-256", "details": "ℹ️ Details", "delete": "🗑️ Delete",
        "recent_incidents": "📋 Recent Incidents",
        "export_html": "📄 Export HTML Report", "export_csv": "📊 Export CSV Report", "export_set": "⬇️ Export Settings", "import_set": "⬆️ Import Settings",
        "clam_path": "clamscan Path:", "fresh_path": "freshclam Path:", "vt_key": "VirusTotal API Key:",
        "max_fs": "Max File Size:", "max_ss": "Max Scan Size:", "enable_sounds": "Enable notification sounds", "save_set": "💾 Save Settings",
        "rt_shield": "Real-Time Shield", "shield_off": "OFF", "shield_on": "ON (Active)",
        "enable_shield": "Enable Shield", "disable_shield": "Disable Shield", "boot_checking": "Boot Scan: Checking...",
        "boot_sched": "Boot Scan: SCHEDULED", "boot_disabled": "Boot Scan: Disabled",
        "sys_telemetry": "System Telemetry", "scanned_files": "Scanned Files:", "threats_blocked": "Threats Blocked:", "defs": "Definitions:",
        "live_console": "Live Security Console", "clear_log": "Clear Log", "toggle_log": "Show / Hide Log",
        "engine_ready": "🟢 Engine Ready", "shield_active": "🟢 Shield Active", "shield_off_stat": "🟡 Shield Off",
        "enable_sched": "Enable Scheduled Scan", "cancel": "Cancel", "confirm": "Confirm",
        "exit_title": "Exit R Antivirus?", "exit_msg": "Are you sure you want to exit?", "exit_ok": "Exit",
        "del_quar_title": "Delete Quarantined File?", "del_quar_ok": "Delete",
        "del_quar_msg": "Permanently delete '{name}' from Quarantine? This cannot be undone."
    },
    "ar": {
        "nav": ["نظرة عامة", "خيارات الفحص", "بدء التشغيل", "الذاكرة والجدولة", "الاستثناءات", "الحجر الصحي", "التقارير والإعدادات", "حول"],
        "theme_dark": "🌙  الوضع الداكن", "theme_light": "☀️  الوضع الفاتح",
        "lang_ar": "🌐  العربية", "lang_en": "🌐  English",
        "min_tray": "🗕  تصغير إلى شريط المهام", "exit": "⏻  خروج من R Antivirus",
        "protected": "أنت محمي", "protected_sub": "محرك ClamAV المحلي والتحقق من VirusTotal جاهز",
        "alert_state": "يحتاج انتباه", "alert_sub": "تم رصد تهديدات — راجع الحجر الصحي أو نفّذ فحصاً",
        "scan_now": "افحص الآن", "update_defs": "🔄 تحديث التعريفات", "full_disk": "🌍 فحص كامل للقرص", "view_quar": "📦 عرض الحجر الصحي",
        "qc_shield_title": "الدرع اللحظي", "qc_defs_title": "تعريفات الفيروسات", "qc_quar_title": "خزنة الحجر الصحي",
        "clam_local": "ClamAV المحلي (مجلد / ملف)", "vt_cloud": "VirusTotal السحابي (ملف واحد SHA-256)",
        "drop_here": "أفلت ملفاً/مجلداً هنا، أو استخدم الأزرار ←", "folder_btn": "مجلد...", "file_btn": "ملف...",
        "recursive": "شامل (Recursive)", "infected_only": "المصاب فقط", "deep_arch": "أرشيف عميق", "auto_quar": "حجر تلقائي",
        "run_scan": "🚀 بدء الفحص المحدد", "stop": "⏹️ إيقاف",
        "win_startup": "<b>فحص برامج بدء تشغيل ويندوز</b>", "auto_quar_startup": "حجر تلقائي لعناصر بدء التشغيل الخبيثة",
        "scan_startup": "🚀 فحص عناصر بدء التشغيل", "boot_task": "<b>مهمة الفحص عند الإقلاع (قبل الجلسة)</b>",
        "status_unknown": "الحالة: غير معروف", "status_sched": "الحالة: مجدول عند بدء تشغيل النظام", "status_not_sched": "الحالة: غير مجدول",
        "sched_boot": "💻 جدولة فحص الإقلاع", "dis_boot": "🛑 تعطيل فحص الإقلاع",
        "mem_scan": "<b>فاحص العمليات النشطة في الذاكرة</b>", "auto_quar_mem": "حجر تلقائي للملفات التنفيذية النشطة الخبيثة",
        "scan_mem": "🧠 فحص العمليات قيد التشغيل", "frequency": "التكرار:", "time_hhmm": "الوقت (HH:MM):", "target_folder": "المجلد المستهدف:", "save_sched": "💾 حفظ الجدولة",
        "whitelisted": "<b>المجلدات والملفات المستثناة</b>", "search_excl": "ابحث في الاستثناءات...", "no_excl": "لا توجد استثناءات بعد",
        "excl_folder": "➕ استبعاد مجلد", "excl_file": "➕ استبعاد ملف", "rem_selected": "➖ إزالة المحدد",
        "quar_vault": "<b>خزنة الحجر الصحي</b>", "search_quar": "ابحث في الملفات المحجورة...", "quar_empty": "الحجر الصحي فارغ",
        "refresh": "🔄 تحديث", "restore": "♻️ استعادة", "trust_exclude": "🛡️ وثوق واستثناء", "sha256": "🔑 SHA-256", "details": "ℹ️ التفاصيل", "delete": "🗑️ حذف",
        "recent_incidents": "📋 سجل الحوادث الأخيرة",
        "export_html": "📄 تصدير تقرير HTML", "export_csv": "📊 تصدير تقرير CSV", "export_set": "⬇️ تصدير الإعدادات", "import_set": "⬆️ استيراد الإعدادات",
        "clam_path": "مسار clamscan:", "fresh_path": "مسار freshclam:", "vt_key": "مفتاح VirusTotal API:",
        "max_fs": "أقصى حجم للملف:", "max_ss": "أقصى حجم للفحص:", "enable_sounds": "تفعيل أصوات الإشعارات", "save_set": "💾 حفظ الإعدادات",
        "rt_shield": "الدرع اللحظي", "shield_off": "مغلق", "shield_on": "مفتوح (نشط)",
        "enable_shield": "تفعيل الدرع", "disable_shield": "تعطيل الدرع", "boot_checking": "فحص الإقلاع: جاري التحقق...",
        "boot_sched": "فحص الإقلاع: مجدول", "boot_disabled": "فحص الإقلاع: معطل",
        "sys_telemetry": "قياسات النظام", "scanned_files": "الملفات المفحوصة:", "threats_blocked": "التهديدات المحجوبة:", "defs": "التعريفات:",
        "live_console": "سجل الأمان المباشر", "clear_log": "مسح السجل", "toggle_log": "إظهار / إخفاء السجل",
        "engine_ready": "🟢 المحرك جاهز", "shield_active": "🟢 الدرع نشط", "shield_off_stat": "🟡 الدرع مغلق",
        "enable_sched": "تفعيل الفحص المجدول", "cancel": "إلغاء", "confirm": "تأكيد",
        "exit_title": "الخروج من R Antivirus؟", "exit_msg": "هل أنت متأكد أنك تريد الخروج؟", "exit_ok": "خروج",
        "del_quar_title": "حذف الملف المحجور؟", "del_quar_ok": "حذف نهائي",
        "del_quar_msg": "هل تريد حذف الملف '{name}' نهائياً من الحجر الصحي؟ لا يمكن التراجع عن هذا الإجراء."
    }
}

# ═══════════════════════════════════════════════════════════════════════
#  THEME QSS (FLAT SHARP WINDOW EDGES — NO OUTER CURVES)
# ═══════════════════════════════════════════════════════════════════════
LIGHT_QSS = """
QMainWindow { background-color: #ffffff; }
QWidget#RootContainer { background-color: #ffffff; }
QFrame#WindowShell {
    background-color: #ffffff;
    border-radius: 0px;
    border: 1px solid #e6dbf7;
}
QFrame#CustomTitleBar {
    background-color: #faf7ff;
    border-radius: 0px;
    border-bottom: 1px solid #ece4f8;
}
QLabel { color: #2c1646; }
QLabel#TitleBarText { font-size: 13px; font-weight: 700; }
QLabel#TitleBarSub  { color: #77688d; font-size: 10px; }
QLabel#HeaderBadge {
    background-color: #f2e6ff;
    color: #6a1b9a;
    border: 1px solid #dec7fa;
    border-radius: 10px;
    padding: 3px 9px;
    font-size: 10px;
    font-weight: 700;
}
QPushButton#TitleBtn { background: transparent; border: none; border-radius: 0px; color: #46355e; font-size: 13px; font-weight: 700; padding: 0px; }
QPushButton#TitleBtn:hover { background-color: #efe5fc; color: #6a1b9a; }
QPushButton#TitleBtnClose { background: transparent; border: none; border-radius: 0px; color: #46355e; font-size: 13px; font-weight: 700; padding: 0px; }
QPushButton#TitleBtnClose:hover { background-color: #e81123; color: #ffffff; }
QFrame#LeftSidebar {
    background-color: #faf7ff;
    border-right: 1px solid #ece4f8;
    border-radius: 0px;
}
QFrame#RightPanel {
    background-color: #fbf9fe;
    border-left: 1px solid #ece4f8;
    border-radius: 0px;
}
QFrame#SoftCard {
    background-color: #ffffff;
    border: 1px solid #ede6f7;
    border-radius: 16px;
}
QFrame#QuickStatCard {
    background-color: #faf6ff;
    border: 1px solid #e7daf9;
    border-radius: 15px;
}
QFrame#QuickStatCard:hover {
    background-color: #f3e8ff;
    border: 1px solid #cfaef7;
}
QFrame#ShieldHeroCard {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #fbf6ff, stop:1 #f1e6ff);
    border: 1px solid #e2d1fa;
    border-radius: 20px;
}
QLabel#BrandTitle { font-size: 21px; font-weight: 800; }
QLabel#BrandSub { color: #77688d; font-size: 11px; }
QLabel#HeroStatus { font-size: 22px; font-weight: 800; }
QLabel#HeroSub { color: #6b5c82; font-size: 12px; }
QLabel#SectionTitle { font-size: 13px; font-weight: 700; }
QLabel#BodyText { font-size: 12px; }
QLabel#MutedText { color: #77688d; font-size: 11px; }
QLabel#SuccessText { color: #2e7d32; font-size: 11px; font-weight: 700; }
QLabel#DangerText { color: #c62828; font-size: 11px; font-weight: 700; }
QPushButton#NavBtn {
    text-align: left;
    padding: 10px 14px;
    border-radius: 12px;
    border: none;
    background-color: transparent;
    color: #46355e;
    font-size: 13px;
    font-weight: 600;
}
QPushButton#NavBtn:hover { background-color: #efe5fc; color: #6a1b9a; }
QPushButton#NavBtn[active="true"] {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #a42cf0,stop:1 #6a1b9a);
    color: #ffffff;
    font-weight: 700;
}
QPushButton#PrimaryScanBtn {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #b938ff,stop:1 #7b1fa2);
    color: #ffffff;
    border: none;
    border-radius: 20px;
    padding: 12px 36px;
    font-size: 15px;
    font-weight: 700;
}
QPushButton#PrimaryScanBtn:hover {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #c64fff,stop:1 #8e24aa);
}
QPushButton#ActionBtn {
    background-color: #f3e8ff;
    color: #5b1885;
    border: 1px solid #dec7fa;
    border-radius: 11px;
    padding: 8px 14px;
    font-size: 12px;
    font-weight: 600;
}
QPushButton#ActionBtn:hover { background-color: #e6d2ff; }
QPushButton#DangerBtn {
    background-color: #ffebee;
    color: #b71c1c;
    border: 1px solid #ffcdd2;
    border-radius: 11px;
    padding: 8px 14px;
    font-size: 12px;
    font-weight: 600;
}
QPushButton#DangerBtn:hover { background-color: #ffcdd2; }
QLineEdit, QComboBox {
    background-color: #ffffff;
    border: 1px solid #dfd3f2;
    border-radius: 10px;
    padding: 7px 10px;
    color: #2c1646;
    font-size: 12px;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid #9c27b0; }
QProgressBar {
    background-color: #ede4fa;
    border: none;
    border-radius: 7px;
    height: 12px;
    text-align: center;
    color: #2c1646;
    font-size: 10px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #b33df7,stop:1 #6a1b9a);
    border-radius: 7px;
}
QTextEdit#ConsoleBox {
    background-color: #181322;
    color: #e8e2f3;
    border-radius: 12px;
    padding: 8px;
    font-family: Consolas, monospace;
    font-size: 11px;
}
QListWidget {
    background-color: #faf7ff;
    border: 1px solid #e7dcf7;
    border-radius: 12px;
    padding: 6px;
    color: #2c1646;
    font-family: Consolas, monospace;
    font-size: 12px;
}
QListWidget::item { padding: 5px 8px; border-radius: 8px; }
QListWidget::item:selected { background-color: #e6d2ff; color: #4a148c; }
QScrollArea { border: none; background: transparent; }
QCheckBox, QRadioButton { color: #46355e; font-size: 12px; }
QCheckBox::indicator, QRadioButton::indicator { width: 16px; height: 16px; background-color: #ffffff; border: 1px solid #c4b5dc; border-radius: 4px; }
QCheckBox::indicator:checked, QRadioButton::indicator:checked { background-color: #7b1fa2; border: 1px solid #7b1fa2; }
QStatusBar {
    background-color: #faf7ff;
    color: #5e4b78;
    font-size: 11px;
    border-top: 1px solid #ece4f8;
    border-radius: 0px;
}
QStatusBar::item { border: none; }
QToolTip { background-color: #2c1646; color: #ffffff; padding: 5px 9px; border-radius: 6px; font-size: 11px; }
QMenu { background-color: #ffffff; border: 1px solid #e7dcf7; border-radius: 10px; padding: 4px; }
QMenu::item { padding: 6px 18px 6px 12px; border-radius: 6px; color: #2c1646; font-size: 12px; }
QMenu::item:selected { background-color: #efe5fc; color: #6a1b9a; }
QDialog { background-color: #fbf9fe; }
"""

DARK_QSS = """
QMainWindow { background-color: #1e1630; }
QWidget#RootContainer { background-color: #1e1630; }
QFrame#WindowShell {
    background-color: #1e1630;
    border-radius: 0px;
    border: 1px solid #352554;
}
QFrame#CustomTitleBar {
    background-color: #1c1430;
    border-radius: 0px;
    border-bottom: 1px solid #2e2247;
}
QLabel { color: #e9d8ff; }
QLabel#TitleBarText { font-size: 13px; font-weight: 700; }
QLabel#TitleBarSub  { color: #a58ec9; font-size: 10px; }
QLabel#HeaderBadge {
    background-color: #31214f;
    color: #e9d8ff;
    border: 1px solid #4c3578;
    border-radius: 10px;
    padding: 3px 9px;
    font-size: 10px;
    font-weight: 700;
}
QPushButton#TitleBtn { background: transparent; border: none; border-radius: 0px; color: #c9b8e6; font-size: 13px; font-weight: 700; padding: 0px; }
QPushButton#TitleBtn:hover { background-color: #2e2247; color: #ffffff; }
QPushButton#TitleBtnClose { background: transparent; border: none; border-radius: 0px; color: #c9b8e6; font-size: 13px; font-weight: 700; padding: 0px; }
QPushButton#TitleBtnClose:hover { background-color: #e81123; color: #ffffff; }
QFrame#LeftSidebar {
    background-color: #1c1430;
    border-right: 1px solid #2e2247;
    border-radius: 0px;
}
QFrame#RightPanel {
    background-color: #1a1330;
    border-left: 1px solid #2e2247;
    border-radius: 0px;
}
QFrame#SoftCard {
    background-color: #241a3d;
    border: 1px solid #33254f;
    border-radius: 16px;
}
QFrame#QuickStatCard {
    background-color: #281c45;
    border: 1px solid #3b2a5c;
    border-radius: 15px;
}
QFrame#QuickStatCard:hover {
    background-color: #322357;
    border: 1px solid #593f8a;
}
QFrame#ShieldHeroCard {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #2a1c47, stop:1 #1e1435);
    border: 1px solid #452d70;
    border-radius: 20px;
}
QLabel#BrandTitle { font-size: 21px; font-weight: 800; }
QLabel#BrandSub { color: #a58ec9; font-size: 11px; }
QLabel#HeroStatus { font-size: 22px; font-weight: 800; }
QLabel#HeroSub { color: #b9a4d8; font-size: 12px; }
QLabel#SectionTitle { font-size: 13px; font-weight: 700; }
QLabel#BodyText { font-size: 12px; }
QLabel#MutedText { color: #9a86bf; font-size: 11px; }
QLabel#SuccessText { color: #69f0ae; font-size: 11px; font-weight: 700; }
QLabel#DangerText { color: #ff6b6b; font-size: 11px; font-weight: 700; }
QPushButton#NavBtn {
    text-align: left;
    padding: 10px 14px;
    border-radius: 12px;
    border: none;
    background-color: transparent;
    color: #c9b8e6;
    font-size: 13px;
    font-weight: 600;
}
QPushButton#NavBtn:hover { background-color: #2e2247; color: #ffffff; }
QPushButton#NavBtn[active="true"] {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #a42cf0,stop:1 #6a1b9a);
    color: #ffffff;
    font-weight: 700;
}
QPushButton#PrimaryScanBtn {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #b938ff,stop:1 #7b1fa2);
    color: #ffffff;
    border: none;
    border-radius: 20px;
    padding: 12px 36px;
    font-size: 15px;
    font-weight: 700;
}
QPushButton#PrimaryScanBtn:hover {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #c64fff,stop:1 #8e24aa);
}
QPushButton#ActionBtn {
    background-color: #33254f;
    color: #e9d8ff;
    border: 1px solid #4a3568;
    border-radius: 11px;
    padding: 8px 14px;
    font-size: 12px;
    font-weight: 600;
}
QPushButton#ActionBtn:hover { background-color: #40305f; }
QPushButton#DangerBtn {
    background-color: #4a1f28;
    color: #ff8a95;
    border: 1px solid #6d2a35;
    border-radius: 11px;
    padding: 8px 14px;
    font-size: 12px;
    font-weight: 600;
}
QPushButton#DangerBtn:hover { background-color: #6d2a35; }
QLineEdit, QComboBox {
    background-color: #1c1430;
    border: 1px solid #3a2a55;
    border-radius: 10px;
    padding: 7px 10px;
    color: #e9d8ff;
    font-size: 12px;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid #b535f6; }
QProgressBar {
    background-color: #2a1e40;
    border: none;
    border-radius: 7px;
    height: 12px;
    text-align: center;
    color: #e9d8ff;
    font-size: 10px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #b938ff,stop:1 #7b1fa2);
    border-radius: 7px;
}
QTextEdit#ConsoleBox {
    background-color: #0e0a18;
    color: #d8c8f0;
    border-radius: 12px;
    padding: 8px;
    font-family: Consolas, monospace;
    font-size: 11px;
}
QListWidget {
    background-color: #1c1430;
    border: 1px solid #33254f;
    border-radius: 12px;
    padding: 6px;
    color: #d8c8f0;
    font-family: Consolas, monospace;
    font-size: 12px;
}
QListWidget::item { padding: 5px 8px; border-radius: 8px; }
QListWidget::item:selected { background-color: #40305f; color: #ffffff; }
QScrollArea { border: none; background: transparent; }
QCheckBox, QRadioButton { color: #c9b8e6; font-size: 12px; }
QCheckBox::indicator, QRadioButton::indicator { width: 16px; height: 16px; background-color: #1c1430; border: 1px solid #4a3568; border-radius: 4px; }
QCheckBox::indicator:checked, QRadioButton::indicator:checked { background-color: #b535f6; border: 1px solid #b535f6; }
QStatusBar {
    background-color: #1a1330;
    color: #b9a4d8;
    font-size: 11px;
    border-top: 1px solid #2e2247;
    border-radius: 0px;
}
QStatusBar::item { border: none; }
QToolTip { background-color: #e9d8ff; color: #1a1025; padding: 5px 9px; border-radius: 6px; font-size: 11px; }
QMenu { background-color: #241a3d; border: 1px solid #33254f; border-radius: 10px; padding: 4px; }
QMenu::item { padding: 6px 18px 6px 12px; border-radius: 6px; color: #e9d8ff; font-size: 12px; }
QMenu::item:selected { background-color: #40305f; color: #ffffff; }
QDialog { background-color: #1a1330; }
QWidget#ScrollInner { background-color: #1e1630; }
"""

# ═══════════════════════════════════════════════════════════════════════
#  CUSTOM WIDGETS
# ═══════════════════════════════════════════════════════════════════════

def build_shield_tray_icon(icon_path: str = "", alert: bool = False) -> QIcon:
    """Render a shield backing behind the app icon so it stands out in the Windows tray."""
    size = 64
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)

    painter = QPainter(pm)
    painter.setRenderHint(QPainter.Antialiasing)

    w, h = float(size), float(size)
    cx = w * 0.5

    shield = QPainterPath()
    shield.moveTo(cx, h * 0.05)
    shield.cubicTo(w * 0.90, h * 0.12, w * 0.92, h * 0.24, w * 0.85, h * 0.56)
    shield.cubicTo(w * 0.78, h * 0.82, cx, h * 0.96, cx, h * 0.96)
    shield.cubicTo(cx, h * 0.96, w * 0.22, h * 0.82, w * 0.15, h * 0.56)
    shield.cubicTo(w * 0.08, h * 0.24, w * 0.10, h * 0.12, cx, h * 0.05)
    shield.closeSubpath()

    grad = QLinearGradient(0, 0, w, h)
    if alert:
        grad.setColorAt(0.0, QColor("#ff6b81"))
        grad.setColorAt(1.0, QColor("#b71c1c"))
    else:
        grad.setColorAt(0.0, QColor("#d972ff"))
        grad.setColorAt(0.55, QColor("#7b1fa2"))
        grad.setColorAt(1.0, QColor("#3a1c71"))

    painter.setPen(QPen(QColor("#ffffff"), 2.4))
    painter.setBrush(grad)
    painter.drawPath(shield)

    if icon_path and os.path.isfile(icon_path):
        fg = QPixmap(icon_path).scaled(36, 36, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        painter.drawPixmap(int((size - fg.width()) / 2), int((size - fg.height()) / 2) + 1, fg)
    else:
        painter.setPen(QColor("#ffffff"))
        painter.drawText(pm.rect(), Qt.AlignCenter, "R")

    painter.end()
    return QIcon(pm)


class ShieldBadgeWidget(QWidget):
    """Custom painted shield with soft drop shadow and status indicator."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._alert = False
        self.setFixedSize(120, 132)

    def set_alert(self, is_alert: bool):
        if self._alert != is_alert:
            self._alert = is_alert
            self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w, h = float(self.width()), float(self.height())
        cx = w * 0.5

        shadow_path = QPainterPath()
        shadow_path.moveTo(cx, h * 0.12)
        shadow_path.cubicTo(w * 0.87, h * 0.18, w * 0.89, h * 0.28, w * 0.83, h * 0.60)
        shadow_path.cubicTo(w * 0.77, h * 0.84, cx, h * 0.98, cx, h * 0.98)
        shadow_path.cubicTo(cx, h * 0.98, w * 0.23, h * 0.84, w * 0.17, h * 0.60)
        shadow_path.cubicTo(w * 0.11, h * 0.28, w * 0.13, h * 0.18, cx, h * 0.12)
        shadow_path.closeSubpath()
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(90, 35, 160, 45))
        painter.drawPath(shadow_path)

        shield_path = QPainterPath()
        shield_path.moveTo(cx, h * 0.08)
        shield_path.cubicTo(w * 0.86, h * 0.14, w * 0.88, h * 0.24, w * 0.82, h * 0.56)
        shield_path.cubicTo(w * 0.76, h * 0.80, cx, h * 0.94, cx, h * 0.94)
        shield_path.cubicTo(cx, h * 0.94, w * 0.24, h * 0.80, w * 0.18, h * 0.56)
        shield_path.cubicTo(w * 0.12, h * 0.24, w * 0.14, h * 0.14, cx, h * 0.08)
        shield_path.closeSubpath()

        grad = QLinearGradient(0, h * 0.08, w, h * 0.94)
        if self._alert:
            grad.setColorAt(0.0, QColor("#ff758f"))
            grad.setColorAt(0.55, QColor("#e53935"))
            grad.setColorAt(1.0, QColor("#8e0000"))
        else:
            grad.setColorAt(0.0, QColor("#d972ff"))
            grad.setColorAt(0.52, QColor("#8e2de2"))
            grad.setColorAt(1.0, QColor("#4a00e0"))

        painter.setPen(QPen(QColor("#ffffff"), 2.2))
        painter.setBrush(grad)
        painter.drawPath(shield_path)

        pen = QPen(QColor("#69f0ae") if not self._alert else QColor("#fff176"), 6.0, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
        painter.setPen(pen)
        if not self._alert:
            check_path = QPainterPath()
            check_path.moveTo(w * 0.35, h * 0.52)
            check_path.lineTo(w * 0.47, h * 0.65)
            check_path.lineTo(w * 0.68, h * 0.39)
            painter.drawPath(check_path)
        else:
            painter.drawLine(QPoint(int(w * 0.50), int(h * 0.34)), QPoint(int(w * 0.50), int(h * 0.58)))
            painter.drawPoint(QPoint(int(w * 0.50), int(h * 0.70)))


class QuickStatCard(QFrame):
    clicked = Signal()

    def __init__(self, title, subtitle, icon_text="⚡"):
        super().__init__()
        self.setObjectName("QuickStatCard")
        self.setCursor(Qt.PointingHandCursor)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(4)

        top = QHBoxLayout()
        ico = QLabel(icon_text)
        ico.setStyleSheet("font-size: 16px;")
        self.lbl_title = QLabel(title)
        self.lbl_title.setObjectName("SectionTitle")
        top.addWidget(ico)
        top.addWidget(self.lbl_title, 1)

        self.lbl_sub = QLabel(subtitle)
        self.lbl_sub.setObjectName("MutedText")
        self.lbl_sub.setWordWrap(True)

        lay.addLayout(top)
        lay.addWidget(self.lbl_sub)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class CustomTitleBar(QFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self._parent = parent
        self._drag_pos = None
        self.setObjectName("CustomTitleBar")
        self.setFixedHeight(46)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 0, 10, 0)
        lay.setSpacing(10)

        logo = QLabel()
        if hasattr(parent, 'icon_path') and os.path.isfile(parent.icon_path):
            logo.setPixmap(QPixmap(parent.icon_path).scaled(26, 26, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            logo.setText("🦋")
            logo.setStyleSheet("font-size: 18px;")
        lay.addWidget(logo)

        title_col = QVBoxLayout()
        title_col.setSpacing(0)
        title_col.setContentsMargins(0, 0, 0, 0)
        t1 = QLabel("R Antivirus")
        t1.setObjectName("TitleBarText")
        t2 = QLabel("Administrator Mode")
        t2.setObjectName("TitleBarSub")
        title_col.addWidget(t1)
        title_col.addWidget(t2)
        lay.addLayout(title_col)

        badge = QLabel("ClamAV + VT")
        badge.setObjectName("HeaderBadge")
        lay.addWidget(badge)
        lay.addStretch()

        self.btn_min = QPushButton("—")
        self.btn_min.setObjectName("TitleBtn")
        self.btn_min.setFixedSize(36, 28)
        self.btn_min.clicked.connect(self._parent.showMinimized)
        self.btn_max = QPushButton("☐")
        self.btn_max.setObjectName("TitleBtn")
        self.btn_max.setFixedSize(36, 28)
        self.btn_max.clicked.connect(self._toggle_max)
        self.btn_close = QPushButton("✕")
        self.btn_close.setObjectName("TitleBtnClose")
        self.btn_close.setFixedSize(36, 28)
        self.btn_close.clicked.connect(self._parent._confirm_quit)
        lay.addWidget(self.btn_min)
        lay.addWidget(self.btn_max)
        lay.addWidget(self.btn_close)

    def sync_max_icon(self, is_max: bool):
        self.btn_max.setText("❐" if is_max else "☐")

    def _toggle_max(self):
        if self._parent.isMaximized():
            self._parent.showNormal()
        else:
            self._parent.showMaximized()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self._parent.frameGeometry().topLeft()

    def mouseMoveEvent(self, event):
        if self._drag_pos is not None and event.buttons() & Qt.LeftButton:
            if self._parent.isMaximized():
                self._parent.showNormal()
                self._drag_pos = QPoint(self._parent.width() // 2, self.height() // 2)
            self._parent.move(event.globalPosition().toPoint() - self._drag_pos)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton and self._drag_pos is not None:
            pos = event.globalPosition().toPoint()
            screen = QApplication.screenAt(pos)
            if screen:
                geo = screen.availableGeometry()
                if pos.y() <= geo.top() + 6:
                    self._parent.showMaximized()
            self._drag_pos = None

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._toggle_max()


class Toast(QFrame):
    """Centered notification bubble near top of window."""
    def __init__(self, parent, message, kind="info", duration=3500):
        super().__init__(parent)
        self.setObjectName("Toast")
        colors = {
            "info": ("#e3f2fd", "#1565c0", "#0d47a1"),
            "success": ("#e8f5e9", "#2e7d32", "#1b5e20"),
            "warning": ("#fff3e0", "#ef6c00", "#e65100"),
            "error": ("#ffebee", "#c62828", "#b71c1c"),
        }
        bg, fg, border = colors.get(kind, colors["info"])
        icon = {"info": "ℹ️", "success": "✅", "warning": "⚠️", "error": "❌"}.get(kind, "ℹ️")
        self.setStyleSheet(
            f"QFrame#Toast {{ background-color: {bg}; border: 1px solid {border}; border-radius: 12px; }} "
            f"QLabel {{ color: {fg}; font-size: 12px; font-weight: 600; }}"
        )
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 9, 14, 9)
        lay.setSpacing(8)
        ico = QLabel(icon)
        ico.setStyleSheet("font-size: 16px;")
        lbl = QLabel(message)
        lbl.setWordWrap(True)
        lay.addWidget(ico)
        lay.addWidget(lbl, 1)
        self.adjustSize()
        self.setFixedWidth(min(440, max(300, parent.width() - 100)))
        parent_rect = parent.rect()
        x_pos = max(10, (parent_rect.width() - self.width()) // 2)
        self.move(x_pos, 56)
        self.show()
        self.raise_()
        QTimer.singleShot(duration, self.deleteLater)


class TaskProgressBlock(QWidget):
    """Real progress bar with elapsed/ETA time underneath and current task detail."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._start_ts = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 4, 0, 0)
        lay.setSpacing(4)

        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)

        meta_row = QHBoxLayout()
        self.pct_lbl = QLabel("0%")
        self.pct_lbl.setObjectName("MutedText")
        self.time_lbl = QLabel("Elapsed: 00:00  |  ETA: --:--")
        self.time_lbl.setObjectName("MutedText")
        meta_row.addWidget(self.pct_lbl)
        meta_row.addStretch()
        meta_row.addWidget(self.time_lbl)

        self.detail_lbl = QLabel("Idle")
        self.detail_lbl.setObjectName("BodyText")
        self.detail_lbl.setWordWrap(True)

        lay.addWidget(self.bar)
        lay.addLayout(meta_row)
        lay.addWidget(self.detail_lbl)

    def start_task(self, detail: str = "Starting task..."):
        self._start_ts = time.monotonic()
        self.bar.setValue(0)
        self.pct_lbl.setText("0%")
        self.time_lbl.setText("Elapsed: 00:00  |  ETA: calculating...")
        self.detail_lbl.setText(detail)

    @staticmethod
    def _fmt_sec(sec: float | None) -> str:
        if sec is None or sec < 0 or sec == float("inf"):
            return "--:--"
        s = int(sec)
        mins, rem = divmod(s, 60)
        hrs, mins = divmod(mins, 60)
        return f"{hrs:02d}:{mins:02d}:{rem:02d}" if hrs else f"{mins:02d}:{rem:02d}"

    def compute_eta_text(self, pct: int) -> str:
        if self._start_ts is None or pct <= 0:
            return "--:--"
        if pct >= 100:
            return "00:00"
        elapsed = time.monotonic() - self._start_ts
        return self._fmt_sec(elapsed * (100 - pct) / pct)

    def update_progress(self, pct: int, current: int = 0, total: int = 0, detail: str | None = None):
        if self._start_ts is None:
            self._start_ts = time.monotonic()
        pct = max(0, min(100, int(pct)))
        self.bar.setValue(pct)
        self.pct_lbl.setText(f"{pct}% ({current}/{total})" if total > 0 else f"{pct}%")

        elapsed = time.monotonic() - self._start_ts
        eta_text = self.compute_eta_text(pct)
        self.time_lbl.setText(f"Elapsed: {self._fmt_sec(elapsed)}  |  ETA: {eta_text}")

        if detail is not None:
            self.detail_lbl.setText(detail)

    def finish_task(self, detail: str = "Completed", success: bool = True):
        elapsed = (time.monotonic() - self._start_ts) if self._start_ts else 0.0
        if success:
            self.bar.setValue(100)
        self.time_lbl.setText(f"Elapsed: {self._fmt_sec(elapsed)}  |  Done")
        self.detail_lbl.setText(detail)


class EmptyState(QWidget):
    def __init__(self, icon, title, subtitle=""):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignCenter)
        lay.setSpacing(6)
        ico = QLabel(icon)
        ico.setAlignment(Qt.AlignCenter)
        ico.setStyleSheet("font-size: 40px;")
        self.t = QLabel(title)
        self.t.setAlignment(Qt.AlignCenter)
        self.t.setObjectName("SectionTitle")
        lay.addWidget(ico)
        lay.addWidget(self.t)
        if subtitle:
            s = QLabel(subtitle)
            s.setAlignment(Qt.AlignCenter)
            s.setObjectName("MutedText")
            lay.addWidget(s)


class ScanButton(QPushButton):
    """Animated scan button: use set_text(...) for label text, never setText(...)."""
    def __init__(self, text="Scan Now"):
        super().__init__(text)
        self.setObjectName("PrimaryScanBtn")
        self.setCursor(Qt.PointingHandCursor)
        self._busy = False
        self._spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self._spin_idx = 0
        self._orig_text = text
        self._label = "Scanning"
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

    def set_text(self, text: str):
        self._orig_text = text
        if not self._busy:
            super().setText(text)

    def set_busy(self, busy: bool, label: str = "Scanning"):
        self._busy = busy
        if busy:
            self._label = label
            self._timer.start(80)
        else:
            self._timer.stop()
            super().setText(self._orig_text)

    def _tick(self):
        self._spin_idx = (self._spin_idx + 1) % len(self._spinner_frames)
        super().setText(f"{self._spinner_frames[self._spin_idx]}  {self._label}...")


class ConfirmDialog(QDialog):
    def __init__(self, parent, title, message, confirm_text="Confirm", cancel_text="Cancel", danger=False):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(380)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 16)
        lay.setSpacing(12)
        ico = QLabel("⚠️" if danger else "❓")
        ico.setStyleSheet("font-size: 28px;")
        ico.setAlignment(Qt.AlignCenter)
        lay.addWidget(ico)
        title_lbl = QLabel(title)
        title_lbl.setObjectName("SectionTitle")
        title_lbl.setAlignment(Qt.AlignCenter)
        lay.addWidget(title_lbl)
        msg = QLabel(message)
        msg.setObjectName("BodyText")
        msg.setWordWrap(True)
        msg.setAlignment(Qt.AlignCenter)
        lay.addWidget(msg)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel = QPushButton(cancel_text)
        cancel.setObjectName("ActionBtn")
        cancel.clicked.connect(self.reject)
        ok = QPushButton(confirm_text)
        ok.setObjectName("DangerBtn" if danger else "PrimaryScanBtn")
        ok.clicked.connect(self.accept)
        btn_row.addWidget(cancel)
        btn_row.addWidget(ok)
        lay.addLayout(btn_row)


class SearchableListWidget(QWidget):
    def __init__(self, placeholder="Search...", empty_icon="📭", empty_title="Nothing here yet"):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        self.search = QLineEdit()
        self.search.setPlaceholderText(placeholder)
        self.search.textChanged.connect(self._filter)
        lay.addWidget(self.search)
        self.list_widget = QListWidget()
        lay.addWidget(self.list_widget, 1)
        self._empty = EmptyState(empty_icon, empty_title)
        lay.addWidget(self._empty)
        self._empty.hide()

    def set_items(self, items):
        self.list_widget.clear()
        for it in items:
            if isinstance(it, QListWidgetItem):
                self.list_widget.addItem(it)
            else:
                self.list_widget.addItem(str(it))
        self._update_empty()

    def clear(self):
        self.list_widget.clear()
        self._update_empty()

    def _filter(self, text):
        text = text.strip().lower()
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            item.setHidden(bool(text) and text not in item.text().lower())
        self._update_empty()

    def _update_empty(self):
        visible = sum(1 for i in range(self.list_widget.count()) if not self.list_widget.item(i).isHidden())
        if visible == 0:
            self.list_widget.hide()
            self._empty.show()
        else:
            self.list_widget.show()
            self._empty.hide()


# ═══════════════════════════════════════════════════════════════════════
#  MAIN WINDOW (UI ONLY)
# ═══════════════════════════════════════════════════════════════════════
class RAntivirusWindow(QMainWindow):
    theme_changed = Signal(str)
    rtl_changed = Signal(bool)
    scan_requested = Signal(str, bool, dict)
    stop_requested = Signal()
    update_defs_requested = Signal()
    full_scan_requested = Signal()
    settings_saved = Signal(dict)
    schedule_saved = Signal(dict)
    exclusions_changed = Signal()
    quarantine_action = Signal(str, str)

    def __init__(self, engine, bridge):
        super().__init__()
        self.engine = engine
        self.bridge = bridge

        self.setWindowTitle("R Antivirus — Administrator Mode")
        self.resize(1240, 820)
        self.setMinimumSize(1020, 700)
        self.setAcceptDrops(True)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)

        data_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.icon_path = os.path.join(data_dir, "Resources", "Ricon.png")
        if not os.path.isfile(self.icon_path):
            self.icon_path = ""
        else:
            self.setWindowIcon(QIcon(self.icon_path))

        self._theme = self.engine.config.get("ui", {}).get("theme", "light")
        self._rtl = self.engine.config.get("ui", {}).get("rtl", False)
        self._sounds = self.engine.config.get("ui", {}).get("sounds", False)
        self._console_collapsed = self.engine.config.get("ui", {}).get("console_collapsed", False)

        self._toast_stack = []
        self._scan_poll = None
        self._scan_busy = False
        self._scan_completed_notified = False
        self._last_sched_run_minute = ""
        self._tray_alert_state = None

        self._build_ui()
        self._init_tray()
        self._apply_theme(self._theme)
        self._sync_maximized_state()

        self.bridge.log_signal.connect(self._append_log)
        self.bridge.progress_signal.connect(self._update_progress_ui)
        self.bridge.scan_finished_signal.connect(lambda msg: self._on_scan_finished(msg, True))
        if hasattr(self.bridge, "scan_result_signal"):
            self.bridge.scan_result_signal.connect(self._on_scan_finished)
        self.bridge.popup_signal.connect(lambda t, m: self._toast(f"{t}: {m}", "success"))
        self.bridge.notify_signal.connect(self._on_engine_notify)
        self.bridge.threat_signal.connect(self._on_threat_detected)

        self.stats_timer = QTimer(self)
        self.stats_timer.timeout.connect(self._poll_stats)
        self.stats_timer.start(1500)

        self.sched_timer = QTimer(self)
        self.sched_timer.timeout.connect(self._check_schedule)
        self.sched_timer.start(20000)

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.WindowStateChange:
            self._sync_maximized_state()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._reposition_toasts()

    def _sync_maximized_state(self):
        is_max = bool(self.isMaximized() or (self.windowState() & Qt.WindowMaximized))
        if hasattr(self, "title_bar"):
            self.title_bar.sync_max_icon(is_max)

    def _refresh_tray_icon(self, has_threats: bool):
        if hasattr(self, "tray") and self._tray_alert_state != has_threats:
            self._tray_alert_state = has_threats
            self.tray.setIcon(build_shield_tray_icon(self.icon_path, alert=has_threats))

    def _on_threat_detected(self):
        self.refresh_quarantine()
        if self._console_collapsed:
            self._set_console_collapsed(False)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            local_path = urls[0].toLocalFile()
            if local_path:
                self.target_input.setText(local_path)
                self._switch_page(1)
                self._toast(f"Selected: {os.path.basename(local_path)}", "info")
                event.acceptProposedAction()
                return
        event.ignore()

    def _on_engine_notify(self, title, message, is_alert=True):
        kind = "warning" if is_alert else "info"
        self._toast(f"{title} — {message}", kind)
        if hasattr(self, "tray") and self.tray.isVisible():
            icon_type = QSystemTrayIcon.Warning if is_alert else QSystemTrayIcon.Information
            self.tray.showMessage(title, message, icon_type, 4000)
        if self._sounds and os.name == "nt":
            try:
                import winsound
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION if is_alert else winsound.MB_OK)
            except Exception:
                pass

    def _check_schedule(self):
        sched = self.engine.config.get("schedule", {})
        if not sched.get("enabled") or self.engine.is_busy:
            return
        target = str(sched.get("target", "")).strip()
        if not target or not os.path.exists(target):
            return
        now = datetime.now()
        hm = now.strftime("%H:%M")
        freq = sched.get("frequency", "Daily")
        if freq == "Daily" and hm == str(sched.get("time", "")).strip() and self._last_sched_run_minute != hm:
            self._last_sched_run_minute = hm
            self._start_all_task_progress(f"Scheduled daily scan: {target}")
            self.engine.run_clamav_scan(target, auto_quarantine=True, source_label="Scheduled Daily")
        elif freq == "Hourly" and now.minute == 0 and self._last_sched_run_minute != hm:
            self._last_sched_run_minute = hm
            self._start_all_task_progress(f"Scheduled hourly scan: {target}")
            self.engine.run_clamav_scan(target, auto_quarantine=True, source_label="Scheduled Hourly")

    def set_rtl_state(self, state):
        self._rtl = bool(state)
        self.setLayoutDirection(Qt.RightToLeft if self._rtl else Qt.LeftToRight)
        self._update_texts()

    def _build_ui(self):
        central = QWidget()
        central.setObjectName("RootContainer")
        self.setCentralWidget(central)
        self._root_lay = QVBoxLayout(central)
        self._root_lay.setContentsMargins(0, 0, 0, 0)
        self._root_lay.setSpacing(0)

        self.shell = QFrame()
        self.shell.setObjectName("WindowShell")
        shell_lay = QVBoxLayout(self.shell)
        shell_lay.setContentsMargins(0, 0, 0, 0)
        shell_lay.setSpacing(0)
        self._root_lay.addWidget(self.shell)

        self.title_bar = CustomTitleBar(self)
        shell_lay.addWidget(self.title_bar)

        body = QWidget()
        body_lay = QHBoxLayout(body)
        body_lay.setContentsMargins(0, 0, 0, 0)
        body_lay.setSpacing(0)
        shell_lay.addWidget(body, 1)

        sidebar = QFrame()
        sidebar.setObjectName("LeftSidebar")
        sidebar.setFixedWidth(246)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(16, 20, 16, 18)
        side.setSpacing(6)

        brand_row = QHBoxLayout()
        logo = QLabel()
        if self.icon_path:
            logo.setPixmap(QPixmap(self.icon_path).scaled(42, 42, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            logo.setText("🦋")
            logo.setStyleSheet("font-size: 26px;")
        brand_row.addWidget(logo)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        lbl_brand = QLabel("R Antivirus")
        lbl_brand.setObjectName("BrandTitle")
        lbl_sub = QLabel("Admin Protection")
        lbl_sub.setObjectName("BrandSub")
        titles.addWidget(lbl_brand)
        titles.addWidget(lbl_sub)
        brand_row.addLayout(titles)
        brand_row.addStretch()
        side.addLayout(brand_row)
        side.addSpacing(12)

        self.stack = QStackedWidget()
        self.nav_icons = ["🛡️", "🔍", "🚀", "🧠", "🚫", "📦", "📊", "ℹ️"]
        self.nav_buttons = []

        for idx in range(8):
            btn = QPushButton()
            btn.setObjectName("NavBtn")
            btn.setProperty("active", idx == 0)
            btn.clicked.connect(lambda checked=False, i=idx: self._switch_page(i))
            side.addWidget(btn)
            self.nav_buttons.append(btn)

        side.addStretch()
        self.theme_btn = QPushButton()
        self.theme_btn.setObjectName("ActionBtn")
        self.theme_btn.clicked.connect(self._toggle_theme)
        side.addWidget(self.theme_btn)

        self.rtl_btn = QPushButton()
        self.rtl_btn.setObjectName("ActionBtn")
        self.rtl_btn.clicked.connect(self._toggle_rtl)
        side.addWidget(self.rtl_btn)

        self.tray_btn = QPushButton()
        self.tray_btn.setObjectName("ActionBtn")
        self.tray_btn.clicked.connect(self._minimize_to_tray)
        side.addWidget(self.tray_btn)

        self.exit_btn = QPushButton()
        self.exit_btn.setObjectName("DangerBtn")
        self.exit_btn.clicked.connect(self._confirm_quit)
        side.addWidget(self.exit_btn)

        body_lay.addWidget(sidebar)

        center = QWidget()
        self.center_lay = QVBoxLayout(center)
        self.center_lay.setContentsMargins(20, 18, 16, 16)
        self.center_lay.setSpacing(12)
        self.center_lay.addWidget(self.stack, stretch=3)

        self.console_card = QFrame()
        self.console_card.setObjectName("SoftCard")
        con_lay = QVBoxLayout(self.console_card)
        con_lay.setContentsMargins(12, 10, 12, 10)
        con_lay.setSpacing(6)
        con_top = QHBoxLayout()
        self.con_lbl = QLabel()
        self.con_lbl.setObjectName("SectionTitle")

        self.toggle_log_btn = QPushButton()
        self.toggle_log_btn.setObjectName("ActionBtn")
        self.toggle_log_btn.setFixedHeight(28)
        self.toggle_log_btn.clicked.connect(lambda: self._set_console_collapsed(not self._console_collapsed))

        self.clear_btn = QPushButton()
        self.clear_btn.setObjectName("ActionBtn")
        self.clear_btn.setFixedHeight(28)
        self.clear_btn.clicked.connect(lambda: self.console_box.clear())

        con_top.addWidget(self.con_lbl)
        con_top.addStretch()
        con_top.addWidget(self.toggle_log_btn)
        con_top.addWidget(self.clear_btn)
        con_lay.addLayout(con_top)

        self.console_box = QTextEdit()
        self.console_box.setObjectName("ConsoleBox")
        self.console_box.setReadOnly(True)
        self.console_box.setMinimumHeight(130)
        self.console_box.setMaximumHeight(175)
        con_lay.addWidget(self.console_box)
        self.center_lay.addWidget(self.console_card, stretch=1)
        body_lay.addWidget(center, stretch=1)

        right = QFrame()
        right.setObjectName("RightPanel")
        right.setFixedWidth(275)
        r_lay = QVBoxLayout(right)
        r_lay.setContentsMargins(16, 20, 16, 20)
        r_lay.setSpacing(12)

        status_box = QFrame()
        status_box.setObjectName("SoftCard")
        sb = QVBoxLayout(status_box)
        sb.setContentsMargins(12, 12, 12, 12)
        sb.setSpacing(8)
        self.rt_shield_lbl = QLabel()
        self.rt_shield_lbl.setObjectName("SectionTitle")
        self.right_shield_status = QLabel()
        self.right_shield_status.setObjectName("DangerText")
        self.toggle_shield_btn = QPushButton()
        self.toggle_shield_btn.setObjectName("ActionBtn")
        self.toggle_shield_btn.clicked.connect(self._toggle_shield)
        self.right_boot_status = QLabel()
        self.right_boot_status.setObjectName("MutedText")
        sb.addWidget(self.rt_shield_lbl)
        sb.addWidget(self.right_shield_status)
        sb.addWidget(self.toggle_shield_btn)
        sb.addWidget(self.right_boot_status)
        r_lay.addWidget(status_box)

        perf_box = QFrame()
        perf_box.setObjectName("SoftCard")
        pf = QVBoxLayout(perf_box)
        pf.setContentsMargins(12, 12, 12, 12)
        pf.setSpacing(6)
        self.sys_telemetry_lbl = QLabel()
        self.sys_telemetry_lbl.setObjectName("SectionTitle")
        pf.addWidget(self.sys_telemetry_lbl)
        self.cpu_lbl = QLabel("CPU: 0%")
        self.cpu_lbl.setObjectName("BodyText")
        self.cpu_bar = QProgressBar()
        self.cpu_bar.setRange(0, 100)
        self.ram_lbl = QLabel("RAM: 0%")
        self.ram_lbl.setObjectName("BodyText")
        self.ram_bar = QProgressBar()
        self.ram_bar.setRange(0, 100)
        self.gpu_lbl = QLabel("GPU: N/A")
        self.gpu_lbl.setObjectName("MutedText")
        pf.addWidget(self.cpu_lbl)
        pf.addWidget(self.cpu_bar)
        pf.addWidget(self.ram_lbl)
        pf.addWidget(self.ram_bar)
        pf.addWidget(self.gpu_lbl)
        r_lay.addWidget(perf_box)

        cnt_box = QFrame()
        cnt_box.setObjectName("SoftCard")
        cnt = QVBoxLayout(cnt_box)
        cnt.setContentsMargins(12, 12, 12, 12)
        cnt.setSpacing(5)
        self.scanned_lbl = QLabel()
        self.scanned_lbl.setObjectName("BodyText")
        self.threats_lbl = QLabel()
        self.threats_lbl.setObjectName("DangerText")
        self.update_lbl = QLabel()
        self.update_lbl.setObjectName("MutedText")
        cnt.addWidget(self.scanned_lbl)
        cnt.addWidget(self.threats_lbl)
        cnt.addWidget(self.update_lbl)
        r_lay.addWidget(cnt_box)
        r_lay.addStretch()
        body_lay.addWidget(right)

        self.scan_progress = TaskProgressBlock()
        self.startup_progress = TaskProgressBlock()
        self.memory_progress = TaskProgressBlock()
        self._progress_blocks = [self.scan_progress, self.startup_progress, self.memory_progress]

        self.stack.addWidget(self._build_overview_page())
        self.stack.addWidget(self._build_scan_page())
        self.stack.addWidget(self._build_startup_boot_page())
        self.stack.addWidget(self._build_memory_schedule_page())
        self.stack.addWidget(self._build_exclusions_page())
        self.stack.addWidget(self._build_quarantine_page())
        self.stack.addWidget(self._build_reports_settings_page())

        if AboutPage:
            self.stack.addWidget(AboutPage(self.icon_path))
        else:
            self.stack.addWidget(QWidget())

        self.status = QStatusBar()
        self.status.setSizeGripEnabled(False)
        self._status_shield = QLabel()
        self._status_defs = QLabel()
        self._status_task = QLabel("")
        self._status_task.setObjectName("MutedText")
        self._status_task.hide()
        self._status_theme = QLabel()
        self._status_version = QLabel("v0.3.1")
        self.status.addWidget(self._status_shield)
        self.status.addWidget(QLabel("  |  "))
        self.status.addWidget(self._status_defs)
        self.status.addWidget(self._status_task)
        self.status.addPermanentWidget(self._status_theme)
        self.status.addPermanentWidget(self._status_version)
        shell_lay.addWidget(self.status)

        self._set_console_collapsed(self._console_collapsed, save=False)
        self.setLayoutDirection(Qt.RightToLeft if self._rtl else Qt.LeftToRight)
        self._update_texts()
        self.refresh_exclusions(self.engine.config.get("exclusions", []))
        self.refresh_quarantine()

    def _set_console_collapsed(self, collapsed: bool, save: bool = True):
        self._console_collapsed = collapsed
        self.console_box.setVisible(not collapsed)
        self.clear_btn.setVisible(not collapsed)
        if save:
            if "ui" not in self.engine.config or not isinstance(self.engine.config["ui"], dict):
                self.engine.config["ui"] = {}
            self.engine.config["ui"]["console_collapsed"] = collapsed
            self.engine.save_config()

    def _init_tray(self):
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(build_shield_tray_icon(self.icon_path, alert=False))
        self.tray.setToolTip("R Antivirus (Admin)")
        menu = QMenu()
        a1 = QAction("Open R Antivirus", self)
        a1.triggered.connect(self._restore_from_tray)
        a2 = QAction("Exit Completely", self)
        a2.triggered.connect(self._confirm_quit)
        menu.addAction(a1)
        menu.addSeparator()
        menu.addAction(a2)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda r: self._restore_from_tray() if r == QSystemTrayIcon.DoubleClick else None)
        self.tray.show()

    def _restore_from_tray(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _minimize_to_tray(self):
        self.hide()
        self._toast("Minimized to system tray", "info")

    def _confirm_quit(self):
        tr = TRANS["ar"] if self._rtl else TRANS["en"]
        dlg = ConfirmDialog(
            self,
            tr["exit_title"],
            tr["exit_msg"],
            confirm_text=tr["exit_ok"],
            cancel_text=tr["cancel"],
        )
        if dlg.exec() == QDialog.Accepted:
            self.engine.stop_realtime()
            self.engine.stop_active_process()
            self.tray.hide()
            QApplication.quit()

    def _update_texts(self):
        tr = TRANS["ar"] if self._rtl else TRANS["en"]
        quar_count = self.quar_list.count() if hasattr(self, "quar_list") else 0

        for i, btn in enumerate(self.nav_buttons):
            label = f"{self.nav_icons[i]}  {tr['nav'][i]}"
            if i == 5 and quar_count > 0:
                label = f"{label}  ({quar_count})"
            btn.setText(label)

        self.theme_btn.setText(tr["theme_light"] if self._theme == "dark" else tr["theme_dark"])
        self.rtl_btn.setText(tr["lang_en"] if self._rtl else tr["lang_ar"])
        self.tray_btn.setText(tr["min_tray"])
        self.exit_btn.setText(tr["exit"])
        self.con_lbl.setText(tr["live_console"])
        self.toggle_log_btn.setText(tr["toggle_log"])
        self.clear_btn.setText(tr["clear_log"])
        self.rt_shield_lbl.setText(tr["rt_shield"])
        self.sys_telemetry_lbl.setText(tr["sys_telemetry"])

        has_threats = self.engine.stats.get("threats_blocked", 0) > 0 or quar_count > 0
        self.shield_widget.set_alert(has_threats)
        self._refresh_tray_icon(has_threats)
        self.hero_status_lbl.setText(tr["alert_state"] if has_threats else tr["protected"])
        self.hero_sub_lbl.setText(tr["alert_sub"] if has_threats else tr["protected_sub"])

        self.hero_scan_btn.setText(tr["scan_now"])
        self.btn_upd_defs.setText(tr["update_defs"])
        self.btn_full_disk.setText(tr["full_disk"])
        self.btn_view_quar.setText(tr["view_quar"])

        self.qc_shield.lbl_title.setText(tr["qc_shield_title"])
        self.qc_defs.lbl_title.setText(tr["qc_defs_title"])
        self.qc_quar.lbl_title.setText(tr["qc_quar_title"])

        self.rb_clam.setText(tr["clam_local"])
        self.rb_vt.setText(tr["vt_cloud"])
        self.target_input.setPlaceholderText(tr["drop_here"])
        self.btn_pick_folder.setText(tr["folder_btn"])
        self.btn_pick_file.setText(tr["file_btn"])
        self.chk_rec.setText(tr["recursive"])
        self.chk_inf.setText(tr["infected_only"])
        self.chk_arc.setText(tr["deep_arch"])
        self.chk_quar.setText(tr["auto_quar"])
        self.btn_run_scan.setText(tr["run_scan"])
        self.btn_full_scan2.setText(tr["full_disk"])
        self.btn_stop_scan.setText(tr["stop"])

        self.lbl_win_startup.setText(tr["win_startup"])
        self.chk_startup_quar.setText(tr["auto_quar_startup"])
        self.btn_scan_startup.setText(tr["scan_startup"])
        self.lbl_boot_task.setText(tr["boot_task"])
        self.btn_sched_boot.setText(tr["sched_boot"])
        self.btn_dis_boot.setText(tr["dis_boot"])
        self._refresh_boot_status()

        self.lbl_mem_scan.setText(tr["mem_scan"])
        self.chk_mem_quar.setText(tr["auto_quar_mem"])
        self.btn_scan_mem.setText(tr["scan_mem"])
        self.chk_sched_en.setText(tr["enable_sched"])
        self.lbl_freq.setText(tr["frequency"])
        self.lbl_time.setText(tr["time_hhmm"])
        self.lbl_target.setText(tr["target_folder"])
        self.btn_save_sched.setText(tr["save_sched"])

        self.lbl_whitelisted.setText(tr["whitelisted"])
        self.excl_widget.search.setPlaceholderText(tr["search_excl"])
        self.excl_widget._empty.t.setText(tr["no_excl"])
        self.btn_excl_dir.setText(tr["excl_folder"])
        self.btn_excl_file.setText(tr["excl_file"])
        self.btn_rem_excl.setText(tr["rem_selected"])

        self.lbl_quar_vault.setText(tr["quar_vault"])
        self.quar_widget.search.setPlaceholderText(tr["search_quar"])
        self.quar_widget._empty.t.setText(tr["quar_empty"])
        self.btn_refresh_quar.setText(tr["refresh"])
        self.btn_restore_quar.setText(tr["restore"])
        self.btn_trust_quar.setText(tr["trust_exclude"])
        self.btn_sha_quar.setText(tr["sha256"])
        self.btn_details_quar.setText(tr["details"])
        self.btn_del_quar.setText(tr["delete"])

        self.btn_view_incidents.setText(tr["recent_incidents"])
        self.btn_exp_html.setText(tr["export_html"])
        self.btn_exp_csv.setText(tr["export_csv"])
        self.btn_exp_set.setText(tr["export_set"])
        self.btn_imp_set.setText(tr["import_set"])
        self.lbl_clam_path.setText(tr["clam_path"])
        self.lbl_fresh_path.setText(tr["fresh_path"])
        self.lbl_vt_key.setText(tr["vt_key"])
        self.lbl_max_fs.setText(tr["max_fs"])
        self.lbl_max_ss.setText(tr["max_ss"])
        self.chk_sounds.setText(tr["enable_sounds"])
        self.btn_save_set.setText(tr["save_set"])

        self._poll_stats()

    def _apply_theme(self, theme):
        self._theme = theme
        self.setStyleSheet(DARK_QSS if theme == "dark" else LIGHT_QSS)
        self._sync_maximized_state()
        self._update_texts()

    def _toggle_theme(self):
        new = "light" if self._theme == "dark" else "dark"
        self._apply_theme(new)
        self.theme_changed.emit(new)

    def _toggle_rtl(self):
        self._rtl = not self._rtl
        self.setLayoutDirection(Qt.RightToLeft if self._rtl else Qt.LeftToRight)
        self.rtl_changed.emit(self._rtl)
        self._update_texts()

    def _build_overview_page(self):
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(14)

        hero = QFrame()
        hero.setObjectName("ShieldHeroCard")
        h = QVBoxLayout(hero)
        h.setContentsMargins(24, 22, 24, 22)
        h.setSpacing(10)
        h.setAlignment(Qt.AlignCenter)

        self.shield_widget = ShieldBadgeWidget()
        self.hero_status_lbl = QLabel()
        self.hero_status_lbl.setObjectName("HeroStatus")
        self.hero_status_lbl.setAlignment(Qt.AlignCenter)
        self.hero_sub_lbl = QLabel()
        self.hero_sub_lbl.setObjectName("HeroSub")
        self.hero_sub_lbl.setAlignment(Qt.AlignCenter)
        self.hero_scan_btn = ScanButton()
        self.hero_scan_btn.clicked.connect(lambda: self._switch_page(1))

        h.addWidget(self.shield_widget, alignment=Qt.AlignCenter)
        h.addWidget(self.hero_status_lbl)
        h.addWidget(self.hero_sub_lbl)
        h.addSpacing(6)
        h.addWidget(self.hero_scan_btn, alignment=Qt.AlignCenter)
        lay.addWidget(hero)

        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)
        self.qc_shield = QuickStatCard("Real-Time Shield", "OFF", "🛡️")
        self.qc_shield.clicked.connect(self._toggle_shield)

        self.qc_defs = QuickStatCard("Virus Definitions", "Never", "🔄")
        self.qc_defs.clicked.connect(self._trigger_update_defs)

        self.qc_quar = QuickStatCard("Quarantine Vault", "0 files", "📦")
        self.qc_quar.clicked.connect(lambda: self._switch_page(5))

        cards_row.addWidget(self.qc_shield)
        cards_row.addWidget(self.qc_defs)
        cards_row.addWidget(self.qc_quar)
        lay.addLayout(cards_row)

        quick = QHBoxLayout()
        quick.setSpacing(10)
        self.btn_upd_defs = QPushButton()
        self.btn_upd_defs.setObjectName("ActionBtn")
        self.btn_upd_defs.clicked.connect(self._trigger_update_defs)
        self.btn_full_disk = QPushButton()
        self.btn_full_disk.setObjectName("ActionBtn")
        self.btn_full_disk.clicked.connect(self._trigger_full_scan)
        self.btn_view_quar = QPushButton()
        self.btn_view_quar.setObjectName("ActionBtn")
        self.btn_view_quar.clicked.connect(lambda: self._switch_page(5))
        quick.addWidget(self.btn_upd_defs)
        quick.addWidget(self.btn_full_disk)
        quick.addWidget(self.btn_view_quar)
        lay.addLayout(quick)
        return page

    def _build_scan_page(self):
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setSpacing(10)
        card = QFrame()
        card.setObjectName("SoftCard")
        c = QVBoxLayout(card)
        c.setContentsMargins(14, 14, 14, 14)
        c.setSpacing(10)

        eng = QHBoxLayout()
        self.rb_clam = QRadioButton()
        self.rb_vt = QRadioButton()
        self.rb_clam.setChecked(True)
        grp = QButtonGroup(self)
        grp.addButton(self.rb_clam)
        grp.addButton(self.rb_vt)
        eng.addWidget(self.rb_clam)
        eng.addWidget(self.rb_vt)
        eng.addStretch()
        c.addLayout(eng)

        tgt = QHBoxLayout()
        self.target_input = QLineEdit()
        self.btn_pick_folder = QPushButton()
        self.btn_pick_folder.setObjectName("ActionBtn")
        self.btn_pick_folder.clicked.connect(self._pick_folder)
        self.btn_pick_file = QPushButton()
        self.btn_pick_file.setObjectName("ActionBtn")
        self.btn_pick_file.clicked.connect(self._pick_file)
        tgt.addWidget(self.target_input)
        tgt.addWidget(self.btn_pick_folder)
        tgt.addWidget(self.btn_pick_file)
        c.addLayout(tgt)

        opts = QHBoxLayout()
        self.chk_rec = QCheckBox()
        self.chk_rec.setChecked(True)
        self.chk_inf = QCheckBox()
        self.chk_inf.setChecked(True)
        self.chk_arc = QCheckBox()
        self.chk_arc.setChecked(True)
        self.chk_quar = QCheckBox()
        for w in (self.chk_rec, self.chk_inf, self.chk_arc, self.chk_quar):
            opts.addWidget(w)
        opts.addStretch()
        c.addLayout(opts)

        act = QHBoxLayout()
        self.btn_run_scan = ScanButton()
        self.btn_run_scan.clicked.connect(self._run_selected_scan)
        self.btn_full_scan2 = QPushButton()
        self.btn_full_scan2.setObjectName("ActionBtn")
        self.btn_full_scan2.clicked.connect(self._trigger_full_scan)
        self.btn_stop_scan = QPushButton()
        self.btn_stop_scan.setObjectName("DangerBtn")
        self.btn_stop_scan.clicked.connect(self.stop_requested.emit)
        act.addWidget(self.btn_run_scan)
        act.addWidget(self.btn_full_scan2)
        act.addWidget(self.btn_stop_scan)
        act.addStretch()
        c.addLayout(act)

        c.addWidget(self.scan_progress)
        self.scan_prog_bar = self.scan_progress.bar
        self.scan_prog_lbl = self.scan_progress.pct_lbl

        lay.addWidget(card)
        lay.addStretch()
        return page

    def _build_startup_boot_page(self):
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setSpacing(12)
        st = QFrame()
        st.setObjectName("SoftCard")
        s = QVBoxLayout(st)
        s.setContentsMargins(14, 14, 14, 14)
        self.lbl_win_startup = QLabel()
        s.addWidget(self.lbl_win_startup)
        self.chk_startup_quar = QCheckBox()
        s.addWidget(self.chk_startup_quar)
        self.btn_scan_startup = QPushButton()
        self.btn_scan_startup.setObjectName("ActionBtn")
        self.btn_scan_startup.clicked.connect(self._run_startup_scan)
        s.addWidget(self.btn_scan_startup, alignment=Qt.AlignLeft)
        s.addWidget(self.startup_progress)
        lay.addWidget(st)

        bt = QFrame()
        bt.setObjectName("SoftCard")
        b_lay = QVBoxLayout(bt)
        b_lay.setContentsMargins(14, 14, 14, 14)
        self.lbl_boot_task = QLabel()
        b_lay.addWidget(self.lbl_boot_task)
        self.page_boot_status = QLabel()
        b_lay.addWidget(self.page_boot_status)
        row = QHBoxLayout()
        self.btn_sched_boot = QPushButton()
        self.btn_sched_boot.setObjectName("ActionBtn")
        self.btn_sched_boot.clicked.connect(self._schedule_boot)
        self.btn_dis_boot = QPushButton()
        self.btn_dis_boot.setObjectName("DangerBtn")
        self.btn_dis_boot.clicked.connect(self._disable_boot)
        row.addWidget(self.btn_sched_boot)
        row.addWidget(self.btn_dis_boot)
        row.addStretch()
        b_lay.addLayout(row)
        lay.addWidget(bt)
        lay.addStretch()
        return page

    def _build_memory_schedule_page(self):
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setSpacing(12)
        mem = QFrame()
        mem.setObjectName("SoftCard")
        m = QVBoxLayout(mem)
        m.setContentsMargins(14, 14, 14, 14)
        self.lbl_mem_scan = QLabel()
        m.addWidget(self.lbl_mem_scan)
        self.chk_mem_quar = QCheckBox()
        m.addWidget(self.chk_mem_quar)
        self.btn_scan_mem = QPushButton()
        self.btn_scan_mem.setObjectName("ActionBtn")
        self.btn_scan_mem.clicked.connect(self._run_memory_scan)
        m.addWidget(self.btn_scan_mem, alignment=Qt.AlignLeft)
        m.addWidget(self.memory_progress)
        lay.addWidget(mem)

        sch = QFrame()
        sch.setObjectName("SoftCard")
        s = QGridLayout(sch)
        s.setContentsMargins(14, 14, 14, 14)
        cfg = self.engine.config.get("schedule", {})
        self.chk_sched_en = QCheckBox()
        self.chk_sched_en.setChecked(bool(cfg.get("enabled", False)))
        self.cmb_freq = QComboBox()
        self.cmb_freq.addItems(["Daily", "Hourly"])
        self.cmb_freq.setCurrentText(cfg.get("frequency", "Daily"))
        self.txt_sched_time = QLineEdit(cfg.get("time", "14:00"))
        dl = os.path.join(os.path.expanduser("~"), "Downloads")
        self.txt_sched_target = QLineEdit(cfg.get("target") or (dl if os.path.isdir(dl) else ""))

        self.lbl_freq = QLabel()
        self.lbl_time = QLabel()
        self.lbl_target = QLabel()
        self.btn_save_sched = QPushButton()
        self.btn_save_sched.setObjectName("ActionBtn")
        self.btn_save_sched.clicked.connect(self._save_schedule)

        s.addWidget(self.chk_sched_en, 0, 0, 1, 2)
        s.addWidget(self.lbl_freq, 1, 0)
        s.addWidget(self.cmb_freq, 1, 1)
        s.addWidget(self.lbl_time, 2, 0)
        s.addWidget(self.txt_sched_time, 2, 1)
        s.addWidget(self.lbl_target, 3, 0)
        s.addWidget(self.txt_sched_target, 3, 1)
        s.addWidget(self.btn_save_sched, 4, 0, 1, 2, Qt.AlignLeft)
        lay.addWidget(sch)
        lay.addStretch()
        return page

    def _build_exclusions_page(self):
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setSpacing(10)
        card = QFrame()
        card.setObjectName("SoftCard")
        c = QVBoxLayout(card)
        c.setContentsMargins(14, 14, 14, 14)
        self.lbl_whitelisted = QLabel()
        c.addWidget(self.lbl_whitelisted)
        self.excl_widget = SearchableListWidget()
        c.addWidget(self.excl_widget)
        self.excl_list = self.excl_widget.list_widget
        row = QHBoxLayout()
        self.btn_excl_dir = QPushButton()
        self.btn_excl_dir.setObjectName("ActionBtn")
        self.btn_excl_dir.clicked.connect(self._add_excl_dir)
        self.btn_excl_file = QPushButton()
        self.btn_excl_file.setObjectName("ActionBtn")
        self.btn_excl_file.clicked.connect(self._add_excl_file)
        self.btn_rem_excl = QPushButton()
        self.btn_rem_excl.setObjectName("DangerBtn")
        self.btn_rem_excl.clicked.connect(self._remove_excl)
        row.addWidget(self.btn_excl_dir)
        row.addWidget(self.btn_excl_file)
        row.addWidget(self.btn_rem_excl)
        row.addStretch()
        c.addLayout(row)
        lay.addWidget(card)
        return page

    def _build_quarantine_page(self):
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setSpacing(10)
        card = QFrame()
        card.setObjectName("SoftCard")
        c = QVBoxLayout(card)
        c.setContentsMargins(14, 14, 14, 14)
        self.lbl_quar_vault = QLabel()
        c.addWidget(self.lbl_quar_vault)
        self.quar_widget = SearchableListWidget()
        c.addWidget(self.quar_widget)
        self.quar_list = self.quar_widget.list_widget
        row = QHBoxLayout()
        self.btn_refresh_quar = QPushButton()
        self.btn_refresh_quar.setObjectName("ActionBtn")
        self.btn_refresh_quar.clicked.connect(self.refresh_quarantine)
        self.btn_restore_quar = QPushButton()
        self.btn_restore_quar.setObjectName("ActionBtn")
        self.btn_restore_quar.clicked.connect(lambda: self._emit_quar_action("restore"))
        self.btn_trust_quar = QPushButton()
        self.btn_trust_quar.setObjectName("ActionBtn")
        self.btn_trust_quar.clicked.connect(self._trust_and_exclude_quar)
        self.btn_sha_quar = QPushButton()
        self.btn_sha_quar.setObjectName("ActionBtn")
        self.btn_sha_quar.clicked.connect(self._copy_quar_sha256)
        self.btn_details_quar = QPushButton()
        self.btn_details_quar.setObjectName("ActionBtn")
        self.btn_details_quar.clicked.connect(self._show_quarantine_details)
        self.btn_del_quar = QPushButton()
        self.btn_del_quar.setObjectName("DangerBtn")
        self.btn_del_quar.clicked.connect(lambda: self._emit_quar_action("delete"))
        for w in (self.btn_refresh_quar, self.btn_restore_quar, self.btn_trust_quar, self.btn_sha_quar, self.btn_details_quar, self.btn_del_quar):
            row.addWidget(w)
        row.addStretch()
        c.addLayout(row)
        lay.addWidget(card)
        return page

    def _build_reports_settings_page(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setSpacing(12)
        rep = QFrame()
        rep.setObjectName("SoftCard")
        r = QHBoxLayout(rep)
        r.setContentsMargins(14, 14, 14, 14)
        self.btn_view_incidents = QPushButton()
        self.btn_view_incidents.setObjectName("ActionBtn")
        self.btn_view_incidents.clicked.connect(self._open_incidents_dialog)
        self.btn_exp_html = QPushButton()
        self.btn_exp_html.setObjectName("ActionBtn")
        self.btn_exp_html.clicked.connect(lambda: self._export_report("html"))
        self.btn_exp_csv = QPushButton()
        self.btn_exp_csv.setObjectName("ActionBtn")
        self.btn_exp_csv.clicked.connect(lambda: self._export_report("csv"))
        self.btn_exp_set = QPushButton()
        self.btn_exp_set.setObjectName("ActionBtn")
        self.btn_exp_set.clicked.connect(self._export_settings_file)
        self.btn_imp_set = QPushButton()
        self.btn_imp_set.setObjectName("ActionBtn")
        self.btn_imp_set.clicked.connect(self._import_settings_file)
        for w in (self.btn_view_incidents, self.btn_exp_html, self.btn_exp_csv, self.btn_exp_set, self.btn_imp_set):
            r.addWidget(w)
        r.addStretch()
        outer.addWidget(rep)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        inner = QWidget()
        inner.setObjectName("ScrollInner")
        s = QGridLayout(inner)
        s.setContentsMargins(14, 14, 14, 14)
        s.setSpacing(10)
        s.setAlignment(Qt.AlignTop | Qt.AlignLeft)

        self.txt_clam = QLineEdit(self.engine.config.get("clamscan_path", ""))
        self.txt_fresh = QLineEdit(self.engine.config.get("freshclam_path", ""))
        self.txt_vt = QLineEdit(self.engine.config.get("vt_api_key", ""))
        self.txt_vt.setEchoMode(QLineEdit.Password)
        self.txt_max_fs = QLineEdit(self.engine.config.get("max_filesize", "250M"))
        self.txt_max_ss = QLineEdit(self.engine.config.get("max_scansize", "500M"))

        vt_row = QHBoxLayout()
        vt_row.addWidget(self.txt_vt, 1)
        show_btn = QToolButton()
        show_btn.setText("👁")
        show_btn.setCheckable(True)
        show_btn.toggled.connect(lambda on: self.txt_vt.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password))
        vt_row.addWidget(show_btn)

        self.lbl_clam_path = QLabel()
        self.lbl_fresh_path = QLabel()
        self.lbl_vt_key = QLabel()
        self.lbl_max_fs = QLabel()
        self.lbl_max_ss = QLabel()

        s.addWidget(self.lbl_clam_path, 0, 0)
        s.addWidget(self.txt_clam, 0, 1, 1, 2)
        s.addWidget(self.lbl_fresh_path, 1, 0)
        s.addWidget(self.txt_fresh, 1, 1, 1, 2)
        s.addWidget(self.lbl_vt_key, 2, 0)
        s.addLayout(vt_row, 2, 1, 1, 2)
        s.addWidget(self.lbl_max_fs, 3, 0)
        s.addWidget(self.txt_max_fs, 3, 1, 1, 2)
        s.addWidget(self.lbl_max_ss, 4, 0)
        s.addWidget(self.txt_max_ss, 4, 1, 1, 2)

        self.chk_sounds = QCheckBox()
        self.chk_sounds.setChecked(self._sounds)
        s.addWidget(self.chk_sounds, 5, 0, 1, 3)

        self.btn_save_set = QPushButton()
        self.btn_save_set.setObjectName("PrimaryScanBtn")
        self.btn_save_set.clicked.connect(self._save_settings)
        s.addWidget(self.btn_save_set, 6, 0, 1, 3, Qt.AlignLeft)
        scroll.setWidget(inner)
        outer.addWidget(scroll)
        outer.addStretch()
        return page

    def _switch_page(self, index):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.setProperty("active", i == index)
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def _pick_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Select Folder")
        if d:
            self.target_input.setText(d)

    def _pick_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select File")
        if f:
            self.target_input.setText(f)

    def _trigger_update_defs(self):
        self._start_all_task_progress("Updating ClamAV definitions via freshclam...")
        self.update_defs_requested.emit()

    def _trigger_full_scan(self):
        self._start_all_task_progress("Starting full disk scan...")
        self.full_scan_requested.emit()

    def _run_selected_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self._toast("Please select a target file or folder", "warning")
            return
        opts = {
            "recursive": self.chk_rec.isChecked(),
            "infected": self.chk_inf.isChecked(),
            "archive": self.chk_arc.isChecked(),
            "quarantine": self.chk_quar.isChecked()
        }
        is_clam = self.rb_clam.isChecked()
        mode_lbl = "ClamAV Scan" if is_clam else "VirusTotal Check"
        self.btn_run_scan.set_busy(True, "Scanning")
        self.hero_scan_btn.set_busy(True, "Scanning")
        self._scan_busy = True
        self._scan_completed_notified = False
        self._start_all_task_progress(f"{mode_lbl}: {target}")
        self.scan_requested.emit(target, is_clam, opts)

    def start_scan_polling(self):
        if self._scan_poll:
            self._scan_poll.stop()
        self._scan_poll = QTimer(self)
        self._scan_poll.timeout.connect(self._check_scan_done)
        self._scan_poll.start(500)

    def _mark_scan_finished_once(self, msg: str, ok: bool = True):
        if self._scan_poll:
            try:
                self._scan_poll.stop()
            except Exception:
                pass
            self._scan_poll = None
        self.btn_run_scan.set_busy(False)
        self.hero_scan_btn.set_busy(False)
        self._scan_busy = False
        if not self._scan_completed_notified:
            self._scan_completed_notified = True
            self._finish_all_task_progress(msg, success=ok)
            self._toast(msg, "success" if ok else "warning")

    def _check_scan_done(self):
        if not self.engine.is_busy:
            self._mark_scan_finished_once("Scan finished", ok=True)

    def _on_scan_finished(self, msg, ok=True):
        self._mark_scan_finished_once(msg, ok=bool(ok))

    def _start_status_bar_task(self, detail: str = "Scanning..."):
        if hasattr(self, "_status_task"):
            self._status_task.setText(f"⏳ 0% | ETA: --:-- | {detail}")
            self._status_task.show()

    def _update_status_bar_task(self, pct: int, current: int = 0, total: int = 0, eta_text: str = "--:--", detail: str = ""):
        if not hasattr(self, "_status_task"):
            return
        pct = max(0, min(100, int(pct)))
        count_part = f" ({current}/{total})" if total > 0 else ""
        short_detail = f" — {detail}" if detail else ""
        self._status_task.setText(f"⏳ {pct}%{count_part} | ETA: {eta_text}{short_detail}")
        self._status_task.show()

    def _finish_status_bar_task(self, detail: str = "Done", hold_ms: int = 4000):
        if not hasattr(self, "_status_task"):
            return
        self._status_task.setText(f"✅ {detail}")
        self._status_task.show()
        QTimer.singleShot(hold_ms, self._clear_status_bar_task)

    def _clear_status_bar_task(self):
        if hasattr(self, "_status_task") and not self._scan_busy:
            self._status_task.setText("")
            self._status_task.hide()

    def _start_all_task_progress(self, detail: str):
        for blk in getattr(self, "_progress_blocks", []):
            blk.start_task(detail)
        self._start_status_bar_task(detail)

    def _update_all_task_progress(self, pct: int, current: int = 0, total: int = 0, detail: str = ""):
        eta_text = "--:--"
        for blk in getattr(self, "_progress_blocks", []):
            blk.update_progress(pct, current, total, detail or None)
            computed = blk.compute_eta_text(pct)
            if computed != "--:--":
                eta_text = computed
        self._update_status_bar_task(pct, current, total, eta_text, detail)

    def _finish_all_task_progress(self, detail: str, success: bool = True):
        for blk in getattr(self, "_progress_blocks", []):
            blk.finish_task(detail, success=success)
        self._finish_status_bar_task(detail if success else f"Stopped: {detail}")

    def _update_progress_ui(self, pct, current, total, detail=""):
        self._update_all_task_progress(pct, current, total, detail)

    def _poll_stats(self):
        tr = TRANS["ar"] if self._rtl else TRANS["en"]
        st = self.engine.stats
        quar_count = self.quar_list.count() if hasattr(self, "quar_list") else 0
        has_threats = st.get("threats_blocked", 0) > 0 or quar_count > 0

        self.scanned_lbl.setText(f"{tr['scanned_files']} {st['total_scanned']}")
        self.threats_lbl.setText(f"{tr['threats_blocked']} {st['threats_blocked']}")
        self.update_lbl.setText(f"{tr['defs']} {st['last_update']}")
        self._status_defs.setText(f"📅 {tr['defs']} {st['last_update']}")

        self.shield_widget.set_alert(has_threats)
        self._refresh_tray_icon(has_threats)
        self.hero_status_lbl.setText(tr["alert_state"] if has_threats else tr["protected"])
        self.hero_sub_lbl.setText(tr["alert_sub"] if has_threats else tr["protected_sub"])

        if self.engine.realtime_active:
            self.right_shield_status.setText(tr["shield_on"])
            self.right_shield_status.setObjectName("SuccessText")
            self.toggle_shield_btn.setText(tr["disable_shield"])
            self._status_shield.setText(tr["shield_active"])
            self.qc_shield.lbl_sub.setText(tr["shield_on"])
        else:
            self.right_shield_status.setText(tr["shield_off"])
            self.right_shield_status.setObjectName("DangerText")
            self.toggle_shield_btn.setText(tr["enable_shield"])
            self._status_shield.setText(tr["shield_off_stat"])
            self.qc_shield.lbl_sub.setText(tr["shield_off"])

        self.qc_defs.lbl_sub.setText(st["last_update"])
        self.qc_quar.lbl_sub.setText(f"{quar_count} {'ملف' if self._rtl else 'files'}")

        self.right_shield_status.style().unpolish(self.right_shield_status)
        self.right_shield_status.style().polish(self.right_shield_status)

        perf = self.engine.get_system_performance()
        self.cpu_bar.setValue(min(100, max(0, int(round(perf["cpu"])))))
        self.cpu_lbl.setText(f"CPU: {perf['cpu']}%")
        self.ram_bar.setValue(min(100, max(0, int(round(perf["ram_pct"])))))
        self.ram_lbl.setText(f"RAM: {perf['ram_text']}")
        self.gpu_lbl.setText(f"GPU: {perf['gpu_text']}")

    def _refresh_boot_status(self):
        tr = TRANS["ar"] if self._rtl else TRANS["en"]
        if self.engine.is_boot_scan_scheduled():
            self.right_boot_status.setText(tr["boot_sched"])
            self.right_boot_status.setObjectName("SuccessText")
            self.page_boot_status.setText(tr["status_sched"])
        else:
            self.right_boot_status.setText(tr["boot_disabled"])
            self.right_boot_status.setObjectName("DangerText")
            self.page_boot_status.setText(tr["status_not_sched"])
        self.right_boot_status.style().unpolish(self.right_boot_status)
        self.right_boot_status.style().polish(self.right_boot_status)

    def _run_startup_scan(self):
        self._start_all_task_progress("Scanning Windows startup items...")
        self.engine.scan_startup_items(
            auto_quarantine=self.chk_startup_quar.isChecked(),
            on_complete=lambda total, threats: (
                self._finish_all_task_progress(f"Startup scan: {total} items, {threats} threats", success=True),
                self.bridge.popup_signal.emit("Startup Scan", f"Inspected {total} items, threats: {threats}")
            ),
        )

    def _schedule_boot(self):
        target = self.target_input.text().strip() or "C:\\"
        ok = self.engine.schedule_boot_scan(target)
        self._refresh_boot_status()
        self._toast("Boot scan scheduled" if ok else "Failed to schedule boot scan", "success" if ok else "error")

    def _disable_boot(self):
        ok = self.engine.remove_boot_scan()
        self._refresh_boot_status()
        self._toast("Boot scan disabled" if ok else "Failed to disable boot scan", "warning" if ok else "error")

    def _run_memory_scan(self):
        self._start_all_task_progress("Scanning active memory processes...")
        self.engine.scan_running_processes(
            auto_quarantine=self.chk_mem_quar.isChecked(),
            on_complete=lambda total, threats: (
                self._finish_all_task_progress(f"Memory scan: {total} processes, {threats} threats", success=True),
                self.bridge.popup_signal.emit("Memory Scan", f"Inspected {total} processes, threats: {threats}")
            ),
        )

    def _add_excl_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Exclude Folder")
        if d:
            self.engine.add_exclusion(d)
            self.engine.clear_threat_for_target(d)
            self.refresh_exclusions(self.engine.config.get("exclusions", []))
            self.exclusions_changed.emit()
            self._poll_stats()
            self._toast("Folder excluded", "success")

    def _add_excl_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Exclude File")
        if f:
            self.engine.add_exclusion(f)
            self.engine.clear_threat_for_target(f)
            self.refresh_exclusions(self.engine.config.get("exclusions", []))
            self.exclusions_changed.emit()
            self._poll_stats()
            self._toast("File excluded", "success")

    def _remove_excl(self):
        item = self.excl_list.currentItem()
        if item:
            self.engine.remove_exclusion(item.text())
            self.refresh_exclusions(self.engine.config.get("exclusions", []))
            self.exclusions_changed.emit()
            self._toast("Exclusion removed", "info")

    def _resolve_quarantine_origin_path(self, item_name: str) -> str:
        meta = getattr(self.engine, "quarantine_meta", None)
        if isinstance(meta, dict):
            entry = meta.get(item_name)
            if isinstance(entry, dict) and entry.get("original_path"):
                return str(entry["original_path"])
            if isinstance(entry, str) and entry:
                return entry

        manifest_path = os.path.join(self.engine.quarantine_dir, "manifest.json")
        if os.path.isfile(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and data.get(item_name):
                    val = data[item_name]
                    return str(val.get("original_path", val) if isinstance(val, dict) else val)
            except Exception:
                pass
        return ""

    def _show_quarantine_details(self):
        item = self.quar_list.currentItem()
        if not item:
            self._toast("Select a quarantined file first", "warning")
            return
        fname = item.text().strip()
        meta = self.engine.quarantine_meta.get(fname, {}) if isinstance(self.engine.quarantine_meta, dict) else {}
        orig = meta.get("original_path", "Unknown") if isinstance(meta, dict) else str(meta)
        sig = meta.get("signature", "Unknown") if isinstance(meta, dict) else "Unknown"
        q_at = meta.get("quarantined_at", "Unknown") if isinstance(meta, dict) else "Unknown"
        dlg = ConfirmDialog(
            self,
            "Quarantine Item Details",
            f"File: {fname}\nSignature: {sig}\nQuarantined: {q_at}\nOriginal Path: {orig}",
            confirm_text="Close",
            cancel_text="Close",
            danger=False,
        )
        dlg.exec()

    def _open_incidents_dialog(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Recent Security Incidents")
        dlg.resize(740, 440)
        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(10)

        top = QHBoxLayout()
        flt = QComboBox()
        flt.addItems(["ALL", "THREAT", "CLEAN"])
        inc_list = QListWidget()
        top.addWidget(QLabel("Filter:"))
        top.addWidget(flt)
        top.addStretch()
        lay.addLayout(top)
        lay.addWidget(inc_list, 1)

        def reload_rows():
            inc_list.clear()
            mode = flt.currentText()
            for inc in reversed(list(self.engine.incident_history)):
                st = inc.get("status", "")
                if mode != "ALL" and st != mode:
                    continue
                inc_list.addItem(
                    f"[{inc.get('timestamp', '')}] [{st}] {inc.get('source', '')} -> {inc.get('target', '')} ({inc.get('details', '')})"
                )

        flt.currentTextChanged.connect(lambda _: reload_rows())
        reload_rows()

        btn_row = QHBoxLayout()
        btn_excl = QPushButton("🛡️ Exclude Selected Target")
        btn_excl.setObjectName("ActionBtn")

        def exclude_selected():
            cur = inc_list.currentItem()
            if not cur:
                return
            txt = cur.text()
            if "->" in txt and "(" in txt:
                target = txt.split("->", 1)[1].rsplit("(", 1)[0].strip()
                if target:
                    self.engine.add_exclusion(target)
                    self.engine.clear_threat_for_target(target)
                    self.refresh_exclusions(self.engine.config.get("exclusions", []))
                    self.exclusions_changed.emit()
                    self._poll_stats()
                    reload_rows()
                    self._toast(f"Excluded & cleared: {target}", "success")

        btn_excl.clicked.connect(exclude_selected)
        btn_close = QPushButton("Close")
        btn_close.setObjectName("ActionBtn")
        btn_close.clicked.connect(dlg.accept)
        btn_row.addWidget(btn_excl)
        btn_row.addStretch()
        btn_row.addWidget(btn_close)
        lay.addLayout(btn_row)
        dlg.exec()

    def _trust_and_exclude_quar(self):
        item = self.quar_list.currentItem()
        if not item:
            self._toast("Select a quarantined file first", "warning")
            return

        item_name = item.text().strip()
        origin_path = self._resolve_quarantine_origin_path(item_name)

        if not origin_path:
            dlg = ConfirmDialog(
                self,
                "Select Path to Exclude",
                "Original path wasn't recorded in vault metadata. Choose the folder (recommended for false positives like NVIDIA App) or file to exclude.",
                confirm_text="Pick Folder",
                danger=False,
            )
            if dlg.exec() == QDialog.Accepted:
                origin_path = QFileDialog.getExistingDirectory(self, "Select Folder to Exclude")
            else:
                origin_path, _ = QFileDialog.getOpenFileName(self, "Select File to Exclude")

        if not origin_path:
            return

        norm_path = os.path.normpath(origin_path)
        self.engine.add_exclusion(norm_path)
        self.engine.clear_threat_for_target(norm_path)
        self.engine.clear_threat_for_target(item_name)
        self.refresh_exclusions(self.engine.config.get("exclusions", []))
        self.exclusions_changed.emit()
        self.quarantine_action.emit("restore", item_name)
        self._poll_stats()
        self._toast(f"Excluded & restoring: {item_name}", "success")

    def _copy_quar_sha256(self):
        item = self.quar_list.currentItem()
        if not item:
            self._toast("Select a quarantined file first", "warning")
            return
        fpath = os.path.join(self.engine.quarantine_dir, item.text())
        digest = self.engine.get_file_sha256(fpath)
        if digest:
            QApplication.clipboard().setText(digest)
            self._toast("SHA-256 copied to clipboard", "success")
        else:
            self._toast("Unable to read quarantined file", "error")

    def _export_report(self, fmt):
        out_path = self.engine.export_report(fmt)
        self._toast(f"Report exported: {os.path.basename(out_path)}", "success")

    def _export_settings_file(self):
        out_path, _ = QFileDialog.getSaveFileName(self, "Export Settings", "r_antivirus_settings.json", "JSON Files (*.json)")
        if out_path:
            try:
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(self.engine.config, f, indent=2, ensure_ascii=False)
                self._toast("Settings exported", "success")
            except Exception as e:
                self._toast(f"Export failed: {e}", "error")

    def _import_settings_file(self):
        in_path, _ = QFileDialog.getOpenFileName(self, "Import Settings", "", "JSON Files (*.json)")
        if in_path and os.path.isfile(in_path):
            try:
                with open(in_path, "r", encoding="utf-8") as f:
                    imported = json.load(f)
                if isinstance(imported, dict):
                    self.engine.config.update(imported)
                    self.engine.save_config()
                    self.txt_clam.setText(self.engine.config.get("clamscan_path", ""))
                    self.txt_fresh.setText(self.engine.config.get("freshclam_path", ""))
                    self.txt_vt.setText(self.engine.config.get("vt_api_key", ""))
                    self.txt_max_fs.setText(self.engine.config.get("max_filesize", "250M"))
                    self.txt_max_ss.setText(self.engine.config.get("max_scansize", "500M"))
                    self.refresh_exclusions(self.engine.config.get("exclusions", []))
                    self._toast("Settings imported successfully", "success")
            except Exception as e:
                self._toast(f"Import failed: {e}", "error")

    def _toggle_shield(self):
        if not self.engine.realtime_active:
            folder = str(self.engine.config.get("shield_target", "")).strip() or self.txt_sched_target.text().strip()
            if not os.path.isdir(folder):
                folder = QFileDialog.getExistingDirectory(self, "Select Folder for Real-Time Shield")
                if not folder:
                    self._toast("Choose a valid folder for Real-Time Shield", "warning")
                    return
                self.engine.config["shield_target"] = os.path.abspath(folder)
                self.engine.save_config()
            self.engine.start_realtime(folder, auto_quarantine=True)
            self._toast(f"Shield enabled for: {os.path.basename(folder)}", "success")
        else:
            self.engine.stop_realtime()
            self._toast("Shield disabled", "info")

    def _save_schedule(self):
        target_val = self.txt_sched_target.text().strip()
        data = {
            "enabled": self.chk_sched_en.isChecked(),
            "frequency": self.cmb_freq.currentText(),
            "time": self.txt_sched_time.text().strip(),
            "target": target_val
        }
        if target_val and not str(self.engine.config.get("shield_target", "")).strip():
            self.engine.config["shield_target"] = target_val
        self.schedule_saved.emit(data)

    def _save_settings(self):
        data = {
            "clamscan_path": self.txt_clam.text().strip(),
            "freshclam_path": self.txt_fresh.text().strip(),
            "vt_api_key": self.txt_vt.text().strip(),
            "max_filesize": self.txt_max_fs.text().strip(),
            "max_scansize": self.txt_max_ss.text().strip()
        }
        self._sounds = self.chk_sounds.isChecked()
        if "ui" not in self.engine.config or not isinstance(self.engine.config["ui"], dict):
            self.engine.config["ui"] = {}
        self.engine.config["ui"]["sounds"] = self._sounds
        self.settings_saved.emit(data)

    def refresh_exclusions(self, items):
        self.excl_widget.set_items(items)

    def refresh_quarantine(self):
        items = []
        if os.path.isdir(self.engine.quarantine_dir):
            items = sorted(
                f for f in os.listdir(self.engine.quarantine_dir)
                if f != "manifest.json" and os.path.isfile(os.path.join(self.engine.quarantine_dir, f))
            )
        self.quar_widget.set_items(items)
        if hasattr(self, "nav_buttons"):
            self._update_texts()

    def _emit_quar_action(self, action):
        tr = TRANS["ar"] if self._rtl else TRANS["en"]
        item = self.quar_list.currentItem()
        if item:
            fname = item.text()
            if action == "delete":
                dlg = ConfirmDialog(
                    self,
                    tr["del_quar_title"],
                    tr["del_quar_msg"].format(name=fname),
                    confirm_text=tr["del_quar_ok"],
                    cancel_text=tr["cancel"],
                    danger=True,
                )
                if dlg.exec() != QDialog.Accepted:
                    return
            self.quarantine_action.emit(action, fname)
            self._poll_stats()

    def _reposition_toasts(self):
        valid_toasts = []
        y_pos = 56
        max_y = max(70, self.height() - 90)
        for t in self._toast_stack:
            if t is not None:
                try:
                    if shiboken6.isValid(t):
                        t.setFixedWidth(min(440, max(300, self.width() - 100)))
                        x_pos = max(10, (self.width() - t.width()) // 2)
                        if y_pos + t.height() > max_y:
                            t.hide()
                            t.deleteLater()
                            continue
                        t.move(x_pos, y_pos)
                        y_pos += t.height() + 8
                        valid_toasts.append(t)
                except Exception:
                    pass
        self._toast_stack = valid_toasts

    def _toast(self, message, kind="info"):
        self._reposition_toasts()
        toast = Toast(self, message, kind)
        x_pos = max(10, (self.width() - toast.width()) // 2)
        y_pos = 56
        for t in self._toast_stack:
            if t.isVisible():
                y_pos += t.height() + 8
        if y_pos + toast.height() > max(70, self.height() - 90):
            y_pos = 56
        toast.move(x_pos, y_pos)
        self._toast_stack.append(toast)

    def _append_log(self, msg, tag=""):
        sb = self.console_box.verticalScrollBar()
        at_bottom = sb.value() >= (sb.maximum() - 4)
        prev_val = sb.value()

        color = "#e8e2f3" if self._theme == "light" else "#d8c8f0"
        if tag == "threat":
            color = "#ff6b6b"
        elif tag == "ok":
            color = "#69f0ae"
        elif tag == "shield":
            color = "#64b5f6"
        elif tag == "vt":
            color = "#ea80fc"

        self.console_box.append(f'<span style="color:{color};">{msg}</span>')

        doc = self.console_box.document()
        if doc.blockCount() > 2000:
            cursor = self.console_box.textCursor()
            cursor.movePosition(cursor.Start)
            cursor.select(cursor.BlockUnderCursor)
            cursor.removeSelectedText()
            cursor.deleteChar()

        if at_bottom:
            sb.setValue(sb.maximum())
        else:
            sb.setValue(prev_val)

    def showEvent(self, event):
        super().showEvent(event)
        self._sync_maximized_state()
        QTimer.singleShot(80, self._apply_native_styles)

    def _apply_native_styles(self):
        try:
            hwnd = int(self.winId())
            import ctypes
            val = ctypes.c_int(1 if self._theme == "dark" else 0)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                ctypes.c_void_p(hwnd), 20, ctypes.byref(val), ctypes.sizeof(val)
            )
        except Exception:
            pass
