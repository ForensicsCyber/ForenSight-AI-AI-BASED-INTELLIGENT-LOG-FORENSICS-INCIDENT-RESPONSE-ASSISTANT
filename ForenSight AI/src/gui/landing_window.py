from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QProgressBar,
    QFileDialog, QMessageBox, QGraphicsDropShadowEffect, QApplication
)
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation
from PyQt5.QtGui import QPixmap, QColor
import os
from src.utils.log_classifier import LogClassifier


class LandingWindow(QWidget):

    def __init__(self):
        super().__init__()
        self.selected_files = {}
        self.classifier = LogClassifier()

        self.supported_types = {"apache", "linux", "openssh", "hdfs", "firewall"}
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("FORENSIGHT AI")
        self.setFixedSize(1600, 850)

        # =====================================================
        # SAFE PATH FOR LOGO (WORKS FROM ANY DIRECTORY)
        # =====================================================
        BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
        logo_path = os.path.join(BASE_DIR, "assets", "logo.png")

        # =====================================================
        # BACKGROUND (MATCH DASHBOARD STYLE)
        # =====================================================
        self.setStyleSheet("background-color: #020617;")

        self.bg_overlay = QLabel(self)
        self.bg_overlay.setGeometry(0, 0, self.width(), self.height())
        self.bg_overlay.lower()

        self.bg_colors = ["#0f172a", "#1e293b", "#020617"]
        self.bg_index = 0

        def animate_bg():
            try:
                self.bg_index = (self.bg_index + 1) % len(self.bg_colors)
                color = self.bg_colors[self.bg_index]

                self.bg_overlay.setStyleSheet(f"""
                    background: radial-gradient(circle at center, {color}, #020617);
                """)
            except Exception:
                pass  # prevent UI crash

        self.bg_timer = QTimer()
        self.bg_timer.timeout.connect(animate_bg)
        self.bg_timer.start(2000)

        # =====================================================
        # MAIN LAYOUT
        # =====================================================
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(50, 30, 50, 30)

        # =====================================================
        # CARD CONTAINER
        # =====================================================
        card = QWidget()
        card.setStyleSheet("""
            QWidget {
                background-color: rgba(30, 41, 59, 0.6);
                border-radius: 20px;
            }
        """)

        card_layout = QVBoxLayout()
        card_layout.setSpacing(24)
        card_layout.setContentsMargins(40, 40, 40, 40)

        # =====================================================
        # LOGO WITH GLOW
        # =====================================================
        self.logo = QLabel()
        self.logo.setAlignment(Qt.AlignCenter)

        pixmap = QPixmap(logo_path)
        if not pixmap.isNull():
            self.logo.setPixmap(pixmap.scaled(200, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation))

        logo_glow = QGraphicsDropShadowEffect()
        logo_glow.setBlurRadius(40)
        logo_glow.setColor(QColor(0, 255, 255))
        logo_glow.setOffset(0)
        self.logo.setGraphicsEffect(logo_glow)

        # =====================================================
        # TITLE WITH GLOW
        # =====================================================
        self.app_title = QLabel("ForenSight AI")
        self.app_title.setAlignment(Qt.AlignCenter)
        self.app_title.setStyleSheet("""
            font-size: 38px;
            font-weight: 700;
            color: #22d3ee;
        """)

        title_glow = QGraphicsDropShadowEffect()
        title_glow.setBlurRadius(25)
        title_glow.setColor(QColor(34, 211, 238))
        title_glow.setOffset(0)
        self.app_title.setGraphicsEffect(title_glow)

        # =====================================================
        # DESCRIPTION
        # =====================================================
        self.app_desc = QLabel(
            "AI-Based Intelligent Log Forensics & Incident Response Assistant"
        )
        self.app_desc.setAlignment(Qt.AlignCenter)
        self.app_desc.setStyleSheet("""
            font-size: 14px;
            color: #94a3b8;
        """)

        # =====================================================
        # UPLOAD TITLE
        # =====================================================
        self.upload_label = QLabel("Upload Log Files")
        self.upload_label.setAlignment(Qt.AlignCenter)
        self.upload_label.setStyleSheet("""
            font-size: 26px;
            font-weight: bold;
            color: #00c8ff;
        """)

        # =====================================================
        # SELECT FILE BUTTON
        # =====================================================
        self.upload_btn = QPushButton("📂 Select Log Files")
        self.upload_btn.setStyleSheet("""
            QPushButton {
                background-color: #3b82f6;
                border-radius: 12px;
                padding: 16px;
                font-size: 15px;
                font-weight: 500;
                color: white;
            }
            QPushButton:hover {
                background-color: #60a5fa;
            }
            QPushButton:pressed {
                background-color: #2563eb;
            }
        """)
        self.upload_btn.clicked.connect(self.select_files)

        # =====================================================
        # STATUS TEXT
        # =====================================================
        self.file_status = QLabel("No files selected")
        self.file_status.setAlignment(Qt.AlignCenter)
        self.file_status.setStyleSheet("""
            font-size: 14px;
            color: #dfe6e9;
            padding: 8px;
        """)

        # STATUS MESSAGE (ABOVE BUTTON)
        self.loading_label = QLabel("")
        self.loading_label.setAlignment(Qt.AlignCenter)
        self.loading_label.setStyleSheet("color: #38bdf8; font-size: 14px;")

        # PROGRESS BAR (TOP)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)

        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #334155;
                border-radius: 5px;
                text-align: center;
                background-color: #020617;
                color: white;
            }
            QProgressBar::chunk {
                background-color: #22d3ee;
            }
        """)

        # =====================================================
        # RUN DETECTION BUTTON
        # =====================================================
        self.start_detection_btn = QPushButton("🚀 Run Detection")
        self.start_detection_btn.clicked.connect(self.run_detection)
        self.start_detection_btn.setEnabled(False)
        self.start_detection_btn.setStyleSheet("""
            QPushButton {
                background-color: #22c55e;
                border-radius: 12px;
                padding: 16px;
                font-size: 15px;
                font-weight: 600;
                color: white;
            }
            QPushButton:hover {
                background-color: #4ade80;
            }
            QPushButton:pressed {
                background-color: #16a34a;
            }
        """)

        # =====================================================
        # RESET BUTTON
        # =====================================================
        self.reset_btn = QPushButton("♻️ Reset Environment")
        self.reset_btn.setStyleSheet("""
            QPushButton {
                background-color: #ef4444;
                border-radius: 10px;
                padding: 12px;
                font-size: 14px;
                color: white;
            }
            QPushButton:hover {
                background-color: #f87171;
            }
        """)
        self.reset_btn.clicked.connect(self.reset_environment)

        # =====================================================
        # ADD TO CARD
        # =====================================================
        card_layout.addWidget(self.logo)
        card_layout.addWidget(self.app_title)
        card_layout.addWidget(self.app_desc)

        card_layout.addSpacing(10)

        card_layout.addWidget(self.upload_label)
        card_layout.addWidget(self.progress_bar)
        card_layout.addWidget(self.loading_label)
        card_layout.addWidget(self.upload_btn)
        card_layout.addWidget(self.file_status)
        card_layout.addWidget(self.start_detection_btn)
        card_layout.addWidget(self.reset_btn)

        card.setLayout(card_layout)

        # =====================================================
        # CARD SHADOW
        # =====================================================
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(60)
        shadow.setYOffset(20)
        shadow.setColor(QColor(0, 200, 255, 80))
        card.setGraphicsEffect(shadow)

        # =====================================================
        # FADE-IN ANIMATION
        # =====================================================
        self.fade_anim = QPropertyAnimation(card, b"windowOpacity")
        self.fade_anim.setDuration(800)
        self.fade_anim.setStartValue(0)
        self.fade_anim.setEndValue(1)
        self.fade_anim.start()

        layout.addStretch()
        layout.addWidget(card, alignment=Qt.AlignCenter)
        layout.addStretch()

        self.setLayout(layout)

    
    def detect_log_type(self, file_path):
        """
        Smart log classifier based on content.
        Returns: apache | linux | openssh | hdfs | firewall | unknown
        """
        try:
            with open(file_path, "r", errors="ignore") as f:
                sample = f.read(2000).lower()

            # -------------------------
            # APACHE LOGS
            # -------------------------
            if "get /" in sample or "post /" in sample or "http/1." in sample:
                return "apache"

            # -------------------------
            # OPENSSH LOGS
            # -------------------------
            if "sshd" in sample or "failed password" in sample:
                return "openssh"

            # -------------------------
            # LINUX LOGS
            # -------------------------
            if "sudo" in sample or "cron" in sample or "session opened" in sample:
                return "linux"

            # -------------------------
            # HDFS LOGS
            # -------------------------
            if "dfsclient" in sample or "namenode" in sample or "block" in sample:
                return "hdfs"

            # -------------------------
            # FIREWALL LOGS (CSV style)
            # -------------------------
            if "," in sample and ("src_ip" in sample or "dst_ip" in sample):
                return "firewall"

            return "unknown"

        except Exception:
            return "unknown"

    # =====================================================
    # FUNCTIONALITY
    # =====================================================
    def select_files(self):
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Log Files",
            "",
            "Supported Logs (*.log *.txt *.csv);;All Files (*)"
        )

        if files:
            
            file_routes = {}
            unsupported_files = []
            unsupported_parser_files = []

            for file in files:
                log_type = self.classifier.classify(file)

                if log_type == "unknown":
                    unsupported_files.append(file)

                elif log_type not in self.supported_types:
                    unsupported_parser_files.append((file, log_type))

                else:
                    file_routes[file] = log_type

            # -----------------------------
            # HANDLE UNSUPPORTED PARSER TYPES
            # -----------------------------
            if unsupported_parser_files:
                msg = QMessageBox(self)
                msg.setIcon(QMessageBox.Warning)
                msg.setWindowTitle("Unsupported Log Type")

                formatted_files = "<br>".join(
                    f"• {os.path.basename(f)} <span style='color:#38bdf8;'>({log_type.upper()})</span>"
                    for f, log_type in unsupported_parser_files
                )

                msg.setText(
                    "<b>Unsupported Log Type Detected</b><br><br>"
                    "The system successfully identified the following log files, "
                    "but no parser is currently available to process them:<br><br>"
                    f"{formatted_files}<br><br>"
                    "Supported log types include:<br>"
                    "• Apache<br>"
                    "• Linux<br>"
                    "• OpenSSH<br>"
                    "• HDFS<br>"
                    "• Firewall"
                )

                msg.setStyleSheet("""
                    QMessageBox {
                        background-color: #0f172a;
                    }
                    QLabel {
                        color: white;
                        font-size: 13px;
                    }
                    QPushButton {
                        background-color: #3b82f6;
                        color: white;
                        padding: 6px 12px;
                        border-radius: 5px;
                    }
                """)

                msg.exec_()

            # -----------------------------
            # 🚨 BLOCK IF ANY INVALID FILES EXIST
            # -----------------------------
            if unsupported_files or unsupported_parser_files:
                self.selected_files = {}
                self.file_status.setText("Invalid files detected - please review")
                self.start_detection_btn.setEnabled(False)
                return  # 🔥 CRITICAL: STOP execution

            # -----------------------------
            # ✅ ONLY PROCEED IF ALL FILES ARE VALID
            # -----------------------------
            if file_routes:
                self.selected_files = file_routes
                self.file_status.setText(f"{len(file_routes)} valid files selected")
                self.start_detection_btn.setEnabled(True)
            else:
                self.selected_files = {}
                self.file_status.setText("No valid log files selected")
                self.start_detection_btn.setEnabled(False)
                
    def reset_environment(self):
        self.selected_files = []
        self.file_status.setText("No files selected")
        self.start_detection_btn.setEnabled(False)

    def run_detection(self):
        if not self.selected_files:
            QMessageBox.warning(self, "Warning", "Please select log files first.")
            return

        # Disable button
        self.start_detection_btn.setEnabled(False)

        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(10)
        self.loading_label.setText("Loading Dashboard...")
        QApplication.processEvents()

        try:
            # -----------------------------
            # STEP 1: INGEST LOGS
            # -----------------------------
            from src.ingestion.ingest_logs import ingest_logs

            ingest_logs(self.selected_files)

            self.progress_bar.setValue(50)
            QApplication.processEvents()

            # -----------------------------
            # STEP 2: DETECTION ENGINE
            # -----------------------------
            from src.detection.detection_engine import run_detection_engine

            run_detection_engine()

            self.progress_bar.setValue(90)
            QApplication.processEvents()

            # -----------------------------
            # COMPLETE
            # -----------------------------
            self.progress_bar.setValue(100)
            QApplication.processEvents()

            self.loading_label.setText("Opening Dashboard...")

            # OPEN DASHBOARD (CALLBACK)
            if hasattr(self, "open_dashboard_callback"):
                self.open_dashboard_callback()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Processing failed:\n{str(e)}")

        finally:
            self.start_detection_btn.setEnabled(True)