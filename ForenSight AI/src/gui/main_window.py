"""
ForenSight AI - Main Dashboard Window
=====================================

Primary graphical dashboard interface for
ForenSight AI.

Responsibilities
----------------
1. Display SOC dashboard metrics
2. Visualize attack timelines
3. Display IOC intelligence
4. Manage incident filtering
5. Generate forensic reports
6. Coordinate threat intelligence views

GUI Components
--------------
• Dashboard Metrics
• Incident Viewer
• Timeline Panel
• IOC Intelligence Table
• Threat Intelligence Table
• PDF Report Generation

Architecture Notes
------------------
• PyQt5-based desktop interface
• Threaded report generation
• Integrated dashboard analytics
• Designed for SOC-style workflows
"""

import os
import subprocess
import platform

from src.reporting.report_builder import build_report_content
from src.reporting.pdf_generator import generate_pdf_report
from src.ai_engine.ai_engine import run_ai_engine

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTabWidget, QAbstractItemView,
    QTableWidget, QTableWidgetItem, QTextEdit,
    QHeaderView, QApplication,
    QMessageBox, QComboBox
)

from src.ai_engine.ioc_extractor import IOCExtractor
from src.ai_engine.threat_intel import ThreatIntel
from src.gui.dashboard_widget import DashboardWidget
from src.gui.data_loader import load_alerts
from src.gui.dashboard_service import compute_metrics
from src.gui.timeline_service import build_timeline
from src.utils.logger_config import setup_logger
logger = setup_logger()

from PyQt5.QtCore import QThread, pyqtSignal

"""
Background worker thread used for
non-blocking forensic report generation.

Prevents GUI freezing during:
• AI analysis
• PDF generation
• chart rendering
• report assembly
"""

class ReportWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, alerts, iocs, timeline, incidents, threat_intel):
        super().__init__()
        self.alerts = alerts
        self.iocs = iocs
        self.timeline = timeline
        self.incidents = incidents
        self.threat_intel = threat_intel

    def run(self):
        try:
            from src.reporting.report_builder import build_report_content
            from src.reporting.pdf_generator import generate_pdf_report
            from src.ai_engine.ai_engine import run_ai_engine

            detection_results = {
                "alerts": self.alerts,
                "iocs": self.iocs,
                "statistics": {}
            }

            ai_results = run_ai_engine(self.alerts)

            report_data = build_report_content(
                detection_results,
                ai_results
            )

            report_data["timeline"] = self.timeline
            report_data["incidents"] = self.incidents
            report_data["threat_intel"] = self.threat_intel

            output_path = generate_pdf_report(report_data)

            self.finished.emit(output_path)

        except Exception as e:
            self.error.emit(str(e))

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("FORENSIGHT AI")
        self.setFixedSize(1600, 850)

        self.threat_intel = ThreatIntel()

        self.init_ui()
        self.apply_dark_theme()

    # -----------------------------
    # UI SETUP
    # -----------------------------
    def init_ui(self):

        main_widget = QWidget()
        main_layout = QVBoxLayout()

        top_bar = QHBoxLayout()

        self.run_button = QPushButton("🔍 Run Analysis")
        self.run_button.clicked.connect(self.run_analysis)

        self.filter_dropdown = QComboBox()
        self.filter_dropdown.addItem("All Attacks")
        self.filter_dropdown.currentTextChanged.connect(self.apply_filter)

        self.severity_label = QLabel("Overall Severity: N/A")
        self.severity_label.setStyleSheet("""
            font-size: 16px;
            font-weight: bold;
            color: #00cec9;
        """)

        self.status_label = QLabel("Status: Idle")
        self.status_label.setStyleSheet("""
            font-size: 15px;
            font-weight: 500;
            color: #dfe6e9;
        """)

        top_bar.addWidget(self.run_button)
        top_bar.addWidget(self.filter_dropdown)

        # -----------------------------
        # Generate Report Button
        # -----------------------------
        self.generate_report_btn = QPushButton("📄 Generate Report")

        self.generate_report_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                border-radius: 6px;
                padding: 6px 12px;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ecc71;
            }
        """)

        self.generate_report_btn.setVisible(False)  # hidden initially
        self.generate_report_btn.setEnabled(False)
        self.generate_report_btn.clicked.connect(self.generate_report)

        top_bar.addWidget(self.generate_report_btn)
        from PyQt5.QtWidgets import QProgressBar

        self.report_progress = QProgressBar()
        self.report_progress.setMaximum(100)
        self.report_progress.setValue(0)
        self.report_progress.setVisible(False)

        self.report_progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #444;
                border-radius: 5px;
                text-align: center;
                background-color: #1e1e2e;
                color: white;
                min-width: 180px;
                max-width: 250px;
            }
            QProgressBar::chunk {
                background-color: #00c8ff;
                border-radius: 5px;
            }
        """)

        top_bar.addWidget(self.report_progress)
        top_bar.addStretch()
        top_bar.addWidget(self.severity_label)
        top_bar.addWidget(self.status_label)

        main_layout.addLayout(top_bar)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setTabPosition(QTabWidget.North)

        self.dashboard = DashboardWidget()
        self.tabs.addTab(self.dashboard, "SOC Dashboard")

        self.incident_table = self.create_table(["Severity", "Type", "Description"])
        self.incident_table.cellClicked.connect(self.show_incident_details)
        self.tabs.addTab(self.incident_table, "Incidents")

        self.timeline_tab = QTextEdit()
        self.timeline_tab.setReadOnly(True)
        self.tabs.addTab(self.timeline_tab, "Timeline")

        self.ioc_table = self.create_table(["IOC Type", "Value", "Username"])
        self.ioc_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tabs.addTab(self.ioc_table, "IOCs")

        self.threat_table = self.create_table(["IP", "Country", "Threat Score"])
        self.threat_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tabs.addTab(self.threat_table, "Threat Intel")

        main_layout.addWidget(self.tabs)

        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

    def create_table(self, headers):
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        return table

    # -----------------------------
    # THEME
    # -----------------------------
    def apply_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #1e1e2e; color: white; }

            QPushButton {
                background-color: #3a7bd5;
                border-radius: 6px;
                padding: 6px 12px;
                color: white;
                font-weight: bold;
            }

            QTabBar::tab {
                background: #2a2a3c;
                padding: 8px;
                color: white;
            }

            QTabBar::tab:selected {
                background: #3a7bd5;
            }

            QTableWidget {
                background-color: #2a2a3c;
                color: white;
            }

            QTextEdit {
                background-color: #2a2a3c;
                color: white;
            }

            QComboBox {
                background-color: #2a2a3c;
                color: white;
            }
        """)
    
    # ---------------------------------------------------------
    # Detection Analysis Workflow
    # ---------------------------------------------------------
    """
    Load detection alerts and populate all
    dashboard visualizations.

    Responsibilities
    ----------------
    1. Load alerts from database
    2. Calculate severity metrics
    3. Generate forensic timeline
    4. Populate IOC intelligence
    5. Update dashboard widgets
    6. Populate threat intelligence
    """

    def run_analysis(self):
        logger.info("Analysis started")

        self.status_label.setText("Status: Running...")
        QApplication.processEvents()

        alerts = load_alerts()

        # Store alerts globally for report
        self.current_alerts = alerts

        if not alerts:
            self.status_label.setText("Status: No Data")
            return

        # -----------------------------
        # Severity Classification
        # -----------------------------
        severity_levels = ["low", "medium", "high", "critical"]
        detected = [a.get("severity", "low").lower() for a in alerts]

        highest = "low"
        for level in severity_levels:
            if level in detected:
                highest = level

        self.severity_label.setText(f"Overall Severity: {highest.upper()}")

        color_map = {
            "critical": "#e84142",
            "high": "#e67e22",
            "medium": "#f1c40f",
            "low": "#2ecc71"
        }

        self.severity_label.setStyleSheet(f"""
            font-size:16px;
            font-weight:bold;
            color:{color_map.get(highest)}
        """)

        # -----------------------------
        # Dashboard Metrics
        # -----------------------------
        metrics = compute_metrics(alerts)
        metrics.setdefault("critical", 0)
        metrics.setdefault("high", 0)
        metrics.setdefault("medium", 0)
        metrics.setdefault("low", 0)
        metrics.setdefault("total", len(alerts))
        metrics.setdefault("top_ip", "N/A")

        # ---------------------------------------------------------
        # Timeline Generation
        # ---------------------------------------------------------
        timeline = build_timeline(alerts)
        self.current_timeline = timeline
        for i, event in enumerate(timeline):
            if "severity" not in event:
                event["severity"] = alerts[i].get("severity", "LOW")

        # -----------------------------
        # IOC Extraction
        # -----------------------------
        iocs = IOCExtractor().extract(alerts)

        self.current_iocs = iocs

        # -----------------------------
        # Attack Filter Population
        # -----------------------------
        self.filter_dropdown.blockSignals(True)
        self.filter_dropdown.clear()
        self.filter_dropdown.addItem("All Attacks")

        attack_types = sorted(set(a.get("type", "Unknown") for a in alerts))
        for attack in attack_types:
            self.filter_dropdown.addItem(attack)

        self.filter_dropdown.blockSignals(False)

        # -----------------------------
        # Dashboard Update
        # -----------------------------
        self.dashboard.update_dashboard(metrics, timeline)

        # ---------------------------------------------------------
        # Attack Distribution Visualization
        # ---------------------------------------------------------
        self.dashboard.plot_attack_pie_chart(alerts)

        # -----------------------------
        # Incidents Table
        # -----------------------------
        self.incident_table.setRowCount(len(alerts))
        for row, alert in enumerate(alerts):
            self.incident_table.setItem(row, 0, QTableWidgetItem(alert.get("severity", "").upper()))
            self.incident_table.setItem(row, 1, QTableWidgetItem(alert.get("type", "")))
            self.incident_table.setItem(row, 2, QTableWidgetItem(alert.get("details", "")))

        # -----------------------------
        # Timeline Text
        # -----------------------------
        self.timeline_tab.clear()
        for event in timeline:
            self.timeline_tab.append(
                f"{event.get('time')} → {event.get('event')} ({event.get('severity')})"
            )

        # -----------------------------
        # IOC Table
        # -----------------------------
        self.ioc_table.setRowCount(0)

        # ---------------------------------------------------------
        # Build IP-to-Username Mapping
        # ---------------------------------------------------------
        ip_user_map = {}

        for alert in alerts:

            ip = alert.get("source_ip")
            username = alert.get("username")

            if ip and username:
                ip_user_map[ip] = username

        for key, values in iocs.items():

            for value in values:

                row = self.ioc_table.rowCount()
                self.ioc_table.insertRow(row)

                self.ioc_table.setItem(
                    row,
                    0,
                    QTableWidgetItem(key)
                )

                self.ioc_table.setItem(
                    row,
                    1,
                    QTableWidgetItem(str(value))
                )

                # ---------------------------------------------------------
                # IOC Username Correlation
                # ---------------------------------------------------------

                username = "N/A"

                if key in ["ips", "attacker_ips"]:
                    username = ip_user_map.get(value, "N/A")

                self.ioc_table.setItem(
                    row,
                    2,
                    QTableWidgetItem(username)
                )

        # -----------------------------
        # Threat Intel Table
        # -----------------------------
        self.threat_table.setRowCount(0)
        ips = iocs.get("ips", []) or iocs.get("attacker_ips", [])

        for ip in ips:
            intel = self.threat_intel.enrich_ip(ip)

            row = self.threat_table.rowCount()
            self.threat_table.insertRow(row)

            self.threat_table.setItem(row, 0, QTableWidgetItem(ip))
            self.threat_table.setItem(row, 1, QTableWidgetItem(intel.get("country", "Unknown")))
            self.threat_table.setItem(row, 2, QTableWidgetItem(intel.get("threat_score", "UNKNOWN")))

        self.status_label.setText("Status: Complete")

        # ---------------------------------------------------------
        # Persist Current Session Data
        # ---------------------------------------------------------
        self.current_incidents = self.current_alerts

        self.current_threat_intel = []

        for ip in ips:
            intel = self.threat_intel.enrich_ip(ip)
            self.current_threat_intel.append(intel)

        # Show report button
        self.generate_report_btn.setVisible(True)
        self.generate_report_btn.setEnabled(True)

        logger.info("Analysis completed") 

    # -----------------------------
    # INCIDENT CLICK
    # -----------------------------
    def show_incident_details(self, row, column):

        severity = self.incident_table.item(row, 0).text()
        attack_type = self.incident_table.item(row, 1).text()
        description = self.incident_table.item(row, 2).text()

        QMessageBox.information(
            self,
            "Incident Details",
            f"Type: {attack_type}\n\n"
            f"Severity: {severity}\n\n"
            f"Description:\n{description}"
        )

    # -----------------------------
    # FILTER
    # -----------------------------
    def apply_filter(self):

        selected = self.filter_dropdown.currentText()

        for row in range(self.incident_table.rowCount()):
            item = self.incident_table.item(row, 1)

            if selected == "All Attacks":
                self.incident_table.setRowHidden(row, False)
            else:
                self.incident_table.setRowHidden(
                    row,
                    selected.lower() not in item.text().lower()
                )

    """
    Generate forensic investigation report.

    The report generation workflow executes
    inside a background worker thread to prevent
    GUI freezing during PDF generation.
    """

    def generate_report(self):

        if not hasattr(self, "current_alerts"):
            QMessageBox.warning(
                self,
                "Warning",
                "Please run analysis before generating report."
            )
            return

        self.report_progress.setVisible(True)
        self.report_progress.setValue(10)

        self.generate_report_btn.setEnabled(False)
        self.status_label.setText("Status: Generating Report...")

        self.worker = ReportWorker(
            self.current_alerts,
            self.current_iocs,
            getattr(self, "current_timeline", []),
            getattr(self, "current_incidents", []),
            getattr(self, "current_threat_intel", [])
        )

        self.worker.finished.connect(self.on_report_finished)
        self.worker.error.connect(self.on_report_error)

        self.worker.start()

    def on_report_finished(self, output_path):
        
        system = platform.system()

        if system == "Windows":
            os.startfile(output_path)
        elif system == "Darwin":
            subprocess.run(["open", output_path])
        elif system == "Linux":
            subprocess.run(["xdg-open", output_path])

        self.report_progress.setValue(100)
        self.status_label.setText("Status: Report Ready")
        self.generate_report_btn.setEnabled(True)

        QMessageBox.information(
            self,
            "Success",
            "Report generated successfully!"
        )


    def on_report_error(self, msg):
        self.generate_report_btn.setEnabled(True)
        self.status_label.setText("Status: Error")

        QMessageBox.critical(
            self,
            "Error",
            f"Failed to generate report:\n{msg}"
        )