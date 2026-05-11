"""
Dashboard Widget (FINAL PREMIUM VERSION)
========================================

✔ Gradient cards
✔ Glow effects
✔ Bigger typography
✔ Improved severity labels
✔ Clean layout
✔ FULL FUNCTIONALITY FIXED
"""

import numpy as np

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QFrame, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QGraphicsDropShadowEffect
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


class DashboardWidget(QWidget):

    def __init__(self):
        super().__init__()

        self.layout = QGridLayout()
        self.layout.setSpacing(16)
        self.layout.setContentsMargins(12, 12, 12, 12)
        self.setLayout(self.layout)
        # LEFT (columns 0,1) = 50%
        self.layout.setColumnStretch(0, 1)
        self.layout.setColumnStretch(1, 1)

        # RIGHT (columns 2,3) = 50%
        self.layout.setColumnStretch(2, 1)
        self.layout.setColumnStretch(3, 1)

        # -----------------------------
        # Severity Bar
        # -----------------------------
        self.severity_bar = self.create_severity_bar()
        self.layout.addWidget(self.severity_bar, 0, 0, 1, 4)

        # -----------------------------
        # Metric Labels
        # -----------------------------
        self.alert_label = QLabel("0")
        self.ioc_label = QLabel("-")
        self.score_label = QLabel("-")
        self.status_label = QLabel("Idle")

        self.layout.addWidget(self.metric_card("Active Alerts", self.alert_label), 1, 0)
        self.layout.addWidget(self.metric_card("Top IOC", self.ioc_label), 1, 1)
        self.layout.addWidget(self.metric_card("Threat Score", self.score_label), 1, 2)
        self.layout.addWidget(self.metric_card("Case Status", self.status_label), 1, 3)

        # -----------------------------
        # 📊 CHART + LEGEND CONTAINER
        # -----------------------------
        self.chart_container = QFrame()
        chart_layout = QHBoxLayout()
        chart_layout.setSpacing(30)

        # LEFT → Chart
        self.figure = Figure()
        self.canvas = FigureCanvas(self.figure)
        self.canvas.setMaximumWidth(500)
        self.canvas.hide()
        chart_layout.addWidget(self.canvas, 11)

        # RIGHT → Legend Panel
        self.legend_panel = QVBoxLayout()
        self.legend_panel.setAlignment(Qt.AlignVCenter)

        chart_layout.addLayout(self.legend_panel, 9)

        self.chart_container.setLayout(chart_layout)

        self.layout.addWidget(self.chart_container, 2, 0, 1, 2)

        # -----------------------------
        # Timeline Table
        # -----------------------------
        self.table = self.create_timeline()
        self.layout.addWidget(self.table, 2, 2, 1, 2)

    # -----------------------------
    # Metric Cards
    # -----------------------------
    def metric_card(self, title, value_label):

        card = QFrame()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(6)

        icon_map = {
            "Active Alerts": "🚨",
            "Top IOC": "🌐",
            "Threat Score": "⚠️",
            "Case Status": "🛡️"
        }

        title_label = QLabel(
            f"<span style='font-size:20px'>{icon_map.get(title)}</span> "
            f"<span style='font-size:15px; font-weight:600'>{title.upper()}</span>"
        )
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: white;")

        value_label.setAlignment(Qt.AlignCenter)
        value_label.setStyleSheet("""
            font-size: 32px;
            font-weight: bold;
            color: white;
        """)

        layout.addWidget(title_label)
        layout.addWidget(value_label)

        card.setLayout(layout)

        color_map = {
            "Active Alerts": "#6c5ce7",
            "Top IOC": "#00cec9",
            "Threat Score": "#b9770e",
            "Case Status": "#2d3436"
        }

        bg_color = color_map.get(title)

        card.setStyleSheet(f"""
            QFrame {{
                border-radius: 14px;
                padding: 6px;
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 {bg_color},
                    stop:1 #1e1e2e
                );
                border: 1px solid rgba(255,255,255,0.08);
            }}
        """)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(25)
        shadow.setColor(QColor(bg_color))
        card.setGraphicsEffect(shadow)

        card.setFixedHeight(120)

        return card

    # -----------------------------
    # Severity Bar
    # -----------------------------
    def create_severity_bar(self):

        container = QFrame()
        layout = QHBoxLayout()

        def create_segment(text, color):
            segment = QFrame()
            seg_layout = QVBoxLayout()
            seg_layout.setAlignment(Qt.AlignCenter)

            label = QLabel(text.upper())
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet("font-size: 15px; font-weight: bold;")

            seg_layout.addWidget(label)
            segment.setLayout(seg_layout)

            segment.setStyleSheet(f"""
                QFrame {{
                    background-color: {color};
                    border-radius: 10px;
                }}
            """)

            segment.setFixedHeight(110)
            return segment

        self.critical_box = create_segment("CRITICAL: 0", "#e74c3c")
        self.high_box = create_segment("HIGH: 0", "#e67e22")
        self.medium_box = create_segment("MEDIUM: 0", "#f1c40f")
        self.low_box = create_segment("LOW: 0", "#2ecc71")

        layout.addWidget(self.critical_box)
        layout.addWidget(self.high_box)
        layout.addWidget(self.medium_box)
        layout.addWidget(self.low_box)

        container.setLayout(layout)
        return container

    # -----------------------------
    # Timeline Table
    # -----------------------------
    def create_timeline(self):

        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Time", "Event", "Severity"])

        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)

        table.setEditTriggers(QTableWidget.NoEditTriggers)

        return table

    # -----------------------------
    # Log Viewer
    # -----------------------------
    def create_log_viewer(self):

        viewer = QTextEdit()
        viewer.setReadOnly(True)
        return viewer

    # -----------------------------
    # 🚀 FINAL FIXED UPDATE
    # -----------------------------
    def update_dashboard(self, metrics, timeline):

        # Top metrics
        self.alert_label.setText(str(metrics.get("total_alerts", 0)))
        self.ioc_label.setText(str(metrics.get("top_ip", "-")))
        self.score_label.setText(metrics.get("overall_severity", "LOW"))

        # 🔥 Severity counts
        severity_counts = metrics.get("severity_counts", {})

        self.critical_box.layout().itemAt(0).widget().setText(
            f"CRITICAL: {severity_counts.get('CRITICAL', 0)}"
        )
        self.high_box.layout().itemAt(0).widget().setText(
            f"HIGH: {severity_counts.get('HIGH', 0)}"
        )
        self.medium_box.layout().itemAt(0).widget().setText(
            f"MEDIUM: {severity_counts.get('MEDIUM', 0)}"
        )
        self.low_box.layout().itemAt(0).widget().setText(
            f"LOW: {severity_counts.get('LOW', 0)}"
        )

        # 🔥 Timeline table
        self.table.setRowCount(len(timeline))

        for row, event in enumerate(timeline):
            self.table.setItem(row, 0, QTableWidgetItem(str(event.get("time", ""))))
            self.table.setItem(row, 1, QTableWidgetItem(event.get("event", "")))
            self.table.setItem(row, 2, QTableWidgetItem(event.get("severity", "")))

        
    # -----------------------------
    # 📊 PIE CHART FUNCTION (NEW)
    # -----------------------------
    def plot_attack_pie_chart(self, alerts):
        """
        FINAL ENTERPRISE DONUT CHART (NO ANIMATION)
        ✔ Bigger chart
        ✔ No center text
        ✔ Safe for empty data
        ✔ Custom hover tooltip
        ✔ Clean centered legend
        ✔ Small slices visibility fix
        """

        self.canvas.show()

        from PyQt5.QtWidgets import QLabel, QHBoxLayout, QSpacerItem, QSizePolicy

        # -----------------------------
        # Prepare Data
        # -----------------------------
        attack_counts = {}
        attack_severity_map = {}

        for alert in alerts:
            attack_type = alert.get("type", "Unknown")
            severity = str(alert.get("severity", "LOW")).upper()

            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1

            # store severity per attack type (latest or highest)
            severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

            existing = attack_severity_map.get(attack_type)

            if not existing or severity_order.index(severity) > severity_order.index(existing):
                attack_severity_map[attack_type] = severity

        labels = list(attack_counts.keys())
        sizes = list(attack_counts.values())

        sorted_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)
        top_attacks = dict(sorted_attacks[:6])

        if len(sorted_attacks) > 6:
            others = sum(count for _, count in sorted_attacks[6:])
            top_attacks["Others"] = others
            attack_severity_map["Others"] = "LOW"

        labels = list(top_attacks.keys())
        sizes = list(top_attacks.values())

        # -----------------------------
        # 🛑 HANDLE EMPTY DATA
        # -----------------------------
        if not sizes or sum(sizes) == 0:

            self.figure.clear()
            ax = self.figure.add_subplot(111)

            self.figure.patch.set_facecolor("#1e1e2e")
            ax.set_facecolor("#1e1e2e")

            ax.text(
                0.5, 0.5,
                "No Attack Data",
                ha='center',
                va='center',
                fontsize=14,
                color="white",
                fontweight="bold"
            )

            ax.set_xticks([])
            ax.set_yticks([])

            self.canvas.draw()
            return

        # -----------------------------
        # Chart Setup
        # -----------------------------
        severity_color_map = {
            "CRITICAL": "#e74c3c",  # red
            "HIGH": "#e67e22",      # orange
            "MEDIUM": "#f1c40f",    # yellow
            "LOW": "#2ecc71"        # green
        }

        colors = [
            severity_color_map.get(attack_severity_map.get(label, "LOW"), "#95a5a6")
            for label in labels
        ]

        self.figure.clear()
        ax = self.figure.add_subplot(111)

        self.figure.patch.set_facecolor("#1e1e2e")
        ax.set_facecolor("#1e1e2e")

        # -----------------------------
        # 🔥 SINGLE CLEAN DRAW (NO ANIMATION)
        # -----------------------------
        wedges, _ = ax.pie(
            sizes,
            labels=None,
            startangle=140,
            colors=colors,
            wedgeprops=dict(width=0.45)
        )

        # -----------------------------
        # TITLE (FIXED)
        # -----------------------------
        ax.set_title(
            "Attack Distribution",
            color="white",
            fontsize=16,
            fontweight="bold",
            pad=20
        )

        self.figure.subplots_adjust(top=0.82)

        self.canvas.draw()

        # -----------------------------
        # 🖱️ CUSTOM HOVER TOOLTIP
        # -----------------------------
        annot = ax.annotate(
            "",
            xy=(0, 0),
            xytext=(10, 10),
            textcoords="offset points",
            bbox=dict(boxstyle="round,pad=0.5", fc="#2d3436", alpha=0.95),
            color="white"
        )

        annot.set_clip_on(False)  # 🔥 VERY IMPORTANT
        annot.set_visible(False)

        total = sum(sizes)

        def update_annot(index, event):
            percentage = (sizes[index] / total) * 100

            annot.set_text(f"{labels[index]}: {percentage:.1f}%")

            # 🔥 Position tooltip at cursor (NOT wedge)
            annot.xy = (event.xdata, event.ydata)

            # Smart offset to avoid clipping
            if event.x > self.canvas.width() / 2:
                annot.xytext = (-80, 10)
                annot.set_horizontalalignment("right")
            else:
                annot.xytext = (20, 10)
                annot.set_horizontalalignment("left")

            if event.y > self.canvas.height() / 2:
                annot.xytext = (annot.xytext[0], -30)
            else:
                annot.xytext = (annot.xytext[0], 20)

        def hover(event):
            vis = annot.get_visible()

            if event.inaxes == ax:
                for i, wedge in enumerate(wedges):
                    contains, _ = wedge.contains(event)
                    if contains:
                        update_annot(i, event)
                        annot.set_visible(True)
                        self.canvas.draw_idle()
                        return

            if vis:
                annot.set_visible(False)
                self.canvas.draw_idle()

        self.canvas.mpl_connect("motion_notify_event", hover)

        # -----------------------------
        # 🧾 LEGEND PANEL
        # -----------------------------
        for i in reversed(range(self.legend_panel.count())):
            item = self.legend_panel.itemAt(i)
            if item.widget():
                item.widget().deleteLater()

        # Top spacer
        self.legend_panel.addSpacerItem(
            QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        )

        # Title
        title = QLabel("Attack Types")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("""
            color: #e0e0e0;
            font-size: 17px;
            font-weight: 700;
            margin-bottom: 8px;
        """)
        self.legend_panel.addWidget(title)

        self.legend_panel.setSpacing(8)

        for i, label in enumerate(labels):

            row = QHBoxLayout()
            row.setSpacing(4)

            color_box = QLabel()
            color_box.setFixedSize(10, 10)
            color_box.setStyleSheet(f"""
                background-color: {colors[i]};
                border-radius: 2px;
            """)

            text = QLabel(label)
            text.setStyleSheet("""
                color: white;
                font-size: 14px;
                font-weight: 500;
            """)

            row.addWidget(color_box)
            row.addWidget(text)
            row.addStretch()

            container = QFrame()
            container.setLayout(row)

            self.legend_panel.addWidget(container)

        # Bottom spacer
        self.legend_panel.addSpacerItem(
            QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        )