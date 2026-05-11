"""
ForenSight AI - Application Entry Point
======================================

Main launcher for the ForenSight AI desktop application.

Responsibilities
----------------
1. Configure application import paths
2. Initialize logging system
3. Launch Qt application instance
4. Display landing screen
5. Handle navigation to dashboard GUI
6. Ensure graceful application shutdown

Application Flow
----------------
Landing Window
      ↓
Main Dashboard
      ↓
Detection / Analysis / Reporting

Notes
-----
• Supports both development (.py) and packaged (.exe) execution
• Designed for PyInstaller compatibility
• Logging system initialized during startup
"""

import sys
import os
import logging


# ---------------------------------------------------------
# PROJECT ROOT PATH CONFIGURATION
# ---------------------------------------------------------
# Ensures the src/ package is importable regardless
# of execution context (.py or packaged executable).
# ---------------------------------------------------------

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)


# ---------------------------------------------------------
# GUI IMPORTS
# ---------------------------------------------------------

from PyQt5.QtWidgets import QApplication

from src.gui.main_window import MainWindow
from src.gui.landing_window import LandingWindow


# ---------------------------------------------------------
# MAIN APPLICATION FUNCTION
# ---------------------------------------------------------

def main():
    """
    Initialize and launch the ForenSight AI application.
    """

    # ---------------------------------------------------------
    # Initialize Logging System
    # ---------------------------------------------------------

    from src.utils.logger_config import setup_logger

    logger = setup_logger()
    logger.info("Application started")

    # ---------------------------------------------------------
    # Create Qt Application Instance
    # ---------------------------------------------------------

    app = QApplication(sys.argv)

    # ---------------------------------------------------------
    # Initialize GUI Windows
    # ---------------------------------------------------------

    landing = LandingWindow()
    dashboard = MainWindow()

    # ---------------------------------------------------------
    # Navigation Callback
    # ---------------------------------------------------------
    # Handles transition from landing screen
    # to main dashboard interface.
    # ---------------------------------------------------------

    def open_dashboard():
        landing.close()
        dashboard.show()

    landing.open_dashboard_callback = open_dashboard

    # ---------------------------------------------------------
    # Display Landing Window
    # ---------------------------------------------------------

    landing.show()

    # ---------------------------------------------------------
    # Start Qt Event Loop
    # ---------------------------------------------------------

    exit_code = app.exec_()

    # ---------------------------------------------------------
    # Graceful Logging Shutdown
    # ---------------------------------------------------------
    # Ensures all log handlers flush correctly before exit.
    # ---------------------------------------------------------

    logging.shutdown()

    # ---------------------------------------------------------
    # Exit Application
    # ---------------------------------------------------------

    sys.exit(exit_code)


# ---------------------------------------------------------
# APPLICATION ENTRY POINT
# ---------------------------------------------------------

if __name__ == "__main__":
    main()