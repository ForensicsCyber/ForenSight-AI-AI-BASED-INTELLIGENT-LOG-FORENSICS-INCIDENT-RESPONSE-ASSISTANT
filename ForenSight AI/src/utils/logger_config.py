"""
Logging Configuration Module
============================

Provides centralized logging configuration for
ForenSight AI.

Responsibilities
----------------
1. Configure application logging
2. Create persistent log directory
3. Maintain consistent log formatting
4. Support both development and packaged execution

Log Storage
-----------
Logs are stored in:

Downloads/ForenSightAI/Logs/

Generated Files
---------------
forensightai.log
"""

import logging
import os


# ---------------------------------------------------------
# LOG FILE PATH
# ---------------------------------------------------------

def get_log_file_path():
    """
    Return centralized application log file path.

    Returns
    -------
    str
        Full log file path
    """

    try:

        downloads_dir = os.path.join(
            os.path.expanduser("~"),
            "Downloads"
        )

        log_dir = os.path.join(
            downloads_dir,
            "ForenSightAI",
            "Logs"
        )

        os.makedirs(log_dir, exist_ok=True)

        return os.path.join(
            log_dir,
            "forensightai.log"
        )

    except Exception:

        # ---------------------------------------------------------
        # Safe fallback location
        # ---------------------------------------------------------

        fallback_dir = os.path.expanduser("~")

        return os.path.join(
            fallback_dir,
            "forensightai.log"
        )


# ---------------------------------------------------------
# LOGGER INITIALIZATION
# ---------------------------------------------------------

def setup_logger():
    """
    Configure and return application logger.

    Returns
    -------
    logging.Logger
    """

    log_file = get_log_file_path()

    logger = logging.getLogger("ForenSightAI")

    logger.setLevel(logging.INFO)

    # ---------------------------------------------------------
    # Prevent duplicate handlers
    # ---------------------------------------------------------

    if not logger.handlers:

        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s"
        )

        # ---------------------------------------------------------
        # File Logging
        # ---------------------------------------------------------

        try:

            file_handler = logging.FileHandler(
                log_file,
                encoding="utf-8",
                delay=False
            )

            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(formatter)

            logger.addHandler(file_handler)

        except Exception:
            pass

        # ---------------------------------------------------------
        # Console Logging
        # ---------------------------------------------------------

        console_handler = logging.StreamHandler()

        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)

        logger.addHandler(console_handler)

    return logger