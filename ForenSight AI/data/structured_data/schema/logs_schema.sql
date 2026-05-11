-- ======================================================
-- ForenSight AI
-- Database Schema Definition
-- Unified Security Log Table
-- ======================================================

-- Drop existing table (optional safety)
DROP TABLE IF EXISTS logs;

-- Main unified log table
CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Event timestamp (ISO 8601 format recommended)
    timestamp TEXT NOT NULL,

    -- Network information
    source_ip TEXT,
    destination_ip TEXT,

    -- User context (used in SSH/Linux logs)
    username TEXT,

    -- Web request details
    request_method TEXT,
    endpoint TEXT,

    -- HTTP or system status code
    status_code INTEGER,

    -- Raw message content from log
    message TEXT,

    -- Type of log source
    log_type TEXT
);