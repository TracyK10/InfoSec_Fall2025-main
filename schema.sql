-- Information Security Fall 2025 Lab - Database Schema
-- Central place for schema so you can add future tables here.

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    andrew_id TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    otp_secret BLOB,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    uploader_andrew_id TEXT NOT NULL,
    upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uploader_andrew_id) REFERENCES users(andrew_id)
);

CREATE TABLE IF NOT EXISTS otp_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,  -- Format: YYYYMMDDHHMM
    otp_code TEXT NOT NULL,   -- 6-digit OTP
    used BOOLEAN DEFAULT 0,   -- Whether the OTP has been used
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(user_id, timestamp)
);
