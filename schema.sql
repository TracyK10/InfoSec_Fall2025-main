-- Information Security Fall 2025 Lab - Database Schema
-- Central place for schema so you can add future tables here.

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    andrew_id TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    uploader_andrew_id TEXT NOT NULL,
    upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uploader_andrew_id) REFERENCES users(andrew_id)
);
