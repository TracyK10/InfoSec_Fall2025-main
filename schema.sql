-- Information Security Fall 2025 Lab - Database Schema
-- Central place for schema so you can add future tables here.

-- First, create users table without any foreign key constraints
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    andrew_id TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'basic',  -- 'basic', 'user_admin', or 'data_admin'
    otp_secret BLOB,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Then create files table without foreign key constraints initially
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    uploader_id INTEGER,
    uploader_andrew_id TEXT,
    upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- OTP chain for two-factor authentication
CREATE TABLE IF NOT EXISTS otp_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,  -- Format: YYYYMMDDHHMM
    otp_code TEXT NOT NULL,   -- 6-digit OTP
    used BOOLEAN DEFAULT 0,   -- Whether the OTP has been used
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, timestamp)
);

-- Audit logs for tracking all sensitive actions
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    actor_id INTEGER NOT NULL,  -- User who performed the action
    actor_andrew_id TEXT NOT NULL,  -- Denormalized for performance
    action TEXT NOT NULL,  -- e.g., 'user_create', 'file_upload', etc.
    target_type TEXT,  -- Type of the target ('user', 'file', etc.)
    target_id INTEGER,  -- ID of the target
    target_pretty TEXT,  -- Human-readable target description
    outcome TEXT NOT NULL,  -- 'allowed' or 'denied'
    FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
);

-- View for easily querying audit logs with user information
CREATE VIEW IF NOT EXISTS audit_logs_pretty AS
SELECT 
    al.id,
    al.created_at,
    al.actor_id,
    al.actor_andrew_id,
    u.name as actor_name,
    al.action,
    al.target_type,
    al.target_id,
    al.target_pretty,
    al.outcome
FROM audit_logs al
LEFT JOIN users u ON al.actor_id = u.id
ORDER BY al.created_at DESC;

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_id ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_files_uploader_id ON files(uploader_id);
CREATE INDEX IF NOT EXISTS idx_files_uploader_andrew_id ON files(uploader_andrew_id);
