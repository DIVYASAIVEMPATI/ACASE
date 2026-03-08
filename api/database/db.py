"""
Database for persistent API key storage
"""
import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent / "storage" / "acase_api.db"

def init_db():
    """Initialize database with tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # API Keys table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            api_key TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TEXT NOT NULL,
            scans_count INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1
        )
    """)
    
    # Scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            api_key TEXT NOT NULL,
            target TEXT NOT NULL,
            email TEXT NOT NULL,
            status TEXT NOT NULL,
            progress INTEGER DEFAULT 0,
            current_action TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            results TEXT,
            FOREIGN KEY (api_key) REFERENCES api_keys(api_key)
        )
    """)
    
    conn.commit()
    conn.close()

def save_api_key(api_key, name, email):
    """Save API key to database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO api_keys (api_key, name, email, created_at)
        VALUES (?, ?, ?, ?)
    """, (api_key, name, email, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_api_key(api_key):
    """Get API key details"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM api_keys WHERE api_key = ? AND active = 1", (api_key,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            "api_key": result[0],
            "name": result[1],
            "email": result[2],
            "created_at": result[3],
            "scans_count": result[4]
        }
    return None

def list_api_keys():
    """List all active API keys"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT api_key, name, email, created_at FROM api_keys WHERE active = 1")
    results = cursor.fetchall()
    conn.close()
    
    return [
        {"api_key": r[0], "name": r[1], "email": r[2], "created_at": r[3]}
        for r in results
    ]

def save_scan(scan_data):
    """Save scan to database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO scans 
        (scan_id, api_key, target, email, status, progress, current_action, started_at, completed_at, results)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_data["scan_id"],
        scan_data["api_key"],
        scan_data["target"],
        scan_data["email"],
        scan_data["status"],
        scan_data.get("progress", 0),
        scan_data.get("current_action", ""),
        scan_data["started_at"],
        scan_data.get("completed_at"),
        json.dumps(scan_data.get("results")) if "results" in scan_data else None
    ))
    conn.commit()
    conn.close()

def get_scan(scan_id):
    """Get scan details"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            "scan_id": result[0],
            "api_key": result[1],
            "target": result[2],
            "email": result[3],
            "status": result[4],
            "progress": result[5],
            "current_action": result[6],
            "started_at": result[7],
            "completed_at": result[8],
            "results": json.loads(result[9]) if result[9] else None
        }
    return None

def get_scans_by_api_key(api_key):
    """Get all scans for an API key"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT scan_id, target, email, status, started_at FROM scans WHERE api_key = ? ORDER BY started_at DESC", (api_key,))
    results = cursor.fetchall()
    conn.close()
    
    return [
        {
            "scan_id": r[0],
            "target": r[1],
            "email": r[2],
            "status": r[3],
            "started_at": r[4]
        }
        for r in results
    ]

# Initialize on import
init_db()
