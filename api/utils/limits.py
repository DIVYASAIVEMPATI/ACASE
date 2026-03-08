"""
Rate Limiting and Usage Quotas
"""
from datetime import datetime, timedelta
from api.database.db import get_api_key, get_scans_by_api_key
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent / "storage" / "acase_api.db"

# Quota Plans
PLANS = {
    "free": {
        "scans_per_day": 5,
        "scans_per_month": 50,
        "name": "Free Tier"
    },
    "pro": {
        "scans_per_day": 100,
        "scans_per_month": 1000,
        "name": "Pro Tier"
    },
    "enterprise": {
        "scans_per_day": 999999,
        "scans_per_month": 999999,
        "name": "Enterprise"
    }
}

def check_quota(api_key):
    """
    Check if API key has exceeded quota
    Returns: (allowed: bool, message: str, remaining: dict)
    """
    key_data = get_api_key(api_key)
    if not key_data:
        return False, "Invalid API key", {}
    
    plan_name = key_data.get("plan", "free")
    plan = PLANS.get(plan_name, PLANS["free"])
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    day_ago = (datetime.now() - timedelta(days=1)).isoformat()
    cursor.execute("""
        SELECT COUNT(*) FROM scans 
        WHERE api_key = ? AND started_at > ?
    """, (api_key, day_ago))
    daily_count = cursor.fetchone()[0]
    
    month_ago = (datetime.now() - timedelta(days=30)).isoformat()
    cursor.execute("""
        SELECT COUNT(*) FROM scans 
        WHERE api_key = ? AND started_at > ?
    """, (api_key, month_ago))
    monthly_count = cursor.fetchone()[0]
    
    conn.close()
    
    if daily_count >= plan["scans_per_day"]:
        return False, f"Daily limit reached ({plan['scans_per_day']} scans/day)", {
            "daily_remaining": 0,
            "monthly_remaining": plan["scans_per_month"] - monthly_count
        }
    
    if monthly_count >= plan["scans_per_month"]:
        return False, f"Monthly limit reached ({plan['scans_per_month']} scans/month)", {
            "daily_remaining": plan["scans_per_day"] - daily_count,
            "monthly_remaining": 0
        }
    
    return True, "OK", {
        "plan": plan_name,
        "daily_used": daily_count,
        "daily_remaining": plan["scans_per_day"] - daily_count,
        "monthly_used": monthly_count,
        "monthly_remaining": plan["scans_per_month"] - monthly_count
    }

def get_usage_stats(api_key):
    """Get detailed usage statistics"""
    key_data = get_api_key(api_key)
    if not key_data:
        return None
    
    plan_name = key_data.get("plan", "free")
    plan = PLANS.get(plan_name, PLANS["free"])
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE api_key = ?", (api_key,))
    total_scans = cursor.fetchone()[0]
    
    today = datetime.now().date().isoformat()
    cursor.execute("""
        SELECT COUNT(*) FROM scans 
        WHERE api_key = ? AND DATE(started_at) = ?
    """, (api_key, today))
    today_scans = cursor.fetchone()[0]
    
    month_start = datetime.now().replace(day=1).isoformat()
    cursor.execute("""
        SELECT COUNT(*) FROM scans 
        WHERE api_key = ? AND started_at >= ?
    """, (api_key, month_start))
    month_scans = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "plan": plan_name,
        "total_scans": total_scans,
        "today": {
            "used": today_scans,
            "limit": plan["scans_per_day"],
            "remaining": plan["scans_per_day"] - today_scans
        },
        "month": {
            "used": month_scans,
            "limit": plan["scans_per_month"],
            "remaining": plan["scans_per_month"] - month_scans
        }
    }
