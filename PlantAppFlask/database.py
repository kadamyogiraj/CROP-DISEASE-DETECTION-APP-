"""
PlantCare AI - Database Module
Local SQLite database for storing users and diagnosis history
Passwords are hashed using werkzeug.security (pbkdf2:sha256)
"""

import sqlite3
import os
from datetime import datetime
import json

try:
    from werkzeug.security import generate_password_hash, check_password_hash
    _HASHING_ENABLED = True
except ImportError:
    _HASHING_ENABLED = False
    print("⚠️  WARNING: werkzeug not found. Passwords stored in plaintext. Install: pip install werkzeug")

DB_PATH = 'plantcare.db'

def get_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _hash_password(password):
    """Hash a plaintext password. Falls back to plaintext if werkzeug unavailable."""
    if _HASHING_ENABLED:
        return generate_password_hash(password)
    return password

def _verify_password(stored, provided):
    """Verify a password against stored hash or plaintext."""
    if _HASHING_ENABLED:
        # If the stored value looks like a werkzeug hash, use check_password_hash
        if stored.startswith('pbkdf2:') or stored.startswith('scrypt:'):
            return check_password_hash(stored, provided)
        # Legacy plaintext fallback (for existing accounts created before hashing)
        return stored == provided
    return stored == provided

def init_db():
    """Initialize database tables"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            phone TEXT,
            dob TEXT,
            gender TEXT,
            preferred_lang TEXT DEFAULT 'en',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Add preferred_lang column if upgrading from older schema
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN preferred_lang TEXT DEFAULT 'en'")
    except Exception:
        pass  # Column already exists
    
    # Diagnosis history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS diagnosis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            plant_name TEXT,
            disease TEXT,
            confidence TEXT,
            treatment TEXT,
            image_path TEXT,
            health_score REAL,
            is_unknown INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Chat history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            message TEXT,
            response TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("[OK] Database initialized!")

# ===== User Functions =====

def create_user(name, email, password, phone=None, dob=None, gender=None):
    """Create new user with hashed password"""
    conn = get_connection()
    cursor = conn.cursor()
    
    hashed = _hash_password(password)
    
    try:
        cursor.execute('''
            INSERT INTO users (name, email, password, phone, dob, gender)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (name, email, hashed, phone, dob, gender))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return {"success": True, "user_id": user_id, "message": "Account created successfully"}
    except sqlite3.IntegrityError:
        conn.close()
        return {"success": False, "error": "Email already exists"}

def login_user(email, password):
    """Login user with password hash verification"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user and _verify_password(user['password'], password):
        return {
            "success": True,
            "user": {
                "id": user['id'],
                "name": user['name'],
                "email": user['email'],
                "preferred_lang": user['preferred_lang'] if 'preferred_lang' in user.keys() and user['preferred_lang'] else 'en'
            }
        }
    return {"success": False, "error": "Invalid email or password"}

def get_user(user_id):
    """Get user by ID"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return dict(user)
    return None

def get_user_by_email(email):
    """Get user by email address"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return dict(user)
    return None

def reset_password(email, new_password):
    """Reset password for user with given email (stored as hash)"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return {"success": False, "error": "Email not found"}
    
    # Hash new password before storing
    hashed = _hash_password(new_password)
    cursor.execute('UPDATE users SET password = ? WHERE email = ?', (hashed, email))
    conn.commit()
    conn.close()
    
    return {"success": True, "message": "Password reset successfully"}

def update_user(user_id, name=None, phone=None, dob=None, gender=None, preferred_lang=None):
    """Update user details"""
    conn = get_connection()
    cursor = conn.cursor()
    
    fields = []
    values = []
    
    if name:
        fields.append("name = ?")
        values.append(name)
    if phone:
        fields.append("phone = ?")
        values.append(phone)
    if dob:
        fields.append("dob = ?")
        values.append(dob)
    if gender:
        fields.append("gender = ?")
        values.append(gender)
    if preferred_lang and preferred_lang in ['en', 'hi', 'mr']:
        fields.append("preferred_lang = ?")
        values.append(preferred_lang)
        
    if not fields:
        conn.close()
        return {"success": False, "error": "No fields to update"}
        
    values.append(user_id)
    query = f"UPDATE users SET {', '.join(fields)} WHERE id = ?"
    
    try:
        cursor.execute(query, values)
        conn.commit()
        conn.close()
        return {"success": True, "message": "User updated successfully"}
    except Exception as e:
        conn.close()
        return {"success": False, "error": str(e)}

def delete_user(user_id):
    """Delete user and their related data"""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('DELETE FROM diagnosis_history WHERE user_id = ?', (user_id,))
        cursor.execute('DELETE FROM chat_history WHERE user_id = ?', (user_id,))
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        
        conn.commit()
        conn.close()
        return {"success": True, "message": "User and related data deleted successfully"}
    except Exception as e:
        conn.close()
        return {"success": False, "error": str(e)}

# ===== Diagnosis History Functions =====

def save_diagnosis(user_id, plant_name, disease, confidence, treatment, image_path=None, health_score=None, is_unknown=False):
    """Save diagnosis result to history"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO diagnosis_history 
        (user_id, plant_name, disease, confidence, treatment, image_path, health_score, is_unknown)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, plant_name, disease, confidence, treatment, image_path, health_score, 1 if is_unknown else 0))
    
    conn.commit()
    diagnosis_id = cursor.lastrowid
    conn.close()
    
    return {"success": True, "diagnosis_id": diagnosis_id}

def get_diagnosis_history(user_id=None, limit=20):
    """Get diagnosis history"""
    conn = get_connection()
    cursor = conn.cursor()
    
    if user_id:
        cursor.execute('''
            SELECT * FROM diagnosis_history 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT ?
        ''', (user_id, limit))
    else:
        cursor.execute('''
            SELECT * FROM diagnosis_history 
            ORDER BY created_at DESC 
            LIMIT ?
        ''', (limit,))
    
    history = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in history]

def get_diagnosis_stats(user_id=None):
    """Get diagnosis statistics"""
    conn = get_connection()
    cursor = conn.cursor()
    
    if user_id:
        cursor.execute('SELECT COUNT(*) as total FROM diagnosis_history WHERE user_id = ?', (user_id,))
    else:
        cursor.execute('SELECT COUNT(*) as total FROM diagnosis_history')
    
    total = cursor.fetchone()['total']
    
    if user_id:
        cursor.execute('SELECT COUNT(*) as diseased FROM diagnosis_history WHERE user_id = ? AND disease != "Healthy" AND is_unknown = 0', (user_id,))
    else:
        cursor.execute('SELECT COUNT(*) as diseased FROM diagnosis_history WHERE disease != "Healthy" AND is_unknown = 0')
    
    diseased = cursor.fetchone()['diseased']
    conn.close()
    
    return {
        "total_scans": total,
        "diseased_plants": diseased,
        "healthy_plants": total - diseased
    }

def delete_diagnosis(diagnosis_id):
    """Delete a diagnosis record"""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('DELETE FROM diagnosis_history WHERE id = ?', (diagnosis_id,))
        conn.commit()
        conn.close()
        return {"success": True, "message": "Diagnosis record deleted"}
    except Exception as e:
        conn.close()
        return {"success": False, "error": str(e)}

# ===== Chat History Functions =====

def save_chat(user_id, message, response):
    """Save chat message"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO chat_history (user_id, message, response)
        VALUES (?, ?, ?)
    ''', (user_id, message, response))
    
    conn.commit()
    conn.close()

def get_chat_history(user_id, limit=50):
    """Get chat history for user"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM chat_history 
        WHERE user_id = ? 
        ORDER BY created_at ASC 
        LIMIT ?
    ''', (user_id, limit))
    
    chats = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in chats]

# Initialize database on import
if not os.path.exists(DB_PATH):
    init_db()
