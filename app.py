from flask import Flask, request, render_template, redirect, make_response, url_for
import sqlite3
from datetime import datetime, timedelta
import secrets
import os
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration
DATABASE = 'users.db'

def get_db_connection():
    return sqlite3.connect(DATABASE)

def initialize_database(force_recreate=False):
    """Initialize database with proper schema"""
    if force_recreate and os.path.exists(DATABASE):
        os.remove(DATABASE)
    
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Create users table
        c.execute('''CREATE TABLE IF NOT EXISTS users
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT UNIQUE NOT NULL,
                     password TEXT NOT NULL)''')
        
        # Drop old sessions table if exists
        c.execute("DROP TABLE IF EXISTS sessions")
        
        # Create new sessions table with proper schema
        c.execute('''CREATE TABLE IF NOT EXISTS sessions
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     token TEXT UNIQUE NOT NULL,
                     username TEXT NOT NULL,
                     ip TEXT NOT NULL,
                     ip_data TEXT,
                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                     expires_at TIMESTAMP NOT NULL)''')
        
        # Add admin user if not exists
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                     ('admin', 'password123'))
            conn.commit()
        except sqlite3.IntegrityError:
            pass

def get_client_info():
    """Get comprehensive client information"""
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ',' in ip:
        ip = ip.split(',')[0].strip()
    
    return {
        'ip': ip,
        'user_agent': str(request.user_agent),
        'headers': dict(request.headers),
        'timestamp': datetime.now().isoformat()
    }

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ? AND password = ?",
                     (username, password))
            user = c.fetchone()
        
        if user:
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(hours=1)
            client_info = get_client_info()
            
            try:
                with get_db_connection() as conn:
                    c = conn.cursor()
                    c.execute('''INSERT INTO sessions 
                                (token, username, ip, ip_data, expires_at)
                                VALUES (?, ?, ?, ?, ?)''',
                             (session_token, username, client_info['ip'], 
                              json.dumps(client_info), expires_at))
                    conn.commit()
                
                resp = make_response(redirect('/admin'))
                resp.set_cookie('session', session_token, httponly=True)
                return resp
            except sqlite3.OperationalError as e:
                if "no such column: ip_data" in str(e):
                    # Database needs recreation
                    initialize_database(force_recreate=True)
                    return redirect('/')
                raise
        
        return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')

@app.route('/admin')
def admin():
    session_token = request.cookies.get('session')
    if not session_token:
        return "Access Denied", 403
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''SELECT username, ip, ip_data FROM sessions
                     WHERE token = ? AND expires_at > ?''',
                 (session_token, datetime.now()))
        session_data = c.fetchone()
    
    if not session_data or session_data[0] != 'admin':
        return "Access Denied", 403
    
    # Get all active sessions
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''SELECT username, token, ip, ip_data, created_at, expires_at 
                     FROM sessions WHERE expires_at > ?''',
                 (datetime.now(),))
        sessions = []
        for row in c.fetchall():
            try:
                ip_data = json.loads(row[3]) if row[3] else {}
            except:
                ip_data = {}
            sessions.append({
                'username': row[0],
                'token': row[1],
                'ip': row[2],
                'ip_data': ip_data,
                'created_at': row[4],
                'expires_at': row[5]
            })
    
    return render_template('admin.html', 
                         sessions=sessions,
                         current_ip=get_client_info()['ip'])

@app.route('/logout')
def logout():
    session_token = request.cookies.get('session')
    if session_token:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM sessions WHERE token = ?", (session_token,))
            conn.commit()
    
    resp = make_response(redirect('/'))
    resp.delete_cookie('session')
    return resp

if __name__ == '__main__':
    # Ensure database directory exists
    db_dir = os.path.dirname(DATABASE)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    
    # Initialize database with force recreate to ensure proper schema
    initialize_database(force_recreate=True)
    
    app.run(debug=True, host='0.0.0.0', port=5000)