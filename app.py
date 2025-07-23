from flask import Flask, request, render_template, redirect, make_response, url_for
import sqlite3
from datetime import datetime, timedelta
import secrets
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# SQLite datetime handlers for Python 3.12+
def adapt_datetime(dt):
    return dt.isoformat()

def convert_datetime(ts):
    return datetime.fromisoformat(ts.decode())

sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("TIMESTAMP", convert_datetime)

# Configuration
LOG_FILE = 'log.txt'
DATABASE = 'users.db'

def get_db_connection():
    return sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)

def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT UNIQUE NOT NULL, 
                     password TEXT NOT NULL)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS sessions
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     token TEXT UNIQUE NOT NULL,
                     username TEXT NOT NULL,
                     ip TEXT NOT NULL,
                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                     expires_at TIMESTAMP NOT NULL)''')
        
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                     ('admin', 'password123'))
            conn.commit()
        except sqlite3.IntegrityError:
            pass

def log_login(username, ip, success=True):
    with open(LOG_FILE, 'a') as f:
        status = "SUCCESS" if success else "FAILED"
        f.write(f"{datetime.now()} | {status} | Username: {username} | IP: {ip}\n")

def cleanup_sessions():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.now(),))
        conn.commit()

@app.route('/', methods=['GET', 'POST'])
def login():
    cleanup_sessions()
    ip = request.remote_addr
    
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
            
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("INSERT INTO sessions (token, username, ip, expires_at) VALUES (?, ?, ?, ?)",
                         (session_token, username, ip, expires_at))
                conn.commit()
            
            resp = make_response(redirect('/admin'))
            resp.set_cookie(
                'session',
                session_token,
                httponly=True,
                secure=False,  # Set to True in production with HTTPS
                samesite='Strict',
                max_age=3600
            )
            
            log_login(username, ip, success=True)
            return resp
        
        log_login(username, ip, success=False)
        return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')

@app.route('/admin')
def admin():
    cleanup_sessions()
    session_token = request.cookies.get('session')
    
    if not session_token:
        return "Access Denied - No session token", 403
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''SELECT username, ip FROM sessions 
                     WHERE token = ? AND expires_at > ?''',
                 (session_token, datetime.now()))
        session_data = c.fetchone()
    
    if not session_data:
        return "Access Denied - Invalid or expired session", 403
    
    username, session_ip = session_data
    
    # Temporarily disabled for testing
    # if session_ip != request.remote_addr:
    #     return "Access Denied - IP mismatch", 403
    
    if username != 'admin':
        return "Access Denied - Admin privileges required", 403
    
    # Get all active sessions
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''SELECT username, token, ip, created_at, expires_at FROM sessions 
                      WHERE expires_at > ?''',
                  (datetime.now(),))
        active_sessions = c.fetchall()
    
    try:
        with open(LOG_FILE, 'r') as f:
            logs = f.readlines()
    except FileNotFoundError:
        logs = []
    
    return render_template(
        'admin.html',
        username=username,
        ip=request.remote_addr,
        logs=reversed(logs[-100:]),
        active_sessions=active_sessions
    )

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
    db_dir = os.path.dirname(DATABASE)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)