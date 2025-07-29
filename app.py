from flask import Flask, request, render_template, redirect, make_response, session
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

    # Parse user agent with user-agents package
    ua_string = request.headers.get('User-Agent', '')
    user_agent = parse(ua_string)
    
    # Get geolocation data
    geo_data = get_geolocation(ip)
    
    # Get hostname if possible
    hostname = None
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        pass
    
    # Get referrer information
    referrer = request.referrer
    referrer_domain = urlparse(referrer).netloc if referrer else None
    
    return {
        'ip': ip,
        'hostname': hostname,
        'user_agent': ua_string,
        'headers': dict(request.headers),
        'timestamp': datetime.now().isoformat(),
        'geolocation': geo_data,
        'referrer': referrer,
        'referrer_domain': referrer_domain,
        'method': request.method,
        'path': request.path,
        'query_params': dict(request.args),
        'cookies': dict(request.cookies),
        'platform': user_agent.os.family,
        'browser': user_agent.browser.family,
        'version': user_agent.browser.version_string,
        'language': request.headers.get('Accept-Language'),
        'is_mobile': user_agent.is_mobile,
        'is_tablet': user_agent.is_tablet,
        'is_pc': user_agent.is_pc,
        'is_bot': user_agent.is_bot,
        'device': user_agent.device.family
    }

def log_activity(username, activity_type, details=None):
    """Log user activity with comprehensive tracking"""
    client_info = get_client_info()
    activity_data = {
        'username': username,
        'activity_type': activity_type,
        'details': details,
        'client_info': client_info,
        'timestamp': datetime.now().isoformat()
    }
    
    # Store activity in memory
    user_activities.append(activity_data)
    
    # Log to activity log file
    log_message = f"{username}|{activity_type}|{client_info['ip']}|{client_info.get('geolocation', {}).get('city', 'Unknown')}|{client_info.get('geolocation', {}).get('country', 'Unknown')}|{details or ''}"
    activity_logger.info(log_message)
    
    # Log to traceback log with more details
    traceback_data = {
        'timestamp': datetime.now().isoformat(),
        'username': username,
        'activity': activity_type,
        'ip': client_info['ip'],
        'geolocation': client_info.get('geolocation', {}),
        'user_agent': client_info['user_agent'],
        'device_info': {
            'platform': client_info['platform'],
            'browser': client_info['browser'],
            'version': client_info['version'],
            'is_mobile': client_info['is_mobile'],
            'is_tablet': client_info['is_tablet'],
            'is_pc': client_info['is_pc'],
            'is_bot': client_info['is_bot']
        },
        'details': details
    }
    traceback_logger.info(json.dumps(traceback_data))

def read_audit_logs(limit=100):
    """Read and parse audit logs from the log file"""
    logs = []
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    timestamp_end = line.find(']') + 1
                    timestamp_str = line[:timestamp_end].strip()
                    level_start = line.find('[', timestamp_end) + 1
                    level_end = line.find(']', level_start)
                    level = line[level_start:level_end]
                    message = line[level_end+2:].strip()
                    
                    logs.append({
                        'timestamp': timestamp_str,
                        'level': level,
                        'message': message
                    })
                except Exception as e:
                    print(f"Error parsing log line: {e}")
    except FileNotFoundError:
        pass
    return logs[-limit:][::-1]

def read_activity_logs(limit=50):
    """Read and parse activity logs from the activity log file"""
    activities = []
    try:
        with open(ACTIVITY_LOG, 'r') as f:
            for line in f:
                try:
                    parts = line.strip().split('|', 5)
                    if len(parts) >= 6:
                        activities.append({
                            'timestamp': parts[0],
                            'username': parts[1],
                            'activity_type': parts[2],
                            'ip': parts[3],
                            'location': f"{parts[4]}, {parts[5]}",
                            'details': parts[6] if len(parts) > 6 else None
                        })
                except Exception as e:
                    print(f"Error parsing activity log line: {e}")
    except FileNotFoundError:
        pass
    return activities[-limit:][::-1]

def read_traceback_logs(limit=50):
    """Read and parse traceback logs"""
    tracebacks = []
    try:
        with open(TRACEBACK_LOG, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    tracebacks.append(data)
                except json.JSONDecodeError as e:
                    print(f"Error parsing traceback log line: {e}")
    except FileNotFoundError:
        pass
    return tracebacks[-limit:][::-1]


@app.before_request
def validate_session():
    if request.endpoint not in ['login', 'static']:
        session_token = request.cookies.get('session')
        if not session_token or session_token not in sessions:
            return redirect('/')
        if datetime.now() > sessions[session_token]['expires_at']:
            del sessions[session_token]
            resp = make_response(redirect('/'))
            resp.delete_cookie('session')
            return resp
        
app.jinja_env.filters['tojson'] = json.dumps
# === LOGIN ===
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        client_info = get_client_info()

        if username in users and check_password_hash(users[username]['password'], password):
            # Create session
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

    # Clear session if accessing login page directly
    session_token = request.cookies.get('session')
    if session_token and session_token in sessions:
        resp = make_response(render_template('login.html'))
        resp.delete_cookie('session')
        del sessions[session_token]
        return resp
    
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
    if session_token and session_token in sessions:
        username = sessions[session_token]['username']
        client_info = sessions[session_token]['client_info']
        log_activity(username, 'logout', {
            'ip': client_info['ip'],
            'location': client_info.get('geolocation', {}),
            'session_duration': str(datetime.now() - sessions[session_token]['created_at'])
        })
        del sessions[session_token]
        logging.info(f"🔓 Session ended for user={username}, IP={client_info['ip']}")

    resp = make_response(redirect('/'))
    resp.delete_cookie('session')
    return resp

# === START SERVER ===
if __name__ == '__main__':
    print(f"🔐 Audit log: {LOG_FILE}")
    print(f"🔍 Activity log: {ACTIVITY_LOG}")
    print(f"🌍 Traceback log: {TRACEBACK_LOG}")
    app.run(debug=True, host='0.0.0.0', port=5000)