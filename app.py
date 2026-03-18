import os
import json
import smtplib
import sqlite3
import hashlib
import hmac
import time
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=[
    "https://vikas-8262.github.io",
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://localhost:3000"
])

# ── CONFIG (set these as environment variables on Render) ──
GMAIL_USER     = os.environ.get('GMAIL_USER',     'vikas.rathod.tech@gmail.com')
GMAIL_APP_PASS = os.environ.get('GMAIL_APP_PASS', '')   # set on Render
ADMIN_HASH     = os.environ.get('ADMIN_HASH',     '')   # set on Render
JWT_SECRET     = os.environ.get('JWT_SECRET',     'change-this-secret-on-render')
DB_PATH        = os.environ.get('DB_PATH',        'portfolio.db')

# ── DATABASE SETUP ──
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS projects (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        title   TEXT NOT NULL,
        nodes   TEXT,
        desc    TEXT,
        stack   TEXT,
        overview TEXT,
        stages  TEXT,
        created_at INTEGER DEFAULT (strftime('%s','now'))
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS experiences (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        company    TEXT NOT NULL,
        role       TEXT NOT NULL,
        start_iso  TEXT,
        end_iso    TEXT,
        location   TEXT,
        type       TEXT,
        bullets    TEXT,
        skills     TEXT,
        created_at INTEGER DEFAULT (strftime('%s','now'))
    )''')
    conn.commit()
    conn.close()

init_db()

# ── SIMPLE JWT (no external library needed) ──
def make_token(payload, expires_in=3600):
    header  = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).decode().rstrip('=')
    payload['exp'] = int(time.time()) + expires_in
    body    = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    sig_input = f"{header}.{body}".encode()
    sig     = hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
    return f"{header}.{body}.{sig_b64}"

def verify_token(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header, body, sig = parts
        sig_input = f"{header}.{body}".encode()
        expected  = base64.urlsafe_b64encode(
            hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest()
        ).decode().rstrip('=')
        if not hmac.compare_digest(sig, expected):
            return None
        padding = 4 - len(body) % 4
        payload = json.loads(base64.urlsafe_b64decode(body + '=' * padding))
        if payload.get('exp', 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization','')
        if not auth.startswith('Bearer '):
            return jsonify({'error':'Unauthorized'}), 401
        token = auth[7:]
        payload = verify_token(token)
        if not payload:
            return jsonify({'error':'Invalid or expired token'}), 401
        return f(*args, **kwargs)
    return decorated

# ── HEALTH CHECK ──
@app.route('/')
def health():
    return jsonify({'status': 'ok', 'message': 'Vikas Rathod Portfolio API'})

# ── AUTH ──
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('password'):
        return jsonify({'error': 'Password required'}), 400

    # Compare against bcrypt hash stored in env var
    submitted = hashlib.sha256(data['password'].encode()).hexdigest()
    if not hmac.compare_digest(submitted, ADMIN_HASH):
        return jsonify({'error': 'Invalid password'}), 401

    token = make_token({'role': 'admin'}, expires_in=1800)  # 30 min
    return jsonify({'token': token})

# ── CONTACT FORM ──
@app.route('/api/contact', methods=['POST'])
def contact():
    data = request.get_json()
    name    = (data.get('name') or '').strip()
    email   = (data.get('email') or '').strip()
    subject = (data.get('subject') or 'Portfolio Enquiry').strip()
    message = (data.get('message') or '').strip()

    if not name or not email or not message:
        return jsonify({'error': 'Name, email and message are required'}), 400

    if '@' not in email or '.' not in email:
        return jsonify({'error': 'Invalid email address'}), 400

    if not GMAIL_APP_PASS:
        return jsonify({'error': 'Email service not configured'}), 500

    try:
        # Email TO Vikas
        msg_to_vikas = MIMEMultipart()
        msg_to_vikas['From']    = GMAIL_USER
        msg_to_vikas['To']      = GMAIL_USER
        msg_to_vikas['Subject'] = f'[Portfolio] {subject}'
        msg_to_vikas['Reply-To'] = email
        body_to_vikas = f"""New message from your portfolio contact form:

Name:    {name}
Email:   {email}
Subject: {subject}

Message:
{message}

---
Reply directly to this email to respond to {name}.
"""
        msg_to_vikas.attach(MIMEText(body_to_vikas, 'plain'))

        # Auto-reply TO sender
        msg_reply = MIMEMultipart()
        msg_reply['From']    = GMAIL_USER
        msg_reply['To']      = email
        msg_reply['Subject'] = f'Thank you for reaching out, {name}!'
        body_reply = f"""Hi {name},

Thank you for contacting me through my portfolio!

I have received your message and will get back to you within 24-48 hours.

Here's a copy of what you sent:

Subject: {subject}
Message:
{message}

Best regards,
Vikas Rathod
Python Developer & AI Automation Engineer
Pune, Maharashtra, India

vikas.rathod.tech@gmail.com
linkedin.com/in/vikas-rathod-4511582a5
"""
        msg_reply.attach(MIMEText(body_reply, 'plain'))

        # Send both via Gmail SMTP
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASS)
            server.send_message(msg_to_vikas)
            server.send_message(msg_reply)

        return jsonify({'success': True, 'message': 'Email sent successfully'})

    except smtplib.SMTPAuthenticationError:
        return jsonify({'error': 'Gmail authentication failed. Check app password.'}), 500
    except Exception as e:
        return jsonify({'error': f'Failed to send email: {str(e)}'}), 500

# ── PROJECTS ──
@app.route('/api/projects', methods=['GET'])
def get_projects():
    conn = get_db()
    rows = conn.execute('SELECT * FROM projects ORDER BY created_at ASC').fetchall()
    conn.close()
    result = []
    for r in rows:
        result.append({
            'id':       r['id'],
            'title':    r['title'],
            'nodes':    r['nodes'],
            'desc':     r['desc'],
            'stack':    json.loads(r['stack'] or '[]'),
            'overview': r['overview'],
            'stages':   json.loads(r['stages'] or '[]')
        })
    return jsonify(result)

@app.route('/api/projects', methods=['POST'])
@require_auth
def add_project():
    data = request.get_json()
    if not data or not data.get('title'):
        return jsonify({'error': 'Title is required'}), 400
    conn = get_db()
    conn.execute(
        'INSERT INTO projects (title,nodes,desc,stack,overview,stages) VALUES (?,?,?,?,?,?)',
        (data['title'], data.get('nodes','?'), data.get('desc',''),
         json.dumps(data.get('stack',[])), data.get('overview',''),
         json.dumps(data.get('stages',[])))
    )
    conn.commit()
    new_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    conn.close()
    return jsonify({'success': True, 'id': new_id}), 201

@app.route('/api/projects/<int:pid>', methods=['DELETE'])
@require_auth
def delete_project(pid):
    conn = get_db()
    conn.execute('DELETE FROM projects WHERE id=?', (pid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ── EXPERIENCES ──
@app.route('/api/experiences', methods=['GET'])
def get_experiences():
    conn = get_db()
    rows = conn.execute('SELECT * FROM experiences ORDER BY created_at ASC').fetchall()
    conn.close()
    result = []
    for r in rows:
        result.append({
            'id':       r['id'],
            'company':  r['company'],
            'role':     r['role'],
            'startISO': r['start_iso'],
            'endISO':   r['end_iso'],
            'location': r['location'],
            'type':     r['type'],
            'bullets':  json.loads(r['bullets'] or '[]'),
            'skills':   json.loads(r['skills'] or '[]')
        })
    return jsonify(result)

@app.route('/api/experiences', methods=['POST'])
@require_auth
def add_experience():
    data = request.get_json()
    if not data or not data.get('company') or not data.get('role'):
        return jsonify({'error': 'Company and role are required'}), 400
    conn = get_db()
    conn.execute(
        'INSERT INTO experiences (company,role,start_iso,end_iso,location,type,bullets,skills) VALUES (?,?,?,?,?,?,?,?)',
        (data['company'], data['role'], data.get('startISO'), data.get('endISO'),
         data.get('location',''), data.get('type','Full-time'),
         json.dumps(data.get('bullets',[])), json.dumps(data.get('skills',[])))
    )
    conn.commit()
    new_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    conn.close()
    return jsonify({'success': True, 'id': new_id}), 201

@app.route('/api/experiences/<int:eid>', methods=['DELETE'])
@require_auth
def delete_experience(eid):
    conn = get_db()
    conn.execute('DELETE FROM experiences WHERE id=?', (eid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
