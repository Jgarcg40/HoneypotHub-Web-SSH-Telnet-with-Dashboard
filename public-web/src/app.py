from flask import Flask, render_template, request, redirect, url_for, jsonify, session
import os
import json
from datetime import datetime
import re
import logging

app = Flask(__name__)
app.secret_key = 'Wt&9*qX#BvP!2dRz$5hE7mG'


logging.basicConfig(
    filename='/var/log/nginx/honeypot.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


login_attempts = []
usernames_attempted = {}
passwords_attempted = {}


def detect_attacks(data):
    attacks = []
    

    sql_injection_patterns = [
        r"'(\s)*OR(\s)*'", r"--", r";(\s)*DROP", r"UNION(\s)+SELECT",
        r"1(\s)*=(\s)*1", r"admin'--"
    ]
    
    xss_patterns = [
        r"<script>", r"<img(\s)+src", r"javascript:", r"onerror(\s)*=",
        r"alert\(", r"eval\("
    ]
    
    path_traversal_patterns = [
        r"\.\.\/", r"\.\.\\", r"%2e%2e%2f", r"\/etc\/passwd"
    ]
    

    for pattern in sql_injection_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            attacks.append({
                "type": "SQL Injection",
                "details": f"Comando: {data}"
            })
            break
    

    for pattern in xss_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            attacks.append({
                "type": "Cross-Site Scripting (XSS)",
                "details": f"Comando: {data}"
            })
            break
    

    for pattern in path_traversal_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            attacks.append({
                "type": "Path Traversal",
                "details": f"Comando: {data}"
            })
            break
    
    return attacks


def log_activity(activity_type, details, attacks=None):
    timestamp = datetime.now().isoformat()
    client_ip = request.headers.get('X-Real-IP', request.remote_addr)
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    log_entry = {
        "timestamp": timestamp,
        "ip": client_ip,
        "user_agent": user_agent,
        "type": activity_type,
        "details": details
    }
    
    if attacks:
        log_entry["attacks"] = attacks
    

    logging.info(json.dumps(log_entry))
    

    try:
        log_file = '/var/log/nginx/activity_log.json'
        
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = json.load(f)
        else:
            logs = []
        
        logs.append(log_entry)
        
        with open(log_file, 'w') as f:
            json.dump(logs, f, indent=2)
    except Exception as e:
        logging.error(f"Error al guardar log: {str(e)}")

@app.route('/')
def index():
    log_activity("page_visit", {"page": "index"})
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        

        username_attacks = detect_attacks(username)
        password_attacks = detect_attacks(password)
        attacks = username_attacks + password_attacks
        

        login_attempts.append({
            "timestamp": datetime.now().isoformat(),
            "username": username,
            "password": password,
            "ip": request.headers.get('X-Real-IP', request.remote_addr),
            "user_agent": request.headers.get('User-Agent', 'Unknown')
        })
        

        usernames_attempted[username] = usernames_attempted.get(username, 0) + 1
        

        passwords_attempted[password] = passwords_attempted.get(password, 0) + 1
        

        honeytokens = {}
        try:
            honeytokens_file = '/app/honeytokens.json'
            if os.path.exists(honeytokens_file):
                with open(honeytokens_file, 'r') as f:
                    honeytokens = json.load(f)
        except Exception as e:
            logging.error(f"Error al cargar honeytokens: {str(e)}")
        

        is_honeytoken = False
        if username in honeytokens and honeytokens[username] == password:
            is_honeytoken = True
        

        log_activity("login_attempt", {
            "username": username,
            "password": password,
            "success": is_honeytoken
        }, attacks)
        

        try:
            with open('/var/log/nginx/login_attempts.json', 'w') as f:
                json.dump(login_attempts, f, indent=2)
            
            with open('/var/log/nginx/usernames.json', 'w') as f:
                json.dump(usernames_attempted, f, indent=2)
            
            with open('/var/log/nginx/passwords.json', 'w') as f:
                json.dump(passwords_attempted, f, indent=2)
        except Exception as e:
            logging.error(f"Error al guardar datos de login: {str(e)}")
        

        if is_honeytoken:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Credenciales inválidas. Inténtelo de nuevo.")
    
    log_activity("page_visit", {"page": "login"})
    return render_template('login.html')

@app.route('/register')
def register():
    log_activity("page_visit", {"page": "register"})
    return render_template('register.html')

@app.route('/about')
def about():
    log_activity("page_visit", {"page": "about"})
    return render_template('about.html')

@app.route('/contact')
def contact():
    log_activity("page_visit", {"page": "contact"})
    return render_template('contact.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    log_activity("page_visit", {"page": "dashboard", "authenticated": True})
    return render_template('dashboard.html')

@app.route('/api/stats', methods=['GET'])
def get_stats():

    return jsonify({
        "login_attempts": len(login_attempts),
        "unique_usernames": len(usernames_attempted),
        "unique_passwords": len(passwords_attempted)
    })


@app.route('/<path:undefined_route>')
def undefined_routes(undefined_route):
    attacks = detect_attacks(undefined_route)
    log_activity("undefined_route_access", {"route": undefined_route}, attacks)
    return render_template('index.html')

if __name__ == '__main__':

    os.makedirs('/var/log/nginx', exist_ok=True)
    

    for filename, data in [
        ('login_attempts.json', login_attempts),
        ('usernames.json', usernames_attempted),
        ('passwords.json', passwords_attempted),
        ('activity_log.json', [])
    ]:
        filepath = f'/var/log/nginx/{filename}'
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
    
    app.run(host='0.0.0.0', port=5000) 