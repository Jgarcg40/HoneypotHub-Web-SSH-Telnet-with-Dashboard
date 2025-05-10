from flask import Flask, render_template, redirect, request, url_for, flash, jsonify, g, session, Response
import json
import os
import time
import re
import logging
from datetime import datetime
import socket
import requests
import threading
from logging.handlers import RotatingFileHandler
from db import mongodb_client
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_url_path='/static')
app.secret_key = os.environ.get('SECRET_KEY', 'default_dev_key_change_in_production')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(
            os.path.join('/app/logs', 'honeypot.log'),
            maxBytes=10 * 1024 * 1024,
            backupCount=5
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('honeypot')

LOG_DIR = '/app/logs'
DATA_DIR = '/app/logs'
os.makedirs(LOG_DIR, exist_ok=True)


WEB_REQUESTS_DIR = os.path.join(LOG_DIR, 'web_requests')
os.makedirs(WEB_REQUESTS_DIR, exist_ok=True)


HONEYTOKENS = {}


def load_honeytokens():
    """Carga los honeytokens desde el archivo JSON"""
    global HONEYTOKENS
    
    try:

        honeytokens_file = os.path.join(os.path.dirname(__file__), 'honeytokens.json')
        

        if os.path.exists(honeytokens_file):
            with open(honeytokens_file, 'r') as f:
                HONEYTOKENS = json.load(f)
                logger.info(f"Honeytokens cargados desde archivo JSON. Total: {len(HONEYTOKENS)}")
        else:
            logger.warning(f"Archivo de honeytokens no encontrado: {honeytokens_file}")

            if os.environ.get('FLASK_ENV') == 'development':
                logger.warning("Usando honeytokens por defecto para desarrollo")
                HONEYTOKENS = {
                    "admin_honeypot": "S3cr3tP@ss123!",
                    "test": "test123",
                }
    except Exception as e:
        logger.error(f"Error al cargar honeytokens desde archivo JSON: {e}")

        HONEYTOKENS = {
            "admin_honeypot": "S3cr3tP@ss123!",
            "test": "test123",
        }


load_honeytokens()


IPINFO_API_KEY = os.environ.get('IPINFO_API_KEY', '')
IPQUALITYSCORE_API_KEY = os.environ.get('IPQUALITYSCORE_API_KEY', '')

def is_vpn_ip(ip):

    try:

        logger.info(f"Verificando si IP {ip} es de VPN con ipinfo.io")
        response = requests.get(f'https://ipinfo.io/{ip}?token={IPINFO_API_KEY}', timeout=5)
        if response.status_code == 200:
            data = response.json()

            if 'company' in data and 'name' in data['company']:
                company_name = data['company']['name'].lower()
                vpn_keywords = ['vpn', 'proxy', 'hosting', 'cloud', 'anonymous', 'tor', 'exit']
                for keyword in vpn_keywords:
                    if keyword in company_name:
                        logger.info(f"IP {ip} detectada como VPN por nombre de compañía: {company_name}")
                        return True
            

            if 'privacy' in data and data['privacy']:
                privacy = data['privacy'].lower()
                if 'vpn' in privacy or 'proxy' in privacy or 'hosting' in privacy:
                    logger.info(f"IP {ip} detectada como VPN por campo privacy: {privacy}")
                    return True
        

        try:
            vpn_check_url = f"https://ipqualityscore.com/api/json/ip/{IPQUALITYSCORE_API_KEY}/{ip}"
            response = requests.get(vpn_check_url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('vpn') or data.get('proxy') or data.get('tor'):
                    logger.info(f"IP {ip} detectada como VPN por ipqualityscore.com")
                    return True
        except Exception as e:
            logger.warning(f"Error al verificar VPN con ipqualityscore para {ip}: {e}")
            
    except Exception as e:
        logger.warning(f"Error al verificar si IP {ip} es de VPN: {e}")
    
    return False

def get_client_ip():

    headers_to_check = [
        'X-Original-IP',
        'X-Forwarded-For',
        'X-Real-IP',
        'X-Client-IP',
        'CF-Connecting-IP',
        'True-Client-IP'
    ]
    
    for header in headers_to_check:
        ip = request.headers.get(header)
        if ip:

            if header == 'X-Forwarded-For':

                ip = ip.split(',')[0].strip()
            logger.info(f"IP detectada desde cabecera {header}: {ip}")
            

            if ip.startswith(('172.', '192.168.', '10.')):
                public_ip = get_public_ip()
                if public_ip:
                    vpn_detected = is_vpn_ip(public_ip)
                    if vpn_detected:
                        logger.info(f"IP pública {public_ip} detectada como VPN")
                    logger.info(f"Usando IP pública en lugar de IP privada: {public_ip}")
                    return public_ip
            

            vpn_detected = is_vpn_ip(ip)
            if vpn_detected:
                logger.info(f"IP {ip} detectada como VPN")
            return ip
    

    client_ip = request.remote_addr
    logger.info(f"Usando IP de conexión directa: {client_ip}")
    

    if client_ip.startswith(('172.', '192.168.', '10.')):
        public_ip = get_public_ip()
        if public_ip:
            vpn_detected = is_vpn_ip(public_ip)
            if vpn_detected:
                logger.info(f"IP pública {public_ip} detectada como VPN")
            logger.info(f"Usando IP pública en lugar de IP privada: {public_ip}")
            return public_ip


    vpn_detected = is_vpn_ip(client_ip)
    if vpn_detected:
        logger.info(f"IP directa {client_ip} detectada como VPN")
    
    return client_ip

def get_public_ip():

    services = [
        'https://api.ipify.org?format=json',
        'https://ifconfig.me/ip',
        'https://icanhazip.com',
        'https://ident.me',
        'https://api.myip.com'
    ]
    
    for service in services:
        try:
            logger.info(f"Intentando obtener IP pública desde: {service}")
            response = requests.get(service, timeout=3)
            
            if response.status_code == 200:

                content = response.text.strip()

                if content.startswith('{'):
                    try:
                        data = response.json()
                        if 'ip' in data:
                            return data['ip']
                    except:
                        pass
                

                if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', content):
                    return content
            
        except Exception as e:
            logger.warning(f"Error al obtener IP pública desde {service}: {e}")
    
    return None

def is_bot_or_crawler(user_agent):

    if not user_agent:
        return True, "Empty-Agent"
    
    user_agent_lower = user_agent.lower()
    

    bot_patterns = {

        'curl': r'curl/',
        'wget': r'wget/',
        'nmap': r'nmap',
        'nikto': r'nikto',
        'gobuster': r'gobuster',
        'wfuzz': r'wfuzz',
        'burp': r'burp',
        'postman': r'postman',
        'python-requests': r'python-requests|python/|requests/',
        'powershell': r'powershell',
        'httpie': r'httpie',
        'insomnia': r'insomnia',
        

        'googlebot': r'googlebot',
        'bingbot': r'bingbot',
        'baiduspider': r'baiduspider',
        'yandexbot': r'yandex',
        'duckduckbot': r'duckduckbot',
        'applebot': r'applebot',
        'yahoo': r'yahoo! slurp',
        'sogou': r'sogou',
        

        'crawler': r'crawler|spider|bot',
        'slurp': r'slurp',
        'semrushbot': r'semrush',
        'ahrefsbot': r'ahrefs',
        'mj12bot': r'mj12bot',
        'screaming frog': r'screaming frog',
        'majestic': r'majestic',
        'rogerbot': r'rogerbot',
        'dotbot': r'dotbot',
        

        'zap': r'zap',
        'sqlmap': r'sqlmap',
        'acunetix': r'acunetix',
        'nuclei': r'nuclei',
        'nessus': r'nessus',
        'openvas': r'openvas',
        'metasploit': r'metasploit',
        'hydra': r'hydra',
        'dirbuster': r'dirbuster',
        

        'axios': r'axios',
        'go-http': r'go-http',
        'java': r'java/',
        'okhttp': r'okhttp',
        'scrapy': r'scrapy',
        'httpclient': r'httpclient',
        'urllib': r'urllib',
        'fetch': r'fetch/',
        'fasthttp': r'fasthttp',
        'webdriver': r'webdriver|selenium',
        

        'discord': r'discord',
        'telegram': r'telegram',
        'whatsapp': r'whatsapp',
        'facebook': r'facebook',
        'headless': r'headless|phantomjs|puppeteer|playwright',
        'empty': r'^$',
        'testing': r'testing|test|pytest',
        'lambda': r'lambda|aws-sdk',
        'cloudflare': r'cloudflare',
        'monitor': r'monitor|uptime|pingdom|statuscake',
        'wordpress': r'wordpress|wp-probe'
    }
    

    for bot_name, pattern in bot_patterns.items():
        if re.search(pattern, user_agent_lower):
            logger.info(f"Bot/Crawler detectado: {bot_name} - User-Agent: {user_agent}")
            return True, bot_name
    

    browser_signatures = [
        'chrome', 'firefox', 'safari', 'edge', 'opera', 'msie', 'trident',
        'mozilla', 'webkit', 'gecko', 'edg/', 'brave', 'vivaldi', 'seamonkey'
    ]
    

    browser_match = False
    browser_type = None
    for browser in browser_signatures:
        if browser in user_agent_lower:
            browser_match = True
            browser_type = browser
            break
    

    if browser_match:
        logger.info(f"Navegador detectado como bot para honeypot: {browser_type} - User-Agent: {user_agent}")
        return True, f"browser-{browser_type}"
    

    suspicious_patterns = [
        r'(?:^|\s)bot(?:\s|$)',
        r'(?:^|\s)scan(?:\s|$)',
        r'(?<!\w)checker(?!\w)',
        r'(?<!\w)check(?!\w)',
        r'(?<!\w)probe(?!\w)',
        r'(?<!\w)exploit(?!\w)',
        r'(?<!\w)hack(?!\w)',
        r'(?<!\w)vuln(?!\w)',
        r'(?<!\w)recon(?!\w)',
        r'^(?:[a-zA-Z0-9.-]+)$'
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, user_agent_lower):
            logger.info(f"User-Agent sospechoso (patrón sospechoso): {user_agent}")
            return True, "suspicious"
    

    if (not browser_match and len(user_agent) > 5) or len(user_agent) < 20 or len(user_agent) > 500:
        logger.info(f"User-Agent sospechoso (longitud inusual): {user_agent}")
        return True, "unusual-length"
    

    logger.info(f"User-Agent no categorizado tratado como bot: {user_agent}")
    return True, "unknown"

def log_web_request(route):

    try:
        timestamp = datetime.now().isoformat()
        ip = get_client_ip()
        path = request.path
        method = request.method
        user_agent = request.headers.get('User-Agent', 'Unknown')
        referrer = request.headers.get('Referer', '')
        query_string = request.query_string.decode('utf-8', errors='ignore')
        

        post_data = {}
        if method == 'POST':
            if request.form:
                post_data = {key: request.form[key] for key in request.form}
            elif request.json:
                post_data = request.json
        

        is_bot, bot_type = is_bot_or_crawler(user_agent)
        

        is_dangerous_tool = False
        suspicious_tools = {
            "nmap": "Nmap",
            "dirbuster": "DirBuster",
            "nikto": "Nikto",
            "sqlmap": "SQLMap",
            "wpscan": "WPScan",
            "gobuster": "GoBuster",
            "masscan": "Masscan",
            "zgrab": "ZGrab",
            "python-requests": "Python Requests"
        }
        

        if not is_bot:
            for tool, name in suspicious_tools.items():
                if tool.lower() in user_agent.lower():
                    is_dangerous_tool = True
                    bot_type = name
                    is_bot = True
                    break
        

        request_entry = {
            'timestamp': timestamp,
            'ip': ip,
            'path': path,
            'method': method,
            'user_agent': user_agent,
            'referrer': referrer,
            'query_string': query_string,
            'post_data': post_data,
            'route': route,
            'is_bot': is_bot,
            'bot_type': bot_type
        }
        

        suspicious_found = []
        suspicious_params = [
            'sleep', 'union', 'select', 'insert', 'delete', 'update', 'drop', 
            'alert', 'confirm', 'exec', 'eval', 'script', 
            '/etc/passwd', '/etc/shadow', '/proc', '/sys', 
            '../', '..\\', 'file://'
        ]
        

        ip_is_malicious = False
        ip_doc = mongodb_client.find_one('ips', {'ip': ip})
        if ip_doc and ip_doc.get('is_malicious'):
            ip_is_malicious = True
            logger.warning(f"IP maliciosa conocida detectada: {ip}")
            

        mongodb_client.log_web_request(request_entry)
        

        for key, param in request.args.items():
            for sus in suspicious_params:
                if sus in str(param).lower():
                    suspicious_found.append(f"{key}={param}")
        has_suspicious_params = len(suspicious_found) > 0
        

        if is_dangerous_tool or has_suspicious_params or ip_is_malicious:
            attack_entry = request_entry.copy()
            

            if is_dangerous_tool:
                attack_entry['attack_type'] = 'Web Scanning Tool'
                attack_entry['details'] = f"Herramienta de escaneo detectada: {bot_type}"
            elif has_suspicious_params:
                attack_entry['attack_type'] = 'Suspicious Parameters'
                attack_entry['details'] = f"Parámetros: {', '.join(suspicious_found)}"
            elif ip_is_malicious:
                attack_entry['attack_type'] = 'Known Malicious IP'
                attack_entry['details'] = f"IP previamente marcada como maliciosa: {ip}"
            
            attack_entry['is_attack'] = True
            

            if not ip_is_malicious:
                logger.warning(f"Marcando IP como maliciosa debido a actividad sospechosa: {ip}")
                try:
                    mongodb_client.db.ips.update_one(
                        {'ip': ip},
                        {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
                        upsert=True
                    )
                except Exception as e:
                    logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
            

            mongodb_client.register_attack(attack_entry)
                
        return request_entry
    except Exception as e:
        logger.error(f"Error general en log_web_request: {str(e)}")
    

    return None

@app.before_request
def before_request():

    if not request.path.startswith('/static/'):

        route = request.endpoint if request.endpoint else "unknown"

        request_entry = log_web_request(route)

        g.request_entry = request_entry

def log_activity(username, password, ip, user_agent, attacks=None):

    timestamp = datetime.now().isoformat()
    

    login_data = {
        'timestamp': timestamp,
        'username': username,
        'password': password,
        'ip': ip,
        'user_agent': user_agent,
        'attacks': attacks or []
    }
    

    geo_info = {}
    try:
        geo_response = requests.get(f'https://ipinfo.io/{ip}?token={IPINFO_API_KEY}', timeout=5)
        if geo_response.status_code == 200:
            geo_info = geo_response.json()
            login_data['geo_info'] = geo_info
    except Exception as e:
        logger.error(f"Error al obtener información geográfica de IP {ip}: {str(e)}")
    

    is_vpn = is_vpn_ip(ip)
    if is_vpn:
        login_data['is_vpn'] = True
    

    success = mongodb_client.log_login_attempt(login_data)
    
    if success:
        logger.info(f"Intento de login registrado en MongoDB - Usuario: {username}, IP: {ip}")
    else:
        logger.error(f"ERROR CRÍTICO: No se pudo registrar intento de login en MongoDB - Usuario: {username}, IP: {ip}")
        logger.error(f"Asegúrate de que MongoDB está ejecutándose y es accesible")

def detect_attacks(username, password, user_agent):

    attacks = []
    

    sql_patterns = [
        r'\bOR\b.*\b(true|1|1=1)\b', 
        r"--",
        r"'.*--", 
        r";.*--", 
        r"/\*.*\*/",
        r"(?i)UNION.*SELECT",
        r"(?i)INSERT.*INTO",
        r"(?i)DROP.*TABLE",
        r"(?i)DELETE.*FROM",
        r"=\s*['\"]\s*--",
        r"=\s*['\"].*['\"]",
        r"'\s*OR\s*'.*'='",
        r"\"\s*OR\s*\".*\"=\"",
        r"'\s*OR\s*1\s*=\s*1",
        r"\"\s*OR\s*1\s*=\s*1",
        r"OR.*=.*",
        r"'.*='",
        r"\".*=\""
    ]
    
    for pattern in sql_patterns:
        if (username and re.search(pattern, username, re.IGNORECASE)) or (password and re.search(pattern, password, re.IGNORECASE)):
            logger.warning(f"Detección de SQL Injection. Patrón: {pattern}, Username: {username}, Password: {password}")
            attacks.append({
                "type": "SQL Injection",
                "details": f"Comando: {username if re.search(pattern, username, re.IGNORECASE) else password}"
            })
            break
    

    xss_patterns = [
        r"<script.*>",
        r"<\s*script",
        r"<\s*/\s*script\s*>",
        r"javascript:",
        r"onerror=",
        r"onload=",
        r"onclick=",
        r"alert\s*\(",
        r"<\s*img[^>]*src\s*=",
        r"<\s*iframe",
        r"<\s*svg"
    ]
    
    for pattern in xss_patterns:
        if (username and re.search(pattern, username, re.IGNORECASE)) or (password and re.search(pattern, password, re.IGNORECASE)):
            logger.warning(f"Detección de XSS. Patrón: {pattern}, Username: {username}, Password: {password}")
            attacks.append({
                "type": "Cross-Site Scripting (XSS)",
                "details": f"Comando: {username if re.search(pattern, username, re.IGNORECASE) else password}"
            })
            break
    

    if user_agent and re.search(r"(?i)(hydra|medusa|ncrack|brutus|patator)", user_agent):
        logger.warning(f"Detección de herramienta de fuerza bruta. User-Agent: {user_agent}")
        attacks.append({
            "type": "Brute Force",
            "details": f"User-Agent: {user_agent}"
        })
    

    command_patterns = [
        r";.*\b(cat|ls|dir|pwd|cd|rm|mv|cp|chmod|chown)\b",
        r"\|.*\b(cat|ls|dir|pwd|cd|rm|mv|cp|chmod|chown)\b",
        r"\b(cat|ls|dir|pwd|cd|rm|mv|cp|chmod|chown)\b.*\|"
    ]
    
    for pattern in command_patterns:
        if (username and re.search(pattern, username)) or (password and re.search(pattern, password)):
            logger.warning(f"Detección de Command Injection. Patrón: {pattern}, Username: {username}, Password: {password}")
            attacks.append({
                "type": "Command Injection",
                "details": f"Comando: {username if re.search(pattern, username) else password}"
            })
            break
    

    if (username and re.search(r"\.\.(/|\\)", username)) or (password and re.search(r"\.\.(/|\\)", password)):
        logger.warning(f"Detección de Path Traversal. Username: {username}, Password: {password}")
        path_traversal_pattern = r"\.\.(/|\\)"
        is_username_match = username and re.search(path_traversal_pattern, username)
        attacks.append({
            "type": "Path Traversal",
            "details": f"Comando: {username if is_username_match else password}"
        })
    
    if attacks:
        logger.info(f"Ataques detectados: {attacks}")
    
    return attacks if attacks else None

@app.route('/')
def index():

    try:
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error al renderizar index.html: {e}")
        return "Error al cargar la página principal. Por favor, contacte al administrador."

@app.route('/about')
def about():

    try:
        return render_template('about.html')
    except Exception as e:
        logger.error(f"Error al renderizar about.html: {e}")
        return "Error al cargar la página. Por favor, contacte al administrador."

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':

        contact_data = {
            'timestamp': datetime.now().isoformat(),
            'name': request.form.get('name', ''),
            'email': request.form.get('email', ''),
            'phone': request.form.get('phone', ''),
            'subject': request.form.get('subject', ''),
            'message': request.form.get('message', ''),
            'ip': get_client_ip(),
            'user_agent': request.headers.get('User-Agent', 'Unknown')
        }
        

        logger.info(f"Intento de contacto - IP: {contact_data['ip']}, Email: '{contact_data['email']}', Asunto: '{contact_data['subject']}'")
        
        try:

            success = mongodb_client.log_contact_form(contact_data)
            
            if not success:
                logger.error(f"ERROR CRÍTICO: No se pudo registrar formulario de contacto en MongoDB - IP: {contact_data['ip']}, Email: {contact_data['email']}")
                logger.error(f"Asegúrate de que MongoDB está ejecutándose y es accesible")
            

            return render_template('contact_success.html')
        except Exception as e:
            logger.error(f"Error al procesar formulario de contacto: {str(e)}")

            return render_template('contact_success.html')
    
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        logger.info(f"Intento de login - Usuario: {username}")
        

        detected_attacks = detect_attacks(username, password, request.headers.get('User-Agent', ''))
        

        if detected_attacks is None:
            detected_attacks = []
        

        ip = get_client_ip()
        user_agent = request.headers.get('User-Agent', 'Unknown')
        

        is_honey = is_honeytoken(username, password)
        

        if is_honey:

            logger.warning(f"¡ALERTA! Intento de login con honeytoken - Usuario: {username}, IP: {ip}")
            try:

                mongodb_client.db.ips.update_one(
                    {'ip': ip},
                    {'$set': {
                        'is_malicious': True, 
                        'honey_token_attempt': True, 
                        'last_seen': datetime.now().isoformat()
                    }},
                    upsert=True
                )
                

                attack_data = {
                    'timestamp': datetime.now().isoformat(),
                    'ip': ip,
                    'user_agent': user_agent,
                    'attack_type': 'Honey Token',
                    'details': f"Intento de uso de credencial trampa: {username}/{password}",
                    'is_attack': True,
                    'path': request.path
                }
                mongodb_client.register_attack(attack_data)
                
            except Exception as e:
                logger.error(f"Error al marcar IP como maliciosa después de honeytoken: {e}")
            

            log_activity(username, password, ip, user_agent, detected_attacks)
            

            if username == 'admin' and password == 'admin123':
                session['logged_in'] = True
                session['username'] = username
                session['is_admin'] = True
                flash('Login successful', 'success')
                return redirect(url_for('admin_dashboard'))
            else:

                session['logged_in'] = True
                session['username'] = username
                session['is_honeypot'] = True
                flash('Login successful', 'success')
                return redirect(url_for('perfil'))
        

        log_activity(username, password, ip, user_agent, detected_attacks)
        

        flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Ruta para cerrar la sesión del usuario"""

    if session.get('logged_in'):
        ip = get_client_ip()
        user_agent = request.headers.get('User-Agent', 'Unknown')
        username = session.get('username', 'unknown')
        
        try:
            log_activity(username, '', ip, user_agent, [
                {"type": "Logout", "details": f"Cierre de sesión del usuario: {username}"}
            ])
        except Exception as e:
            logger.error(f"Error al registrar cierre de sesión: {e}")
    

    session.clear()
    

    return redirect(url_for('index'))

@app.route('/perfil')
def perfil():

    if not session.get('logged_in') or not session.get('is_honeypot'):
        return redirect(url_for('login'))
    

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    fake_data = {
        'servers': [
            {'name': 'prod-db-01', 'status': 'online', 'ip': '10.0.1.5'},
            {'name': 'prod-web-01', 'status': 'online', 'ip': '10.0.1.10'},
            {'name': 'dev-server', 'status': 'maintenance', 'ip': '10.0.2.15'}
        ],
        'users': [
            {'username': 'admin', 'role': 'administrator'},
            {'username': 'john', 'role': 'developer'},
            {'username': 'backup', 'role': 'system'}
        ],
        'recent_logins': [
            {'username': 'admin', 'time': '2025-04-18 10:23:45', 'ip': '192.168.1.25'},
            {'username': 'john', 'time': '2025-04-18 09:15:30', 'ip': '192.168.1.30'},
            {'username': 'system', 'time': '2025-04-17 22:45:10', 'ip': '192.168.1.100'}
        ]
    }
    

    logger.info(f"Usuario logueado con honeytoken explorando dashboard falso - Usuario: {session.get('username')}, IP: {ip}")
    

    try:

        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {
                'is_malicious': True, 
                'honeypot_interaction': True, 
                'last_seen': datetime.now().isoformat()
            }},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al marcar IP como maliciosa en interacción con honeypot: {e}")
    
    return render_template('fake_dashboard.html', data=fake_data)


@app.route('/fake_dashboard', endpoint='fake_dashboard')
def fake_dashboard_redirect():

    return redirect(url_for('perfil'))

@app.route('/ip-debug')
def ip_debug():

    ip_info = {
        'remote_addr': request.remote_addr,
        'x_forwarded_for': request.headers.get('X-Forwarded-For'),
        'x_real_ip': request.headers.get('X-Real-IP'),
        'x_original_ip': request.headers.get('X-Original-IP'),
        'detected_ip': get_client_ip(),
        'all_headers': dict(request.headers)
    }
    return jsonify(ip_info)


def is_honeytoken(username, password):

    logger.info(f"Honeytokens cargados: {HONEYTOKENS}")
    logger.info(f"Verificando credenciales - Usuario: {username}, Pass: {password}")
    
    if username in HONEYTOKENS and HONEYTOKENS[username] == password:
        logger.warning(f"¡Intento de uso de honeytoken detectado! Username: {username}")
        return True
        

    for token_user, token_pass in HONEYTOKENS.items():
        if password == token_pass and username != token_user:
            logger.warning(f"¡Contraseña de honeytoken detectada con usuario diferente! Username: {username}, Token: {token_user}")
            return True
    
    logger.info(f"No se detectó honeytoken para {username}")
    return False

@app.route('/dashboard')
def admin_dashboard():

    if not session.get('logged_in') or not session.get('is_admin'):
        flash('Acceso denegado. Por favor inicie sesión como administrador.', 'error')
        return redirect(url_for('login'))
    

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    

    logger.info(f"Usuario admin accediendo al dashboard administrativo - Usuario: {session.get('username')}, IP: {ip}")
    

    admin_data = {
        'servers': [
            {'name': 'MongoDB', 'status': 'online', 'ip': '172.19.0.20'},
            {'name': 'Web-Honeypot', 'status': 'online', 'ip': '172.19.0.10'},
            {'name': 'Dashboard', 'status': 'online', 'ip': '127.0.0.1'}
        ],
        'users': [
            {'username': session.get('username', 'admin'), 'role': 'administrator'},
            {'username': 'system', 'role': 'system'},
            {'username': 'backup', 'role': 'system'}
        ],
        'recent_logins': []
    }
    

    try:
        recent_login_attempts = list(mongodb_client.db.login_attempts.find().sort("timestamp", -1).limit(10))
        for login in recent_login_attempts:
            admin_data['recent_logins'].append({
                'username': login.get('username', 'unknown'),
                'time': login.get('timestamp', datetime.now().isoformat()),
                'ip': login.get('ip', 'unknown')
            })
    except Exception as e:
        logger.error(f"Error al obtener intentos de login: {e}")

        admin_data['recent_logins'] = [
            {'username': 'admin', 'time': datetime.now().isoformat(), 'ip': '127.0.0.1'},
            {'username': 'system', 'time': '2023-01-01 00:00:00', 'ip': '127.0.0.1'}
        ]
    
    return render_template('fake_dashboard.html', data=admin_data)


@app.route('/dashboard', endpoint='dashboard')
def dashboard_redirect():

    return redirect(url_for('admin_dashboard'))


@app.route('/.env')
def fake_env_file():

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"Acceso a archivo .env falso desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': '/.env',
        'method': request.method,
        'attack_type': 'Environment File Access',
        'details': 'Intento de acceso a archivo .env',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    try:
        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
    

    env_content = """# Configuración de la aplicación
APP_ENV=production
DEBUG=false
APP_KEY=base64:jW2cjfYOj9hN5z8M3X6tsU9wcBn2BqKR+UFoNwECrbQ=

# Configuración de base de datos (no válida)
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=myapp_db
DB_USERNAME=dbuser
DB_PASSWORD=dbp@ssword123

# Configuración de email (no válida)
MAIL_DRIVER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null

# Claves API (no válidas)
STRIPE_KEY=pk_test_7UaZP0P0vDVmYl3v9lQjZ0Aq00zJcA1qCj
STRIPE_SECRET=sk_test_KpWwB3YlzW4F7Bp9Vp7hL7Aq00Nm4WzCkA
"""
    return Response(env_content, mimetype='text/plain')

@app.route('/config.php')
def fake_config_php():

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"Acceso a archivo config.php falso desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': '/config.php',
        'method': request.method,
        'attack_type': 'Configuration File Access',
        'details': 'Intento de acceso a archivo config.php',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    try:
        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
    

    config_content = """<?php
// Configuración de la base de datos
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'webapp_user');
define('DB_PASSWORD', 'S3cureP@ssw0rd!');
define('DB_NAME', 'webapp_db');

// Intentar conectarse a la base de datos MySQL
$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Verificar conexión
if($mysqli === false){
    die("ERROR: No se pudo conectar. " . $mysqli->connect_error);
}

// Otras configuraciones
define('SITE_URL', 'http://example.com');
define('ADMIN_EMAIL', 'admin@example.com');
define('API_KEY', 'f1a4c168-9B9d-4eF8-aBc1-234d5ef67890');
?>
"""
    return Response(config_content, mimetype='text/plain')

@app.route('/.htpasswd')
def fake_htpasswd():

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"Acceso a archivo .htpasswd falso desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': '/.htpasswd',
        'method': request.method,
        'attack_type': 'Access Control File Access',
        'details': 'Intento de acceso a archivo .htpasswd',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    try:
        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
    

    htpasswd_content = """admin:$apr1$K8eGtX4b$tTR/37Ut8iBGFjAFbPT7N0
user:$apr1$lR54zAj9$8Kn3HxJ3L1YhTvbQm1APA.
webmaster:$apr1$9dTe5Mv8$XpC93aUP3RvDhPKwCCEXk/
developer:$apr1$kD3jNp1$4Ri8OcBZY7Vh8ZXbzKuXm1
"""
    return Response(htpasswd_content, mimetype='text/plain')

@app.route('/.htaccess')
def fake_htaccess():

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"Acceso a archivo .htaccess falso desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': '/.htaccess',
        'method': request.method,
        'attack_type': 'Access Control File Access',
        'details': 'Intento de acceso a archivo .htaccess',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    try:
        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
    

    htaccess_content = """# Secure Directory
AuthType Basic
AuthName "Restricted Area"
AuthUserFile /var/www/.htpasswd
Require valid-user

# Disable directory listing
Options -Indexes

# Block bad bots
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} ^.*(bot|spider|crawler|wget|curl).*$ [NC]
RewriteRule .* - [F,L]

# Protect sensitive files
<FilesMatch "^(wp-config\.php|config\.php|configuration\.php|\.env|\.git)">
Order Allow,Deny
Deny from all
</FilesMatch>

# PHP settings
php_value upload_max_filesize 20M
php_value post_max_size 20M
php_value memory_limit 128M
php_flag display_errors off
"""
    return Response(htaccess_content, mimetype='text/plain')

@app.route('/.git/config')
def fake_git_config():

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"Acceso a archivo .git/config falso desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': '/.git/config',
        'method': request.method,
        'attack_type': 'Git Repository Access',
        'details': 'Intento de acceso a archivo .git/config',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    try:
        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
    

    git_config_content = """[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/example/webapp.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[user]
	name = Developer Name
	email = developer@example.com
[credential]
	helper = store
"""
    return Response(git_config_content, mimetype='text/plain')

@app.route('/.git/index')
def fake_git_index():

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"Acceso a archivo .git/index falso desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': '/.git/index',
        'method': request.method,
        'attack_type': 'Git Repository Access',
        'details': 'Intento de acceso a archivo .git/index',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    try:
        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
    

    fake_binary_data = b'DIRC\x00\x00\x00\x02\x00\x00\x00\x0c\x01\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03'
    fake_binary_data += os.urandom(100)
    
    return Response(fake_binary_data, mimetype='application/octet-stream')

@app.route('/sites/default/<path:subpath>')
def fake_drupal_files(subpath):

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"Acceso a ruta Drupal falsa /sites/default/{subpath} desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': f'/sites/default/{subpath}',
        'method': request.method,
        'attack_type': 'CMS Structure Scanning',
        'details': f'Intento de acceso a archivo Drupal: /sites/default/{subpath}',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    if subpath == 'settings.php':
        settings_content = """<?php
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal_db',
      'username' => 'drupal_user',
      'password' => 'drupal_P@ssw0rd!2023',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
$drupal_hash_salt = 'f8a9sdf7a9s8df7as9df87as9d8f7a9s8df';
$base_url = 'https://example.com';
$update_free_access = FALSE;
$cookie_domain = 'example.com';
"""
        return Response(settings_content, mimetype='text/plain')
    

    return "Access denied", 403


@app.route('/wp-login.php')
def fake_wp_login():

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"Acceso a archivo wp-login.php falso desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': '/wp-login.php',
        'method': request.method,
        'attack_type': 'WordPress Scanning',
        'details': 'Intento de acceso a página de login de WordPress',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    try:
        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
    

    return redirect(url_for('login'))

@app.route('/wp-admin')
@app.route('/wp-admin/')
def fake_wp_admin():

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"Acceso a wp-admin falso desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': '/wp-admin',
        'method': request.method,
        'attack_type': 'WordPress Scanning',
        'details': 'Intento de acceso a panel de administración WordPress',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    try:
        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
    

    return redirect(url_for('login'))

@app.route('/wp-config.php.bak')
def fake_wp_config_bak():

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"Acceso a wp-config.php.bak falso desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': '/wp-config.php.bak',
        'method': request.method,
        'attack_type': 'WordPress Configuration Access',
        'details': 'Intento de acceso a archivo de configuración WordPress de respaldo',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    try:
        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
    

    wp_config_bak = """<?php
/**
 * The base configuration for WordPress
 */

// ** MySQL settings ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress_db' );

/** MySQL database username */
define( 'DB_USER', 'wp_user_2023' );

/** MySQL database password */
define( 'DB_PASSWORD', 'secure_wp_password!2023' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'AUTH_KEY',         'X/JH[V}VgSZ|N+oAwl4@h)0pW+Y>7Dl3C1AKN_nG=IWL-M5~8xG_+5p!s+F}8RA!' );
define( 'SECURE_AUTH_KEY',  'j^v[n~n;G|prW]/p*p-eY$Z-4q;.+m%6a$}R[X.yz:UNid=X#[7%q!|>t-?W(~Q@' );
define( 'LOGGED_IN_KEY',    '3*V5*UX2|]nC:|%<zUm(3;x3_b=h&c+f%Dy-8l1F8VD-T+G&d$Xq=B2D:VH~lc,E' );
define( 'NONCE_KEY',        '}5nz(P?x?y%|B-O)@iHjc.9d|lbNB9H_Dcy7}eJW}GJ*2d,T&:.|g.}k|e;5YC_%' );
define( 'AUTH_SALT',        'J<pIy#Sp:7er{/7d|Qu4#S+8:=?E4A=aW2|Ug+8+WlD4wqUl7$pVK97QV?jG5CWd' );
define( 'SECURE_AUTH_SALT', '!IUP{lOD:t7Y+z7p$l.5.Gd4JP`qXk!~Tr$?(-|(G|W>v=p|qdY6|l+a<oeafHYl' );
define( 'LOGGED_IN_SALT',   '?1C{J;9c1&4vO+{G8c|YvU9OD^D9*U2+KR/-Ug6Y<{Q-G]G+{EZqR)LG<uN=qE.+' );
define( 'NONCE_SALT',       'D{G+6T51r_RX%F8GQ^B|Bd*J;vLY:<~=;HV|=:aeOH+K4eH>jU7-zQ3Z9M=~.8W$' );

$table_prefix = 'wp_';

define( 'WP_DEBUG', false );

/* That's all, stop editing! Happy publishing. */
"""
    return Response(wp_config_bak, mimetype='text/plain')

@app.route('/xmlrpc.php')
def fake_xmlrpc():

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"Acceso a xmlrpc.php falso desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': '/xmlrpc.php',
        'method': request.method,
        'attack_type': 'WordPress XML-RPC Scanning',
        'details': 'Intento de acceso a API XML-RPC de WordPress',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    try:
        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
    

    xmlrpc_response = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>403</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>XML-RPC services are disabled on this site.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
"""
    return Response(xmlrpc_response, mimetype='text/xml')


@app.route('/administrator')
@app.route('/administrator/')
def fake_joomla_admin():

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"Acceso a panel de administración Joomla falso desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': '/administrator',
        'method': request.method,
        'attack_type': 'Joomla Scanning',
        'details': 'Intento de acceso a panel de administración Joomla',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    try:
        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
    

    return redirect(url_for('login'))

@app.route('/admin')
@app.route('/admin/')
def fake_generic_admin():

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"Acceso a panel de administración genérico falso desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': '/admin',
        'method': request.method,
        'attack_type': 'Admin Panel Scanning',
        'details': 'Intento de acceso a panel de administración genérico',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    try:
        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
    

    return redirect(url_for('login'))

@app.route('/phpmyadmin')
@app.route('/phpmyadmin/')
@app.route('/phpMyAdmin')
def fake_phpmyadmin():

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"Acceso a phpMyAdmin falso desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': '/phpmyadmin',
        'method': request.method,
        'attack_type': 'Database Admin Scanning',
        'details': 'Intento de acceso a phpMyAdmin',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    try:
        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
    

    return redirect(url_for('login'))

@app.route('/.well-known/security.txt')
def fake_security_txt():

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"Acceso a security.txt falso desde IP: {ip}, User-Agent: {user_agent}")
    

    request_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': '/.well-known/security.txt',
        'method': request.method,
        'is_bot': True,
        'bot_type': 'Security Scanner'
    }
    mongodb_client.log_web_request(request_entry)
    

    security_txt = """# Security Policy
Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59+00:00
Encryption: https://example.com/pgp-key.txt
Acknowledgements: https://example.com/hall-of-fame
Policy: https://example.com/security-policy
Hiring: https://example.com/jobs
"""
    return Response(security_txt, mimetype='text/plain')

@app.route('/robots.txt')
def robots_txt():

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    

    request_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': '/robots.txt',
        'method': request.method,
        'is_bot': True,
        'bot_type': 'crawler'
    }
    mongodb_client.log_web_request(request_entry)
    

    robots_content = """User-agent: *
Allow: /
Disallow: /private/
Disallow: /admin/
Disallow: /secret/
Disallow: /backup/
Disallow: /wp-admin/
Disallow: /includes/
Disallow: /administrator/

# Honeypot directories
Disallow: /honeypot/
Disallow: /trap/

Sitemap: https://example.com/sitemap.xml
"""
    return Response(robots_content, mimetype='text/plain')


@app.route('/private/')
@app.route('/private/<path:subpath>')
def honeypot_private(subpath=""):

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    path = f"/private/{subpath}" if subpath else "/private/"
    
    logger.warning(f"Acceso a zona privada honeypot {path} desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': path,
        'method': request.method,
        'attack_type': 'Robots.txt Violation',
        'details': 'Intento de acceso a directorio prohibido en robots.txt',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    try:
        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
    

    return "Access denied", 403

@app.route('/secret/')
@app.route('/secret/<path:subpath>')
def honeypot_secret(subpath=""):

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    path = f"/secret/{subpath}" if subpath else "/secret/"
    
    logger.warning(f"Acceso a zona secreta honeypot {path} desde IP: {ip}, User-Agent: {user_agent}")
    

    attack_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user_agent': user_agent,
        'path': path,
        'method': request.method,
        'attack_type': 'Robots.txt Violation',
        'details': 'Intento de acceso a directorio prohibido en robots.txt',
        'is_attack': True
    }
    mongodb_client.register_attack(attack_entry)
    

    try:
        mongodb_client.db.ips.update_one(
            {'ip': ip},
            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
    

    return "Access denied", 403

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False) 