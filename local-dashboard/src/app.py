from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session, send_file
import json
import os
import time
from datetime import datetime, timedelta, timezone
import matplotlib.pyplot as plt
import matplotlib
import requests
import logging
import threading
import re
import io
import base64
import pickle
import signal
import atexit
from collections import Counter, defaultdict
import traceback
import functools
import werkzeug.security
from flask_wtf.csrf import CSRFProtect
from db import mongodb_client
import os
import re
import sys
import time
import json
import random
import logging
import hashlib
import binascii
import functools
import threading
import traceback
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Set
from collections import defaultdict, Counter
import urllib.parse
import socket
import ipaddress
from pathlib import Path
from bson.objectid import ObjectId
import tempfile

matplotlib.use('Agg')

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key_change_in_production')
app.config['DASHBOARD_USER'] = os.environ.get('DASHBOARD_USER', 'admin')
app.config['DASHBOARD_PASSWORD'] = os.environ.get('DASHBOARD_PASSWORD', 'secure_password')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['WTF_CSRF_TIME_LIMIT'] = 3600


app.config['ENABLE_HTTPS'] = os.environ.get('ENABLE_HTTPS', 'false').lower() == 'true'
app.config['SSL_CERT_PATH'] = os.environ.get('SSL_CERT_PATH', '/certs/server.crt')
app.config['SSL_KEY_PATH'] = os.environ.get('SSL_KEY_PATH', '/certs/server.key')

csrf = CSRFProtect(app)

@csrf.exempt
@app.route('/login', methods=['GET', 'POST'])
def login():

    if session.get('logged_in'):
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if (username == app.config['DASHBOARD_USER'] and
            password == app.config['DASHBOARD_PASSWORD']):
            
            session['logged_in'] = True
            session['username'] = username
            session.permanent = True
            
            logger.info(f"Inicio de sesión exitoso para el usuario: {username}")
            

            return redirect('/')
        

        flash('Usuario o contraseña incorrectos. Por favor, inténtalo de nuevo.', 'danger')
        logger.warning(f"Intento de inicio de sesión fallido para el usuario: {username}")
        return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
def logout():

    if session.get('logged_in'):
        username = session.get('username', 'Unknown')
        logger.info(f"Cierre de sesión para el usuario: {username}")
    

    session.clear()
    flash('Has cerrado sesión correctamente.', 'success')
    return redirect(url_for('login'))


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('dashboard')


LOGS_DIR = "/app/logs"
DATA_DIR = "/app/logs"
IPINFO_API_KEY = os.environ.get('IPINFO_API_KEY', '')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')

def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Debes iniciar sesión para acceder a esta página.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

class DashboardData:
    def __init__(self):
        self.login_attempts = []
        self.ip_data = {}
        self.usernames = {}
        self.passwords = {}
        self.activity_logs = []
        self.attack_attempts = {}
        self.events_by_hour = defaultdict(int)
        self.events_by_day = defaultdict(int)
        self.malicious_ips = set()
        self.user_agents = Counter()
        self.countries = Counter()
        self.anonymous_connections = set()
        self.last_updated = None

dashboard_data = DashboardData()

class IPCache:
    def __init__(self, cache_file_path):
        self.cache_file_path = cache_file_path
        self.ip_info_cache = {}
        self.malicious_ip_cache = {}
        self.last_save = datetime.now()
        self.save_interval = timedelta(minutes=5)
        self.load_cache()
    
    def load_cache(self):
        try:
            if os.path.exists(self.cache_file_path):
                with open(self.cache_file_path, 'rb') as f:
                    cache_data = pickle.load(f)
                    self.ip_info_cache = cache_data.get('ip_info', {})
                    self.malicious_ip_cache = cache_data.get('malicious_ip', {})
                    logger.info(f"Caché de IPs cargada: {len(self.ip_info_cache)} entradas de información de IPs y {len(self.malicious_ip_cache)} entradas de IPs maliciosas")
        except Exception as e:
            logger.error(f"Error al cargar la caché de IPs: {str(e)}")
            self.ip_info_cache = {}
            self.malicious_ip_cache = {}
    
    def save_cache(self, force=False):
        now = datetime.now()
        if force or (now - self.last_save) > self.save_interval:
            try:
                cache_data = {
                    'ip_info': self.ip_info_cache,
                    'malicious_ip': self.malicious_ip_cache
                }
                with open(self.cache_file_path, 'wb') as f:
                    pickle.dump(cache_data, f)
                self.last_save = now
                logger.info(f"Caché de IPs guardada: {len(self.ip_info_cache)} entradas de información de IPs y {len(self.malicious_ip_cache)} entradas de IPs maliciosas")
            except Exception as e:
                logger.error(f"Error al guardar la caché de IPs: {str(e)}")
    
    def get_ip_info(self, ip):

        if ip in self.ip_info_cache:
            return self.ip_info_cache[ip]
        
        try:
            response = requests.get(f"https://ipinfo.io/{ip}?token={IPINFO_API_KEY}")
            if response.status_code == 200:
                data = response.json()
                data['cache_time'] = datetime.now().isoformat()
                self.ip_info_cache[ip] = data
                self.save_cache()
                return data
            else:
                logger.warning(f"Error al obtener información de IP {ip}: {response.status_code}")
                data = {"ip": ip, "country": "Unknown", "city": "Unknown", "org": "Unknown", "cache_time": datetime.now().isoformat()}
                self.ip_info_cache[ip] = data
                self.save_cache()
                return data
        except Exception as e:
            logger.error(f"Excepción al obtener información de IP {ip}: {str(e)}")
            data = {"ip": ip, "country": "Unknown", "city": "Unknown", "org": "Unknown", "cache_time": datetime.now().isoformat()}
            self.ip_info_cache[ip] = data
            self.save_cache()
            return data
    
    def is_malicious_ip(self, ip):
        try:
            ip_doc = mongodb_client.find_one('ips', {'ip': ip})
            if ip_doc and ip_doc.get('is_malicious', False):
                logger.info(f"IP {ip} está marcada como maliciosa en la base de datos")
                
                self.malicious_ip_cache[ip] = {
                    'is_malicious': True,
                    'cache_time': datetime.now().isoformat(),
                    'source': 'mongodb'
                }
                
                return True
        except Exception as e:
            logger.error(f"Error al verificar IP maliciosa en MongoDB {ip}: {str(e)}")
        
        if ip in self.malicious_ip_cache:
            return self.malicious_ip_cache[ip].get('is_malicious', False)
        
        try:
            headers = {
                "x-apikey": VIRUSTOTAL_API_KEY
            }
            response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)
            
            is_malicious = False
            if response.status_code == 200:
                data = response.json()
                last_analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious_count = last_analysis_stats.get('malicious', 0)
                is_malicious = malicious_count > 0
            
            self.malicious_ip_cache[ip] = {
                'is_malicious': is_malicious,
                'cache_time': datetime.now().isoformat(),
                'source': 'virustotal'
            }
            
            if is_malicious:
                logger.warning(f"VirusTotal indica que IP {ip} es maliciosa - Actualizando MongoDB")
                try:
                    mongodb_client.db.ips.update_one(
                        {'ip': ip},
                        {'$set': {
                            'is_malicious': True,
                            'last_seen': datetime.now().isoformat(),
                            'virustotal_flagged': True
                        }},
                        upsert=True
                    )
                    
                    attack_data = {
                        'timestamp': datetime.now().isoformat(),
                        'ip': ip,
                        'user_agent': 'Unknown',
                        'attack_type': 'Malicious IP (VirusTotal)',
                        'details': f"IP marcada como maliciosa por VirusTotal",
                        'is_attack': True,
                        'path': '/'
                    }
                    mongodb_client.register_attack(attack_data)
                    
                except Exception as e:
                    logger.error(f"Error al actualizar IP maliciosa en MongoDB después de VirusTotal: {str(e)}")
            
            self.save_cache()
            return is_malicious
        except Exception as e:
            logger.error(f"Error al verificar IP maliciosa {ip} con VirusTotal: {str(e)}")
            self.malicious_ip_cache[ip] = {
                'is_malicious': False,
                'cache_time': datetime.now().isoformat(),
                'error': str(e),
                'source': 'error'
            }
            self.save_cache()
            return False
    
    def flush(self):
        self.save_cache(force=True)

ip_cache = IPCache(os.path.join(LOGS_DIR, 'ip_cache.pkl'))

def get_ip_info(ip):
    if ip in dashboard_data.ip_data:
        return dashboard_data.ip_data[ip]
    
    data = ip_cache.get_ip_info(ip)
    
    dashboard_data.ip_data[ip] = data
    
    if 'country' in data:
        dashboard_data.countries[data['country']] += 1
    
    if is_anonymous_connection(data):
        dashboard_data.anonymous_connections.add(ip)
    
    return data

def check_malicious_ip(ip):
    if ip in dashboard_data.malicious_ips:
        return True
    
    is_malicious = ip_cache.is_malicious_ip(ip)
    
    if is_malicious:
        dashboard_data.malicious_ips.add(ip)
    
    return is_malicious

def is_anonymous_connection(ip_data):
    if not ip_data or 'org' not in ip_data:
        return False
    
    org = ip_data['org'].lower()
    anonymous_keywords = ['vpn', 'tor', 'proxy', 'exit node', 'anonymous', 'relay']
    return any(keyword in org for keyword in anonymous_keywords)

def update_dashboard_data():
    try:
        if not mongodb_client.is_connected():
            logger.warning("No hay conexión con MongoDB. Intentando reconectar...")
            if not mongodb_client.connect():
                logger.error("No se pudo conectar a MongoDB. No se actualizarán los datos.")
                return
        
        dashboard_data.login_attempts = []
        dashboard_data.usernames = {}
        dashboard_data.passwords = {}
        dashboard_data.activity_logs = []
        dashboard_data.ip_data = {}
        dashboard_data.attack_attempts = {}
        dashboard_data.events_by_hour.clear()
        dashboard_data.events_by_day.clear()
        dashboard_data.user_agents.clear()
        dashboard_data.malicious_ips.clear()
        dashboard_data.anonymous_connections.clear()
        
        login_attempts = mongodb_client.find('login_attempts', {}, limit=9999999)
        dashboard_data.login_attempts = login_attempts
        logger.info(f"Cargados {len(login_attempts)} intentos de login desde MongoDB")
        
        activity_logs = mongodb_client.find('web_requests', {}, limit=9999999)
        dashboard_data.activity_logs = activity_logs
        logger.info(f"Cargados {len(activity_logs)} registros de actividad desde MongoDB")
        
        usernames_count = {}
        for attempt in login_attempts:
            username = attempt.get('username', '')
            if username:
                usernames_count[username] = usernames_count.get(username, 0) + 1
        dashboard_data.usernames = usernames_count
        
        passwords_count = {}
        for attempt in login_attempts:
            password = attempt.get('password', '')
            if password:
                passwords_count[password] = passwords_count.get(password, 0) + 1
        dashboard_data.passwords = passwords_count
        
        all_events = []
        all_events.extend(login_attempts)
        

        login_ips_timestamps = {(log.get('ip'), log.get('timestamp')) for log in login_attempts}
        filtered_activity = [log for log in activity_logs 
                             if log.get('type') != 'login_attempt' and 
                                (log.get('ip'), log.get('timestamp')) not in login_ips_timestamps]
        all_events.extend(filtered_activity)
        
        logger.info(f"Total de eventos combinados para análisis: {len(all_events)}")
        
        ips_data = mongodb_client.find('ips', {})
        for ip_doc in ips_data:
            ip = ip_doc.get('ip')
            if ip:
                dashboard_data.ip_data[ip] = ip_doc
                if ip_doc.get('is_malicious'):
                    dashboard_data.malicious_ips.add(ip)
                if ip_doc.get('is_vpn') or is_anonymous_connection(ip_doc):
                    dashboard_data.anonymous_connections.add(ip)
        
        logger.info(f"Cargadas {len(dashboard_data.ip_data)} IPs únicas desde MongoDB")
        
        attack_count = 0
        processed_ips_for_geo = set()

        for log in all_events:
            if 'user_agent' in log:
                dashboard_data.user_agents[log['user_agent']] += 1
            
            if 'timestamp' in log:
                try:
                    timestamp = log['timestamp']
                    dt = None
                    try:
                        dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        try:
                            dt = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f')
                        except ValueError:
                            try:
                                dt = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S')
                            except ValueError:
                                logger.error(f"Error al analizar timestamp: formato no reconocido - {timestamp}")
                                continue
                    
                    if dt:
                        hour_key = dt.strftime('%Y-%m-%d %H:00')
                        day_key = dt.strftime('%Y-%m-%d')
                        dashboard_data.events_by_hour[hour_key] += 1
                        dashboard_data.events_by_day[day_key] += 1
                except Exception as e:
                    logger.error(f"Error al analizar timestamp: {str(e)}")
            
            if 'attacks' in log and log['attacks'] and isinstance(log['attacks'], list):
                for attack in log['attacks']:
                    attack_count += 1
                    attack_type = attack.get('type', 'Unknown Attack Type')
                    
                    if attack_type not in dashboard_data.attack_attempts:
                        dashboard_data.attack_attempts[attack_type] = []
                    
                    attack_info = {
                        'timestamp': log.get('timestamp', ''),
                        'ip': log.get('ip', ''),
                        'username': log.get('username', ''),
                        'password': log.get('password', ''),
                        'user_agent': log.get('user_agent', ''),
                        'details': attack.get('details', 'No details provided')
                    }
                    dashboard_data.attack_attempts[attack_type].append(attack_info)

            ip = log.get('ip')
            if ip and ip != 'unknown' and ip not in processed_ips_for_geo:
                try:
                    ip_info = ip_cache.get_ip_info(ip)
                    
                    is_malicious = ip_cache.is_malicious_ip(ip)
                    
                    is_anonymous = is_anonymous_connection(ip_info)
                    
                    dashboard_data.ip_data[ip] = ip_info
                    
                    if is_malicious:
                        dashboard_data.malicious_ips.add(ip)
                    
                    if is_anonymous:
                        dashboard_data.anonymous_connections.add(ip)
                    
                    if 'country' in ip_info:
                        dashboard_data.countries[ip_info['country']] += 1
                    
                    processed_ips_for_geo.add(ip)
                except Exception as e:
                    logger.error(f"Error al procesar información geográfica de IP {ip}: {str(e)}")
        
        logger.info(f"Procesados {attack_count} ataques en total de los eventos combinados")
        # LOG ADICIONAL:
        logger.info(f"DEBUG update_dashboard_data END: events_by_hour size: {len(dashboard_data.events_by_hour)}, events_by_day size: {len(dashboard_data.events_by_day)}")

        dashboard_data.last_updated = datetime.now().isoformat()
        
        logger.info("Datos del dashboard actualizados correctamente")
        logger.info(f"Intentos de login: {len(dashboard_data.login_attempts)}")
        logger.info(f"Usernames únicos: {len(dashboard_data.usernames)}")
        logger.info(f"Ataques detectados: {sum(len(attacks) for attacks in dashboard_data.attack_attempts.values())}")
        logger.info(f"IPs únicas: {len(dashboard_data.ip_data)}")
        
    except Exception as e:
        logger.error(f"Error al actualizar datos del dashboard: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())

def generate_hourly_events_chart():

    try:
        events_by_hour = defaultdict(int)
        
        today = datetime.now().strftime('%Y-%m-%d')
        logger.info(f"Generando gráfico horario para la fecha: {today}")
        
        if mongodb_client.is_connected():
            try:
                pipeline = [
                    {
                        '$addFields': {
                            'date': {
                                '$dateFromString': {'dateString': '$timestamp', 'onError': None}
                            }
                        }
                    },
                    {
                        '$match': {
                            'date': {'$exists': True, '$ne': None}
                        }
                    },
                    {
                        '$project': {
                            'hour': {
                                '$dateToString': {
                                    'format': '%Y-%m-%d %H:00',
                                    'date': '$date'
                                }
                            },
                            'day': {
                                '$dateToString': {
                                    'format': '%Y-%m-%d',
                                    'date': '$date'
                                }
                            }
                        }
                    },
                    {
                        '$match': {
                            'day': today
                        }
                    },
                    {
                        '$group': {
                            '_id': '$hour',
                            'count': {'$sum': 1}
                        }
                    },
                    {
                        '$sort': {'_id': 1}
                    }
                ]
                
                login_attempts_agg = list(mongodb_client.aggregate('login_attempts', pipeline))
                web_requests_agg = list(mongodb_client.aggregate('web_requests', pipeline))
                attacks_agg = list(mongodb_client.aggregate('attacks', pipeline))
                
                logger.info(f"Resultados de agregación: login_attempts={len(login_attempts_agg)}, web_requests={len(web_requests_agg)}, attacks={len(attacks_agg)}")
                
                for doc in login_attempts_agg:
                    events_by_hour[doc['_id']] += doc['count']
                
                for doc in web_requests_agg:
                    events_by_hour[doc['_id']] += doc['count']
                    
                for doc in attacks_agg:
                    events_by_hour[doc['_id']] += doc['count']
                
                logger.info(f"Generando gráfico horario con {len(events_by_hour)} slots de MongoDB para el día {today}")
                logger.info(f"Events by hour: {dict(events_by_hour)}")
                
                if not events_by_hour:
                    logger.warning(f"No se encontraron resultados con la agregación. Intentando búsqueda directa.")
                    
                    start_of_day = f"{today}T00:00:00"
                    end_of_day = f"{today}T23:59:59"
                    
                    login_attempts = mongodb_client.find('login_attempts', {
                        'timestamp': {'$gte': start_of_day, '$lte': end_of_day}
                    })
                    
                    web_requests = mongodb_client.find('web_requests', {
                        'timestamp': {'$gte': start_of_day, '$lte': end_of_day}
                    })
                    
                    attacks = mongodb_client.find('attacks', {
                        'timestamp': {'$gte': start_of_day, '$lte': end_of_day}
                    })
                    
                    for doc in login_attempts:
                        try:
                            dt = datetime.fromisoformat(doc['timestamp'].replace('Z', '+00:00'))
                            hour_key = f"{today} {dt.hour:02d}:00"
                            events_by_hour[hour_key] += 1
                        except Exception as e:
                            logger.error(f"Error al procesar timestamp: {str(e)}")
                    
                    for doc in web_requests:
                        try:
                            dt = datetime.fromisoformat(doc['timestamp'].replace('Z', '+00:00'))
                            hour_key = f"{today} {dt.hour:02d}:00"
                            events_by_hour[hour_key] += 1
                        except Exception as e:
                            logger.error(f"Error al procesar timestamp: {str(e)}")
                            
                    for doc in attacks:
                        try:
                            dt = datetime.fromisoformat(doc['timestamp'].replace('Z', '+00:00'))
                            hour_key = f"{today} {dt.hour:02d}:00"
                            events_by_hour[hour_key] += 1
                        except Exception as e:
                            logger.error(f"Error al procesar timestamp: {str(e)}")
                    
                    logger.info(f"Búsqueda directa: login_attempts={len(login_attempts) if login_attempts else 0}, web_requests={len(web_requests) if web_requests else 0}, attacks={len(attacks) if attacks else 0}")
                    logger.info(f"Events by hour después de búsqueda directa: {dict(events_by_hour)}")
            except Exception as e:
                logger.error(f"Error al obtener datos de MongoDB para gráfico horario: {str(e)}")
                logger.error(traceback.format_exc())
                filtered_events = {k: v for k, v in dashboard_data.events_by_hour.items() if k.startswith(today)}
                events_by_hour = defaultdict(int, filtered_events)
        else:
            filtered_events = {k: v for k, v in dashboard_data.events_by_hour.items() if k.startswith(today)}
            events_by_hour = defaultdict(int, filtered_events)
            logger.warning("No hay conexión a MongoDB, usando datos en memoria para gráfico horario")

        if not events_by_hour:
            logger.warning(f"No se encontraron eventos para el día {today} para generar el gráfico horario.")
            
            for hour in range(24):
                hour_key = f"{today} {hour:02d}:00"
                events_by_hour[hour_key] = 0
        
        sorted_hours = sorted(events_by_hour.items())
        hours = [h[0].split(' ')[1] for h in sorted_hours]
        counts = [h[1] for h in sorted_hours]

        avg_count = sum(counts) / len(counts) if counts else 0

        plt.figure(figsize=(12, 6), dpi=120)
        plt.style.use('ggplot')
        plt.grid(True, linestyle='--', alpha=0.6, axis='y')

        bars = plt.bar(range(len(hours)), counts, width=0.6, color='#3498db', alpha=0.7)
        for bar in bars:
            bar.set_edgecolor('#2980b9')
            bar.set_linewidth(1.5)
        
        plt.axhline(y=avg_count, color='r', linestyle='-', alpha=0.6,
                   label=f'Promedio: {avg_count:.1f}')
        plt.legend()
        
        plt.xticks(range(len(hours)), hours, rotation=45, fontsize=10)
        plt.yticks(fontsize=10)
        plt.xlabel('Hora', fontsize=14, fontweight='bold')
        plt.ylabel('Número de eventos', fontsize=14, fontweight='bold')
        plt.title(f'Eventos por Hora - {today}', fontsize=18, fontweight='bold', pad=20)
        
        for i, count in enumerate(counts):
            if count > 0:
                plt.annotate(str(count), (i, count), textcoords="offset points",
                             xytext=(0, 5), ha='center', fontsize=11, fontweight='bold',
                             bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))
        
        plt.margins(0.05)
        max_count = max(counts) if counts else 0
        plt.ylim(0, max(max_count * 1.2, 1))
        
        ax = plt.gca()
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_linewidth(0.5)
        ax.spines['bottom'].set_linewidth(0.5)
        
        plt.tight_layout()

        img_bytes = io.BytesIO()
        plt.savefig(img_bytes, format='png', bbox_inches='tight', dpi=120)
        plt.close()
        
        if img_bytes.getbuffer().nbytes == 0:
            logger.error("Hourly chart savefig resulted in 0 bytes.")
            return None
            
        img_bytes.seek(0)
        base64_image = base64.b64encode(img_bytes.getvalue()).decode('utf-8')
        logger.info(f"Hourly chart generated successfully (Length: {len(base64_image)}).")
        return base64_image

    except Exception as e:
        logger.error(f"Error al generar gráfico de eventos por hora: {str(e)}")
        logger.error(traceback.format_exc())
        try:
            plt.close()
        except:
            pass
        return None

def generate_daily_events_chart():
    try:
        events_by_day = defaultdict(int)

        if mongodb_client.is_connected():
            try:
                pipeline = [
                    {
                        '$project': {
                            'day': {
                                '$dateToString': {
                                    'format': '%Y-%m-%d',
                                    'date': {'$dateFromString': {'dateString': '$timestamp'}}
                                }
                            }
                        }
                    },
                    {
                        '$group': {
                            '_id': '$day',
                            'count': {'$sum': 1}
                        }
                    },
                    {
                        '$sort': {'_id': 1}
                    }
                ]
                
                login_attempts_agg = mongodb_client.aggregate('login_attempts', pipeline)
                web_requests_agg = mongodb_client.aggregate('web_requests', pipeline)
                
                for doc in login_attempts_agg:
                    events_by_day[doc['_id']] += doc['count']
                
                for doc in web_requests_agg:
                    events_by_day[doc['_id']] += doc['count']
                
                logger.info(f"Generando gráfico diario con {len(events_by_day)} días de MongoDB")
            except Exception as e:
                logger.error(f"Error al obtener datos de MongoDB para gráfico diario: {str(e)}")
                events_by_day = dashboard_data.events_by_day
        else:
            events_by_day = dashboard_data.events_by_day
            logger.warning("No hay conexión a MongoDB, usando datos en memoria para gráfico diario")

        if not events_by_day:
            logger.warning("No events found to generate daily chart.")
            return None

        sorted_days = sorted(events_by_day.items())
        days = [d[0] for d in sorted_days]
        counts = [d[1] for d in sorted_days]

        avg_count = sum(counts) / len(counts) if counts else 0

        plt.figure(figsize=(12, 6), dpi=120)
        plt.style.use('ggplot')
        plt.grid(True, linestyle='--', alpha=0.6, axis='y')
        
        bars = plt.bar(range(len(days)), counts, width=0.6, color='#198754', alpha=0.7)
        for bar in bars:
            bar.set_edgecolor('#0e6e3a')
            bar.set_linewidth(1.5)
            
        plt.axhline(y=avg_count, color='r', linestyle='-', alpha=0.6,
                   label=f'Promedio: {avg_count:.1f}')
        plt.legend()
        
        plt.xticks(range(len(days)), days, rotation=45, fontsize=10)
        plt.yticks(fontsize=10)
        plt.xlabel('Fecha', fontsize=14, fontweight='bold')
        plt.ylabel('Número de eventos', fontsize=14, fontweight='bold')
        plt.title('Eventos por Día', fontsize=18, fontweight='bold', pad=20)
        
        for i, count in enumerate(counts):
            if count > 0:
                plt.annotate(str(count), (i, count), textcoords="offset points",
                             xytext=(0, 5), ha='center', fontsize=11, fontweight='bold',
                             bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))
        
        plt.margins(0.05)
        max_count = max(counts) if counts else 0
        plt.ylim(0, max(max_count * 1.2, 1))
        
        ax = plt.gca()
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_linewidth(0.5)
        ax.spines['bottom'].set_linewidth(0.5)
        
        plt.tight_layout()

        img_bytes = io.BytesIO()
        plt.savefig(img_bytes, format='png', bbox_inches='tight', dpi=120)
        plt.close()
        
        if img_bytes.getbuffer().nbytes == 0:
            logger.error("Daily chart savefig resulted in 0 bytes.")
            return None
            
        img_bytes.seek(0)
        base64_image = base64.b64encode(img_bytes.getvalue()).decode('utf-8')
        logger.info(f"Daily chart generated successfully (Length: {len(base64_image)}).")
        return base64_image

    except Exception as e:
        logger.error(f"Error al generar gráfico de eventos por día: {str(e)}")
        logger.error(traceback.format_exc())
        try:
            plt.close()
        except:
            pass
        return None


def scheduled_update():
    while True:
        try:
            logger.info("Iniciando actualización periódica de datos...")
            update_dashboard_data()
            ip_cache.save_cache()
            logger.info("Actualización periódica completada con éxito")
        except Exception as e:
            logger.error(f"Error crítico durante la actualización periódica: {str(e)}")
            logger.error(traceback.format_exc())
            time.sleep(5)
        time.sleep(60)

def save_cache_on_exit():
    logger.info("Guardando caché de IPs antes de salir...")
    ip_cache.flush()

atexit.register(save_cache_on_exit)

def signal_handler(sig, frame):
    logger.info(f"Señal recibida: {sig}, guardando caché y saliendo...")
    save_cache_on_exit()
    exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

update_thread = threading.Thread(target=scheduled_update, daemon=True)
update_thread.start()

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/stats')
@login_required
def get_stats():
    try:
        hourly_chart = generate_hourly_events_chart()
        daily_chart = generate_daily_events_chart()


        login_attempts_count = 0
        unique_usernames_count = 0
        unique_passwords_count = 0
        unique_ips_count = 0
        attacks_detected_count = 0
        malicious_ips_count = 0
        anonymous_connections_count = 0
        detected_bots_count = 0
        total_connections_count = 0

        if not mongodb_client.is_connected():
            logger.error("No se pudo conectar a MongoDB")
            if not mongodb_client.connect():
                logger.error("No se pudo reconectar a MongoDB")
                return jsonify({
                    'error': 'No MongoDB connection',
                    'login_attempts': 0, 'unique_usernames': 0, 'unique_passwords': 0, 'unique_ips': 0,
                    'anonymous_connections': 0, 'malicious_ips': 0, 'detected_bots': 0, 'detected_attacks': 0,
                    'total_connections': 0, 'hourly_chart': hourly_chart, 'daily_chart': daily_chart,
                    'last_updated': datetime.now().isoformat()
                })
        

        mongodb_stats = {}
        try:
            login_attempts_count = mongodb_client.count_documents('login_attempts')
            unique_usernames_count = mongodb_client.count_documents('usernames')
            unique_passwords_count = mongodb_client.count_documents('passwords')
            unique_ips_count = mongodb_client.count_documents('ips')
            attacks_detected_count = mongodb_client.count_documents('attacks')
            malicious_ips_count = mongodb_client.count_documents('malicious_ips')
            
            anonymous_connections_count = mongodb_client.count_documents('ips', {'is_vpn': True})
            
            detected_bots_count = mongodb_client.count_documents('web_requests', {'is_bot': True})
            
            total_connections_count = mongodb_client.count_documents('web_requests')
            
            logger.info(f"Stats Count from MongoDB: Logins={login_attempts_count}, Usernames={unique_usernames_count}, "
                    f"Passwords={unique_passwords_count}, IPs={unique_ips_count}, Attacks={attacks_detected_count}, "
                    f"MaliciousIPs={malicious_ips_count}, AnonConnections={anonymous_connections_count}, "
                    f"Bots={detected_bots_count}, TotalConnections={total_connections_count}")
        except Exception as e:
            logger.error(f"Error al obtener estadísticas de MongoDB: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                'error': 'MongoDB query error',
                'login_attempts': 0, 'unique_usernames': 0, 'unique_passwords': 0, 'unique_ips': 0,
                'anonymous_connections': 0, 'malicious_ips': 0, 'detected_bots': 0, 'detected_attacks': 0, 
                'total_connections': 0, 'hourly_chart': hourly_chart, 'daily_chart': daily_chart,
                'last_updated': datetime.now().isoformat()
            })
        
        last_updated_ts = datetime.now().isoformat()

        return jsonify({
            "login_attempts": login_attempts_count,
            "unique_usernames": unique_usernames_count,
            "unique_passwords": unique_passwords_count,
            "unique_ips": unique_ips_count,
            "anonymous_connections": anonymous_connections_count,
            "malicious_ips": malicious_ips_count,
            "detected_bots": detected_bots_count,
            "detected_attacks": attacks_detected_count,
            "total_connections": total_connections_count,
            "hourly_chart": hourly_chart,
            "daily_chart": daily_chart,
            "last_updated": last_updated_ts
        })
    except Exception as e:
        logger.error(f"Error fatal en get_stats: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'error': 'Failed to generate statistics',
            'login_attempts': 0, 'unique_usernames': 0, 'unique_passwords': 0, 'unique_ips': 0,
            'anonymous_connections': 0, 'malicious_ips': 0, 'detected_bots': 0, 'detected_attacks': 0,
            'total_connections': 0, 'hourly_chart': None, 'daily_chart': None,
            'last_updated': datetime.now().isoformat()
        }), 500

@app.route('/api/logins')
@login_required
def get_logins():
    logins = []
    
    if not mongodb_client.is_connected():
        logger.error("No se pudo conectar a MongoDB para obtener logins")
        if not mongodb_client.connect():
            logger.error("No se pudo reconectar a MongoDB para obtener logins")
            return jsonify([])
    
    try:
        login_attempts = mongodb_client.find(
            collection='login_attempts',
            sort=[('timestamp', -1)],
            limit=9999999
        )
        
        if not login_attempts:
            logger.warning("No se encontraron intentos de login en MongoDB")
            return jsonify([])
        
        ip_info_cache = {}
        
        for attempt in login_attempts:
            try:
                ip = attempt.get('ip', 'unknown')
                
                if ip not in ip_info_cache:
                    ip_doc = mongodb_client.find_one('ips', {'ip': ip})
                    
                    is_malicious = False
                    is_anonymous = False
                    country = ''
                    city = ''
                    
                    if ip_doc:
                        is_malicious = ip_doc.get('is_malicious', False)
                        is_anonymous = ip_doc.get('is_vpn', False)
                    
                    ipinfo_data = ip_cache.get_ip_info(ip)
                    country = ipinfo_data.get('country', '')
                    city = ipinfo_data.get('city', '')
                    
                    ip_info_cache[ip] = {
                        'is_malicious': is_malicious,
                        'is_anonymous': is_anonymous,
                        'country': country,
                        'city': city
                    }
                

                ip_info = ip_info_cache[ip]
                
                attacks = attempt.get('attacks', [])
                is_successful_login = False
                for attack in attacks:
                    if attack.get('type') in ['Honey Token', 'Honeypot Interaction']:
                        is_successful_login = True
                        break
                
                if is_successful_login:
                    ip_info['is_malicious'] = True
                    try:
                        mongodb_client.db.ips.update_one(
                            {'ip': ip},
                            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
                            upsert=True
                        )
                    except Exception as e:
                        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
                
                login_info = {
                    'timestamp': attempt.get('timestamp', ''),
                    'username': attempt.get('username', ''),
                    'password': attempt.get('password', ''),
                    'ip': ip,
                    'is_malicious': ip_info['is_malicious'],
                    'is_anonymous': ip_info['is_anonymous'],
                    'country': ip_info['country'],
                    'city': ip_info['city']
                }
                
                if 'password' not in login_info or login_info['password'] is None:
                    login_info['password'] = ''
                
                logins.append(login_info)
            except Exception as e:
                logger.error(f"Error al procesar intento de login: {str(e)}")
        
        return jsonify(logins)
    except Exception as e:
        logger.error(f"Error al obtener intentos de login desde MongoDB: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify([])

@app.route('/api/geo')
@login_required
def get_geo_data():
    geo_data = []
    
    def convert_mongo_id(doc):
        if isinstance(doc, dict):
            for k, v in list(doc.items()):
                if k == '_id':
                    doc[k] = str(v)
                elif isinstance(v, (dict, list)):
                    convert_mongo_id(v)
        elif isinstance(doc, list):
            for item in doc:
                convert_mongo_id(item)
        return doc
    
    try:
        if not mongodb_client.is_connected():
            logger.error("No se pudo conectar a MongoDB para obtener datos geográficos")
            if not mongodb_client.connect():
                logger.error("No se pudo reconectar a MongoDB para obtener datos geográficos")
                return jsonify([])
                
        ip_docs = mongodb_client.find('ips', {})
        
        if not ip_docs:
            logger.warning("No se encontraron IPs en MongoDB")
            return jsonify([])
            
        logger.info(f"Procesando {len(ip_docs)} IPs para información geográfica")
        
        for ip_doc in ip_docs:
            try:
                ip_doc = convert_mongo_id(ip_doc)
                
                ip = ip_doc.get('ip')
                if not ip:
                    continue
                
                try:
                    ipinfo_data = ip_cache.get_ip_info(ip)
                    
                    is_malicious = ip_cache.is_malicious_ip(ip)
                    
                    is_anonymous = ip_doc.get('is_vpn', False) or is_anonymous_connection(ipinfo_data)
                    
                    geo_entry = {
                        'ip': ip,
                        'country': ipinfo_data.get('country', 'Unknown'),
                        'country_code': ipinfo_data.get('country_code', '').lower(),
                        'city': ipinfo_data.get('city', 'Unknown'),
                        'org': ipinfo_data.get('org', 'Unknown'),
                        'count': ip_doc.get('count', 1),
                        'is_malicious': is_malicious,
                        'is_anonymous': is_anonymous,
                        'first_seen': ip_doc.get('first_seen', ''),
                        'last_seen': ip_doc.get('last_seen', '')
                    }
                    
                    geo_data.append(geo_entry)
                except Exception as e:
                    logger.error(f"Error al obtener información de la IP {ip}: {str(e)}")
                
            except Exception as e:
                logger.error(f"Error al procesar datos geográficos para IP {ip}: {str(e)}")
        
        return jsonify(sorted(geo_data, key=lambda x: x['count'], reverse=True))
    except Exception as e:
        logger.error(f"Error al obtener datos geográficos: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify([])

@app.route('/api/attacks')
@login_required
def get_attacks():
    attacks = []
    
    attacking_ips = {}
    
    def convert_mongo_id(doc):
        if isinstance(doc, dict):
            for k, v in list(doc.items()):
                if k == '_id':
                    doc[k] = str(v)
                elif isinstance(v, (dict, list)):
                    convert_mongo_id(v)
        elif isinstance(doc, list):
            for item in doc:
                convert_mongo_id(item)
        return doc
    
    if not mongodb_client.is_connected():
        logger.error("No se pudo conectar a MongoDB para obtener ataques")
        if not mongodb_client.connect():
            logger.error("No se pudo reconectar a MongoDB para obtener ataques")
            return jsonify([])
    
    try:

        attack_docs = mongodb_client.find(
            'attacks', 
            {"attack_type": {"$nin": ["Known Malicious IP"]}},
            limit=9999999
        )
        
        if not attack_docs:
            logger.warning("No se encontraron ataques en MongoDB")
            return jsonify([])
        
        ip_status = {}
        for attack in attack_docs:
            ip = attack.get('ip', 'unknown')
            if ip != 'unknown' and ip not in ip_status:
                ip_doc = mongodb_client.find_one('ips', {'ip': ip})
                is_malicious = ip_cache.is_malicious_ip(ip)
                ipinfo_data = ip_cache.get_ip_info(ip)
                is_anonymous = is_anonymous_connection(ipinfo_data)
                
                ip_status[ip] = {
                    'is_malicious': is_malicious,
                    'is_anonymous': is_anonymous,
                    'ipinfo_data': ipinfo_data,
                    'country': ipinfo_data.get('country', 'Unknown'),
                    'city': ipinfo_data.get('city', 'Unknown'),
                    'org': ipinfo_data.get('org', 'Unknown')
                }
        
        for attack in attack_docs:
            try:
                attack = convert_mongo_id(attack)
                
                ip = attack.get('ip', 'unknown')
                
                ip_data = ip_status.get(ip, {
                    'is_malicious': False,
                    'is_anonymous': False,
                    'ipinfo_data': {},
                    'country': 'Unknown',
                    'city': 'Unknown',
                    'org': 'Unknown'
                })
                
                is_successful_login = False
                if attack.get('attack_type') in ['Honey Token', 'Honeypot Interaction']:
                    is_successful_login = True
                    try:
                        mongodb_client.db.ips.update_one(
                            {'ip': ip},
                            {'$set': {'is_malicious': True, 'last_seen': datetime.now().isoformat()}},
                            upsert=True
                        )
                    except Exception as e:
                        logger.error(f"Error al actualizar IP como maliciosa: {str(e)}")
                    ip_data['is_malicious'] = True
                    
                if ip not in attacking_ips:
                    attacking_ips[ip] = {
                        'count': 1,
                        'is_malicious': ip_data['is_malicious'],
                        'is_anonymous': ip_data['is_anonymous'],
                        'country': ip_data['country'],
                        'city': ip_data['city'],
                        'org': ip_data['org'],
                        'last_seen': attack.get('timestamp', '')
                    }
                else:
                    attacking_ips[ip]['count'] += 1
                    if attack.get('timestamp', '') > attacking_ips[ip]['last_seen']:
                        attacking_ips[ip]['last_seen'] = attack.get('timestamp', '')
                
                try:

                    password = attack.get('password', '')
                    
                    attack_info = {
                        'type': attack.get('attack_type', 'Unknown Attack Type'),
                        'timestamp': attack.get('timestamp', ''),
                        'ip': ip,
                        'ip_info': {
                            'country': ip_data['country'],
                            'city': ip_data['city'],
                            'org': ip_data['org'],
                            'is_malicious': ip_data['is_malicious'],
                            'is_anonymous': ip_data['is_anonymous']
                        },
                        'username': attack.get('username', ''),
                        'user_agent': attack.get('user_agent', ''),
                        'details': attack.get('details', ''),
                        'is_malicious': ip_data['is_malicious'],
                        'is_anonymous': ip_data['is_anonymous']
                    }
                    
                    if password and password.strip():
                        attack_info['password'] = password
                    
                    attacks.append(attack_info)
                except Exception as e:
                    logger.error(f"Error al formatear datos del ataque: {str(e)}")
                
            except Exception as e:
                logger.error(f"Error al procesar ataque: {str(e)}")
        
        attacking_ips_list = []
        for ip, data in attacking_ips.items():
            attacking_ips_list.append({
                'ip': ip,
                'count': data['count'],
                'country': data['country'],
                'city': data['city'],
                'is_malicious': data['is_malicious'],
                'is_anonymous': data['is_anonymous'],
                'org': data['org'],
                'last_seen': data['last_seen'],
                'location': f"{data['city']}, {data['country']}"
            })
        
        attacking_ips_list = sorted(attacking_ips_list, key=lambda x: x['count'], reverse=True)
        
        response_data = {
            'attacks': sorted(attacks, key=lambda x: x['timestamp'], reverse=True),
            'attacking_ips': attacking_ips_list
        }
        
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"Error al obtener ataques de MongoDB: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'attacks': [], 'attacking_ips': []})

@app.route('/api/credentials')
@login_required
def get_credentials():
    try:
        if not mongodb_client.is_connected():
            logger.error("No se pudo conectar a MongoDB para obtener credenciales")
            if not mongodb_client.connect():
                return jsonify({"status": "error", "message": "No se pudo conectar a MongoDB"}), 500
        
        usernames_pipeline = [
            {"$match": {
                "username": {
                    "$exists": True, 
                    "$ne": None, 
                    "$ne": ""
                }
            }},
            {"$group": {"_id": "$username", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        usernames = list(mongodb_client.db.login_attempts.aggregate(usernames_pipeline))
        
        passwords_pipeline = [
            {"$match": {
                "password": {
                    "$exists": True, 
                    "$ne": None, 
                    "$ne": ""
                }
            }},
            {"$group": {"_id": "$password", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        passwords = list(mongodb_client.db.login_attempts.aggregate(passwords_pipeline))
        
        logger.info(f"Credenciales encontradas - Usuarios: {len(usernames)}, Contraseñas: {len(passwords)}")
        if len(usernames) > 0:
            logger.info(f"Primer usuario: {usernames[0]}")
        if len(passwords) > 0:
            logger.info(f"Primera contraseña: {passwords[0]}")
        
        credentials = {
            'usernames': [{"username": u["_id"], "count": u["count"]} for u in usernames if u["_id"]],
            'passwords': [{"password": p["_id"], "count": p["count"]} for p in passwords if p["_id"]]
        }
        
        return jsonify(credentials)
    except Exception as e:
        logger.error(f"Error al obtener credenciales: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/useragents')
@login_required
def get_user_agents():
    agents = [{
        'user_agent': agent,
        'count': count
    } for agent, count in dashboard_data.user_agents.most_common(50)]
    
    return jsonify(agents)

@app.route('/logins')
@login_required
def logins():
    return render_template('logins.html')

@app.route('/attacks')
@login_required
def attacks():
    return render_template('attacks.html')

@app.route('/credentials')
@login_required
def credentials():
    return render_template('credentials.html')

@app.route('/geography')
@login_required
def geography():
    return render_template('geography.html')

@app.route('/bots')
@login_required
def bots():
    return render_template('bots.html')

@app.route('/contacts')
@login_required
def contacts_page():
    return render_template('contacts.html')

@app.route('/api/contacts')
@login_required
def get_contacts():
    try:
        def convert_mongo_id(doc):
            if isinstance(doc, dict):
                for k, v in list(doc.items()):
                    if k == '_id':
                        doc[k] = str(v)
                    elif isinstance(v, (dict, list)):
                        convert_mongo_id(v)
            elif isinstance(doc, list):
                for item in doc:
                    convert_mongo_id(item)
            return doc
        
        if not mongodb_client.is_connected():
            logger.error("No se pudo conectar a MongoDB para obtener contactos")
            if not mongodb_client.connect():
                logger.error("No se pudo reconectar a MongoDB para obtener contactos")
                return jsonify([])
        
        contacts = mongodb_client.find(
            'contacts', 
            {}, 
            sort=[('timestamp', -1)],
            limit=9999999
        )
        
        if not contacts:
            logger.warning("No se encontraron contactos en MongoDB")
            return jsonify([])
        
        contacts = [convert_mongo_id(contact) for contact in contacts]
        
        for contact in contacts:
            try:
                ip = contact.get('ip', 'unknown')
                
                ipinfo_data = ip_cache.get_ip_info(ip)
                
                contact['country'] = ipinfo_data.get('country', '')
                contact['city'] = ipinfo_data.get('city', '')
                
                contact['is_anonymous'] = is_anonymous_connection(ipinfo_data)
                
                contact['is_malicious'] = ip_cache.is_malicious_ip(ip)
            except Exception as e:
                logger.error(f"Error al añadir información geográfica para contacto con IP {ip}: {str(e)}")
        
        return jsonify(contacts)
    except Exception as e:
        logger.error(f"Error al obtener datos de contacto: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify([])

@app.route('/api/bots')
@login_required
def get_bots():
    try:
        def convert_mongo_id(doc):
            try:
                if isinstance(doc, dict):
                    for k, v in list(doc.items()):
                        if k == '_id':
                            doc[k] = str(v)
                        elif isinstance(v, (dict, list)):
                            convert_mongo_id(v)
                elif isinstance(doc, list):
                    for item in doc:
                        convert_mongo_id(item)
                return doc
            except Exception as e:
                logger.error(f"Error al convertir ObjectId: {str(e)}")
                return doc
        
        if not mongodb_client.is_connected():
            logger.error("No se pudo conectar a MongoDB para obtener bots")
            if not mongodb_client.connect():
                logger.error("No se pudo reconectar a MongoDB para obtener bots")
                return jsonify([])
        
        bots_data = mongodb_client.find(
            'web_requests', 
            {'is_bot': True}, 
            sort=[('timestamp', -1)],
            limit=9999999
        )
        
        if not bots_data:
            logger.warning("No se encontraron bots en MongoDB")
            return jsonify([])
        
        enhanced_bots_data = []
        for bot in bots_data:
            try:
                bot_info = dict(bot)
                
                bot_info = convert_mongo_id(bot_info)
                
                if 'timestamp' in bot_info:
                    bot_info['formatted_timestamp'] = bot_info['timestamp']
                
                if 'ip' in bot_info:
                    ip = bot_info['ip']
                    
                    try:
                        ipinfo_data = ip_cache.get_ip_info(ip)
                        
                        is_malicious = ip_cache.is_malicious_ip(ip)
                        
                        is_anonymous = is_anonymous_connection(ipinfo_data)
                        
                        bot_info['country'] = ipinfo_data.get('country', 'Unknown')
                        bot_info['city'] = ipinfo_data.get('city', 'Unknown')
                        bot_info['org'] = ipinfo_data.get('org', 'Unknown')
                        bot_info['is_malicious'] = is_malicious
                        bot_info['is_vpn'] = is_anonymous
                        
                        if ip in dashboard_data.ip_data:
                            dashboard_data.ip_data[ip].update({
                                'country': ipinfo_data.get('country', 'Unknown'),
                                'city': ipinfo_data.get('city', 'Unknown'),
                                'org': ipinfo_data.get('org', 'Unknown')
                            })
                        
                        if is_malicious and ip not in dashboard_data.malicious_ips:
                            dashboard_data.malicious_ips.add(ip)
                        
                        if is_anonymous and ip not in dashboard_data.anonymous_connections:
                            dashboard_data.anonymous_connections.add(ip)
                    except Exception as e:
                        logger.error(f"Error al obtener información de IP {ip}: {str(e)}")
                        bot_info['country'] = 'Unknown'
                        bot_info['city'] = 'Unknown'
                        bot_info['org'] = 'Unknown'
                        bot_info['is_malicious'] = False
                        bot_info['is_vpn'] = False
                
                enhanced_bots_data.append(bot_info)
            except Exception as e:
                logger.error(f"Error al procesar información de bot: {str(e)}")
        
        return jsonify(enhanced_bots_data)
    except Exception as e:
        logger.error(f"Error al obtener datos de bots desde MongoDB: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify([])

@csrf.exempt
@app.route('/api/reset', methods=['POST'])
@login_required
def reset_database():
    try:
        if not mongodb_client.is_connected():
            logger.error("No se pudo conectar a MongoDB para realizar el reseteo")
            if not mongodb_client.connect():
                logger.error("No se pudo reconectar a MongoDB para realizar el reseteo")
                return jsonify({"success": False, "message": "Error de conexión a MongoDB"}), 500
        
        collections_to_reset = [
            'login_attempts',
            'usernames',
            'passwords',
            'web_requests',
            'ips',
            'attacks',
            'malicious_ips',
            'contacts',
            'downloads',
            'malware',
            'download',
            'activity_logs',
            'auth',
            'event',
            'input'
        ]
        
        reset_count = 0
        for collection in collections_to_reset:
            try:
                result = mongodb_client.db[collection].delete_many({})
                reset_count += result.deleted_count
                logger.info(f"Borrados {result.deleted_count} documentos de la colección {collection}")
            except Exception as e:
                logger.error(f"Error al borrar colección {collection}: {str(e)}")
        
        malware_dirs = [
            '/malware_files',
            '/host_malware',
            '/malware_data',
            '/cowrie/var/lib/cowrie/downloads',
            '/cowrie/var/lib/cowrie/tty',
            '/cowrie/dl'
        ]
        
        deleted_files_count = 0
        
        for dir_path in malware_dirs:
            if os.path.exists(dir_path) and os.path.isdir(dir_path):
                try:
                    logger.info(f"Limpiando directorio de malware: {dir_path}")
                    for filename in os.listdir(dir_path):
                        if filename.startswith('.') or os.path.isdir(os.path.join(dir_path, filename)):
                            continue
                        
                        file_path = os.path.join(dir_path, filename)
                        try:
                            os.remove(file_path)
                            deleted_files_count += 1
                            logger.info(f"Archivo de malware eliminado: {file_path}")
                        except Exception as file_error:
                            logger.error(f"Error al eliminar archivo {file_path}: {str(file_error)}")
                except Exception as dir_error:
                    logger.error(f"Error al acceder al directorio {dir_path}: {str(dir_error)}")
                
        try:
            dashboard_data.login_attempts = []
            dashboard_data.usernames = {}
            dashboard_data.passwords = {}
            dashboard_data.activity_logs = []
            dashboard_data.ip_data = {}
            dashboard_data.attack_attempts = {}
            dashboard_data.events_by_hour.clear()
            dashboard_data.events_by_day.clear()
            dashboard_data.user_agents.clear()
            dashboard_data.malicious_ips.clear()
            dashboard_data.anonymous_connections.clear()
            
            update_dashboard_data()
            
            ip_cache.ip_info_cache = {}
            ip_cache.malicious_ip_cache = {}
            ip_cache.flush()
        except Exception as e:
            logger.error(f"Error al limpiar estructuras de datos en memoria: {str(e)}")
        
        return jsonify({
            "success": True, 
            "message": f"Base de datos reseteada correctamente. {reset_count} documentos y {deleted_files_count} archivos de malware eliminados.",
            "count": reset_count,
            "files_deleted": deleted_files_count
        })
    
    except Exception as e:
        logger.error(f"Error durante el reseteo de la base de datos: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route('/api/bot_queries')
@login_required
def get_bot_queries():
    try:
        def convert_mongo_id(doc):
            try:
                if isinstance(doc, dict):
                    for k, v in list(doc.items()):
                        if k == '_id':
                            doc[k] = str(v)
                        elif isinstance(v, (dict, list)):
                            convert_mongo_id(v)
                elif isinstance(doc, list):
                    for item in doc:
                        convert_mongo_id(item)
                return doc
            except Exception as e:
                logger.error(f"Error al convertir ObjectId: {str(e)}")
                return doc
        
        if not mongodb_client.is_connected():
            logger.error("No se pudo conectar a MongoDB para obtener consultas de bots")
            if not mongodb_client.connect():
                logger.error("No se pudo reconectar a MongoDB para obtener consultas de bots")
                return jsonify([])
        
        query_requests = mongodb_client.find(
            'web_requests', 
            {
                '$or': [
                    {'query_string': {'$exists': True, '$ne': ''}},
                    {'post_data': {'$exists': True, '$ne': {}}}
                ]
            }, 
            sort=[('timestamp', -1)],
            limit=9999999
        )
        
        if not query_requests:
            logger.warning("No se encontraron consultas de bots en MongoDB")
            return jsonify([])
        
        enhanced_data = []
        for req in query_requests:
            try:
                req_info = dict(req)
                
                req_info = convert_mongo_id(req_info)
                
                if 'timestamp' in req_info:
                    req_info['formatted_timestamp'] = req_info['timestamp']
                
                if 'ip' in req_info:
                    ip = req_info['ip']
                    
                    try:
                        ipinfo_data = ip_cache.get_ip_info(ip)
                        
                        is_malicious = ip_cache.is_malicious_ip(ip)
                        
                        is_anonymous = is_anonymous_connection(ipinfo_data)
                        
                        req_info['country'] = ipinfo_data.get('country', 'Unknown')
                        req_info['city'] = ipinfo_data.get('city', 'Unknown')
                        req_info['org'] = ipinfo_data.get('org', 'Unknown')
                        req_info['is_malicious'] = is_malicious
                        req_info['is_vpn'] = is_anonymous
                    except Exception as e:
                        logger.error(f"Error al obtener información de IP {ip}: {str(e)}")
                        req_info['country'] = 'Unknown'
                        req_info['city'] = 'Unknown'
                        req_info['org'] = 'Unknown'
                        req_info['is_malicious'] = False
                        req_info['is_vpn'] = False
                
                enhanced_data.append(req_info)
            except Exception as e:
                logger.error(f"Error al procesar información de consulta: {str(e)}")
        
        return jsonify(enhanced_data)
    except Exception as e:
        logger.error(f"Error al obtener datos de consultas desde MongoDB: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify([])

@app.route('/ssh_honeypot')
@login_required
def ssh_honeypot():
    return render_template('ssh_honeypot.html')

@app.route('/api/honeypot_data')
@login_required
def get_honeypot_data():
    try:
        if not mongodb_client.is_connected():
            if not mongodb_client.connect():
                return jsonify([])
        
        data_type = request.args.get('type', 'sessions')
        
        if data_type == 'logins':
            auth_logins = list(mongodb_client.db.auth.find({
                "eventid": {"$in": ["cowrie.login.success", "cowrie.login.failed"]},
                "timestamp": {"$exists": True}
            }).sort('timestamp', -1).limit(100))
            
            processed_logins = []
            for login in auth_logins:
                processed_login = {
                    '_id': str(login['_id']),
                    'protocol': 'telnet' if 'CowrieTelnetTransport' in login.get('system', '') else 'ssh',
                    'ip': login.get('src_ip', 'Desconocido'),
                    'username': login.get('username', 'Desconocido'),
                    'password': login.get('password') if login.get('password') else 'Desconocida',
                    'date': login.get('timestamp', 'N/A'),
                    'timestamp': login.get('timestamp', 'N/A'),
                    'success': login.get('eventid') == 'cowrie.login.success',
                    'message': login.get('message', ''),
                    'session': login.get('session', '')
                }
                
                ipinfo_data = ip_cache.get_ip_info(login.get('src_ip', ''))
                processed_login['country'] = ipinfo_data.get('country', 'Desconocido')
                processed_login['country_code'] = ipinfo_data.get('country_code', '').lower()
                processed_login['city'] = ipinfo_data.get('city', '')
                processed_login['org'] = ipinfo_data.get('org', 'Desconocida')
                processed_login['is_malicious'] = ip_cache.is_malicious_ip(login.get('src_ip', ''))
                processed_login['is_vpn'] = is_anonymous_connection(ipinfo_data)
                
                processed_logins.append(processed_login)
            
            for item in processed_logins:
                if isinstance(item['timestamp'], str):
                    try:
                        dt = datetime.fromisoformat(item['timestamp'].replace('Z', '+00:00'))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        item['datetime_obj'] = dt
                        item['timestamp'] = dt.isoformat()
                    except (ValueError, TypeError):
                        item['datetime_obj'] = datetime.min.replace(tzinfo=timezone.utc)
            
            processed_logins.sort(key=lambda x: x.get('datetime_obj', datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
            
            for item in processed_logins:
                if 'datetime_obj' in item:
                    del item['datetime_obj']
            
            return jsonify(processed_logins)
            
        elif data_type == 'commands':
            ssh_sessions = list(mongodb_client.db["input"].find({
                "system": {"$regex": "SSH", "$options": "i"},
                "eventid": "cowrie.command.input"
            }).sort('timestamp', -1).limit(100))
            
            telnet_sessions = list(mongodb_client.db["input"].find({
                "system": {"$regex": "Telnet", "$options": "i"},
                "eventid": "cowrie.command.input"
            }).sort('timestamp', -1).limit(100))
            
            ssh_commands = []
            telnet_commands = []
            
            for session in ssh_sessions:
                session['_id'] = str(session['_id'])
                session['protocol'] = 'ssh'
                session['ip'] = session.get('src_ip', 'Desconocido')
                session['command'] = session.get('input', session.get('command', 'Comando desconocido'))
                session['date'] = session.get('timestamp', 'N/A')
                session['username'] = session.get('username', 'Desconocido')
                
                ipinfo_data = ip_cache.get_ip_info(session.get('src_ip', ''))
                session['country'] = ipinfo_data.get('country', 'Desconocido')
                session['country_code'] = ipinfo_data.get('country_code', '').lower()
                session['city'] = ipinfo_data.get('city', '')
                session['org'] = ipinfo_data.get('org', 'Desconocida')
                session['is_malicious'] = ip_cache.is_malicious_ip(session.get('src_ip', ''))
                session['is_vpn'] = is_anonymous_connection(ipinfo_data)
                
                ssh_commands.append(session)
            
            for session in telnet_sessions:
                session['_id'] = str(session['_id'])
                session['protocol'] = 'telnet'
                session['ip'] = session.get('src_ip', 'Desconocido')
                session['command'] = session.get('input', session.get('command', 'Comando desconocido'))
                session['date'] = session.get('timestamp', 'N/A')
                session['username'] = session.get('username', 'Desconocido')
                
                ipinfo_data = ip_cache.get_ip_info(session.get('src_ip', ''))
                session['country'] = ipinfo_data.get('country', 'Desconocido')
                session['country_code'] = ipinfo_data.get('country_code', '').lower()
                session['city'] = ipinfo_data.get('city', '')
                session['org'] = ipinfo_data.get('org', 'Desconocida')
                session['is_malicious'] = ip_cache.is_malicious_ip(session.get('src_ip', ''))
                session['is_vpn'] = is_anonymous_connection(ipinfo_data)
                
                telnet_commands.append(session)
            
            combined_commands = ssh_commands + telnet_commands
            combined_commands.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            return jsonify(combined_commands)
            
        else:
            ssh_data = list(mongodb_client.db.sessions.find({
                "protocol": "ssh"
            }).sort('timestamp', -1).limit(100))
            
            telnet_data = list(mongodb_client.db.sessions.find({
                "protocol": "telnet"
            }).sort('timestamp', -1).limit(100))
            
            for item in ssh_data:
                item['_id'] = str(item['_id'])
                item['protocol'] = 'ssh'
                item['ip'] = item.get('src_ip', 'Desconocido')
                item['date'] = item.get('timestamp', 'N/A')
                
                ipinfo_data = ip_cache.get_ip_info(item.get('src_ip', ''))
                item['country'] = ipinfo_data.get('country', 'Desconocido')
                item['country_code'] = ipinfo_data.get('country_code', '').lower()
                item['city'] = ipinfo_data.get('city', '')
                item['org'] = ipinfo_data.get('org', 'Desconocida')
                item['is_malicious'] = ip_cache.is_malicious_ip(item.get('src_ip', ''))
                item['is_vpn'] = is_anonymous_connection(ipinfo_data)
            
            for item in telnet_data:
                item['_id'] = str(item['_id'])
                item['protocol'] = 'telnet'
                item['ip'] = item.get('src_ip', 'Desconocido')
                item['date'] = item.get('timestamp', 'N/A')
                
                ipinfo_data = ip_cache.get_ip_info(item.get('src_ip', ''))
                item['country'] = ipinfo_data.get('country', 'Desconocido')
                item['country_code'] = ipinfo_data.get('country_code', '').lower()
                item['city'] = ipinfo_data.get('city', '')
                item['org'] = ipinfo_data.get('org', 'Desconocida')
                item['is_malicious'] = ip_cache.is_malicious_ip(item.get('src_ip', ''))
                item['is_vpn'] = is_anonymous_connection(ipinfo_data)
            
            combined_data = ssh_data + telnet_data
            
            for item in combined_data:
                if isinstance(item.get('timestamp'), str):
                    try:
                        dt = datetime.fromisoformat(item['timestamp'].replace('Z', '+00:00'))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        item['datetime_obj'] = dt
                    except (ValueError, TypeError):
                        item['datetime_obj'] = datetime.min.replace(tzinfo=timezone.utc)
                else:
                    item['datetime_obj'] = datetime.min.replace(tzinfo=timezone.utc)
            
            combined_data.sort(key=lambda x: x.get('datetime_obj', datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
            
            for item in combined_data:
                if 'datetime_obj' in item:
                    del item['datetime_obj']
            
            ip_cache.save_cache()
            
            return jsonify(combined_data)
        
    except Exception as e:
        logger.error(f"Error al obtener datos de honeypot: {str(e)}")
        return jsonify([])

@app.route('/api/ssh_logins')
@login_required
def get_ssh_logins():
    try:
        if not mongodb_client.is_connected():
            app.logger.error("MongoDB no está conectado")
            if not mongodb_client.connect():
                return jsonify([])
        
        colecciones = mongodb_client.db.list_collection_names()
        app.logger.info(f"Colecciones disponibles: {colecciones}")
        
        todos_eventos = []
        try:
            todos_eventos = list(mongodb_client.db.auth.find({}).sort("timestamp", -1))
            app.logger.info(f"Usando colección 'auth': encontrados {len(todos_eventos)} eventos totales")
        except Exception as e1:
            app.logger.error(f"Error accediendo a colección 'auth': {str(e1)}")
            try:
                todos_eventos = list(mongodb_client.db.login_attempts.find({}).sort("timestamp", -1))
                app.logger.info(f"Usando colección 'login_attempts': encontrados {len(todos_eventos)} eventos totales")
            except Exception as e2:
                app.logger.error(f"Error accediendo a colección 'login_attempts': {str(e2)}")
        
        if todos_eventos:
            app.logger.info(f"Ejemplos de eventos encontrados:")
            for i in range(min(3, len(todos_eventos))):
                evento = todos_eventos[i]
                app.logger.info(f"Evento {i+1}: ID={str(evento.get('_id', ''))}, eventid={evento.get('eventid', '')}, session={evento.get('session', '')}, username={evento.get('username', '')}, password={evento.get('password', '')}")
        
        login_events = [e for e in todos_eventos if e.get('eventid') in ['cowrie.login.success', 'cowrie.login.failed']]
        app.logger.info(f"Eventos de login filtrados: {len(login_events)}")
        
        if not login_events:
            app.logger.warning("No se encontraron intentos de login en ninguna colección")
            return jsonify([])
        
        result = []
        for login in login_events:
            login_data = {
                '_id': str(login.get('_id', '')),
                'session': login.get('session', ''),
                'protocol': 'ssh/telnet',
                'ip': login.get('src_ip', 'Desconocido'),
                'username': login.get('username', 'Desconocido'),
                'password': login.get('password', 'Desconocida'),
                'date': login.get('timestamp', 'N/A'),
                'success': login.get('eventid') == 'cowrie.login.success',
                'message': login.get('message', '')
            }
            
            system = login.get('system', '')
            if system:
                if 'SSH' in system or 'ssh' in system:
                    login_data['protocol'] = 'ssh'
                elif 'Telnet' in system or 'telnet' in system:
                    login_data['protocol'] = 'telnet'
            
            result.append(login_data)
        
        result.sort(key=lambda x: x.get('date', ''), reverse=True)
        
        app.logger.info(f"Se procesaron {len(result)} intentos de login SSH/Telnet")
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error obteniendo logins SSH: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify([])

@app.route('/api/ssh_commands')
@login_required
def get_ssh_commands():
    try:
        commands = list(mongodb_client.db["input"].find({
            "eventid": "cowrie.command.input"
        }).sort('timestamp', -1))
        
        for cmd in commands:
            cmd['_id'] = str(cmd['_id'])
            cmd['protocol'] = cmd.get('system', '').split(',')[0]
            
            cmd['ip'] = cmd.get('src_ip', 'Desconocido')
            cmd['command'] = cmd.get('input', 'Comando desconocido')
            cmd['date'] = cmd.get('timestamp', 'N/A')
            
        return jsonify(commands)
    except Exception as e:
        app.logger.error(f"Error obteniendo comandos SSH: {str(e)}")
        return jsonify([])

@app.route('/api/ssh_malware')
@login_required
def get_ssh_malware():
    try:
        malware_paths = [
        
            '/var/lib/docker/volumes/honeypot-web_cowrie_dl/_data'
        ]
        
        malware_files = []
        malware_path = None
        
        for path in malware_paths:
            if os.path.exists(path):
                malware_path = path
                try:
                    files = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f)) and not f.startswith('.')]
                    if files:
                        app.logger.info(f"Encontrados {len(files)} archivos malware en {path} (excluyendo archivos ocultos)")
                        malware_files = files
                        break
                except Exception as e:
                    app.logger.error(f"Error accediendo a {path}: {str(e)}")
        
        if not malware_files:
            app.logger.warning("No se encontraron archivos malware físicos")
            return jsonify([{
                "_id": "placeholder",
                "ip": "0.0.0.0",
                "protocol": "ssh",
                "filename": "No hay archivos malware disponibles",
                "size": 0,
                "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "shasum": "N/A",
                "message": "No se han capturado archivos malware todavía"
            }])
        
        result = []
        for filename in malware_files:
            file_path = os.path.join(malware_path, filename)
            try:
                file_stats = os.stat(file_path)
                file_size = file_stats.st_size
                file_mtime = datetime.fromtimestamp(file_stats.st_mtime)
                
                malware_data = {
                    '_id': filename,
                    'protocol': 'ssh/telnet',
                    'ip': 'Desconocido',
                    'filename': filename,
                    'size': file_size,
                    'date': file_mtime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    'shasum': filename,
                    'message': f"Archivo malware encontrado en {malware_path}"
                }
                result.append(malware_data)
            except Exception as e:
                app.logger.error(f"Error procesando archivo {filename}: {str(e)}")
        
        result.sort(key=lambda x: x.get('date', ''), reverse=True)
        
        app.logger.info(f"Se procesaron {len(result)} archivos malware desde el sistema de archivos")
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error obteniendo datos de malware: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify([])

@app.route('/api/telnet_logins')
@login_required
def get_telnet_logins():
    try:
        if not mongodb_client.is_connected():
            app.logger.error("MongoDB no está conectado")
            if not mongodb_client.connect():
                return jsonify([])

        telnet_eventos = []
        try:
            telnet_eventos = list(mongodb_client.db.auth.find({
                "system": {"$regex": "Telnet", "$options": "i"}
            }).sort("timestamp", -1))
            app.logger.info(f"Usando colección 'auth' para telnet: encontrados {len(telnet_eventos)} eventos totales")
        except Exception as e1:
            app.logger.error(f"Error accediendo a colección 'auth' para telnet: {str(e1)}")
            try:
                telnet_eventos = list(mongodb_client.db.login_attempts.find({
                    "system": {"$regex": "Telnet", "$options": "i"}
                }).sort("timestamp", -1))
                app.logger.info(f"Usando colección 'login_attempts' para telnet: encontrados {len(telnet_eventos)} eventos totales")
            except Exception as e2:
                app.logger.error(f"Error accediendo a colección 'login_attempts' para telnet: {str(e2)}")
        
        if telnet_eventos:
            app.logger.info(f"Ejemplos de eventos Telnet encontrados:")
            for i in range(min(3, len(telnet_eventos))):
                evento = telnet_eventos[i]
                app.logger.info(f"Evento Telnet {i+1}: ID={str(evento.get('_id', ''))}, eventid={evento.get('eventid', '')}, session={evento.get('session', '')}, username={evento.get('username', '')}, password={evento.get('password', '')}")
        
        telnet_login_events = [e for e in telnet_eventos if e.get('eventid') in ['cowrie.login.success', 'cowrie.login.failed']]
        app.logger.info(f"Eventos de login Telnet filtrados: {len(telnet_login_events)}")
        
        if not telnet_login_events:
            app.logger.warning("No se encontraron intentos de login Telnet en ninguna colección")
            return jsonify([])
        
        result = []
        for login in telnet_login_events:
            login_data = {
                '_id': str(login.get('_id', '')),
                'session': login.get('session', ''),
                'protocol': 'telnet',
                'ip': login.get('src_ip', 'Desconocido'),
                'username': login.get('username', 'Desconocido'),
                'password': login.get('password', 'Desconocida'),
                'date': login.get('timestamp', 'N/A'),
                'success': login.get('eventid') == 'cowrie.login.success',
                'message': login.get('message', '')
            }
            result.append(login_data)
        
        result.sort(key=lambda x: x.get('date', ''), reverse=True)
            
        app.logger.info(f"Se procesaron {len(result)} intentos de login Telnet")
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error obteniendo logins Telnet: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify([])

@app.route('/api/telnet_commands')
@login_required
def get_telnet_commands():
    try:
        commands = list(mongodb_client.db["input"].find({
            "system": {"$regex": "Telnet", "$options": "i"},
            "eventid": "cowrie.command.input"
        }).sort('timestamp', -1))
        
        app.logger.info(f"Se encontraron {len(commands)} comandos Telnet")
        
        result = []
        for cmd in commands:
            command_data = {
                '_id': str(cmd['_id']),
                'protocol': 'telnet',
                'ip': cmd.get('src_ip', 'Desconocido'),
                'command': cmd.get('input', 'Comando desconocido'),
                'date': cmd.get('timestamp', 'N/A'),
                'username': cmd.get('username', 'Desconocido'),
                'session': cmd.get('session', 'N/A')
            }
            result.append(command_data)
            
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error obteniendo comandos Telnet: {str(e)}")
        return jsonify([])

@app.route('/api/telnet_transfers')
@login_required
def get_telnet_transfers():
    try:
        transfers = list(mongodb_client.db.telnet_events.find({"eventid": "telnet.file_download"}).sort('timestamp', -1))
        
        for transfer in transfers:
            transfer['_id'] = str(transfer['_id'])
            transfer['protocol'] = 'telnet'
            
            transfer['ip'] = transfer.get('src_ip', 'Desconocido')
            transfer['date'] = transfer.get('timestamp', 'N/A')
            
        return jsonify(transfers)
    except Exception as e:
        app.logger.error(f"Error obteniendo transferencias Telnet: {str(e)}")
        return jsonify([])

@app.route('/api/telnet_malware')
@login_required
def get_telnet_malware():
    try:
        if not mongodb_client.is_connected():
            if not mongodb_client.connect():
                return jsonify({"status": "error", "message": "No se pudo conectar a MongoDB"}), 500
        
        if malware_id == "placeholder":
            return jsonify({
                "_id": "placeholder",
                "ip": "0.0.0.0",
                "protocol": "telnet",
                "filename": "No disponible",
                "size": 0,
                "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "shasum": "N/A",
                "strings": ["No hay datos disponibles"],
                "hex_view": "<div class='byte-ascii'><div class='byte-hex'>No hay datos disponibles</div></div>"
            })
        
        malware = None
        for collection_name in ["downloads", "malware", "download"]:
            try:
                malware = mongodb_client.db[collection_name].find_one({"_id": ObjectId(malware_id)})
                if malware:
                    app.logger.info(f"Malware {malware_id} encontrado en la colección {collection_name}")
                    break
            except Exception as e:
                app.logger.error(f"Error accediendo a colección {collection_name}: {str(e)}")
        
        if not malware:
            return jsonify({"status": "error", "message": "Archivo malware no encontrado"}), 404
        
        destfile = malware.get('destfile', 'unknown.bin')
        filename = destfile.split('/')[-1] if '/' in destfile else destfile
        
        malware['_id'] = str(malware['_id'])
        
        malware['ip'] = malware.get('src_ip', 'Desconocido')
        malware['filename'] = filename
        malware['destpath'] = malware.get('destfile', '')
        malware['outfile'] = malware.get('outfile', '')
        malware['filesize'] = malware.get('size', 0)
        malware['date'] = malware.get('timestamp', 'N/A')
        malware['protocol'] = 'telnet'
        
        system = malware.get('system', '')
        if 'ssh' in system.lower() and 'telnet' not in system.lower():
            malware['protocol'] = 'ssh'
            
        malware['file_hash'] = malware.get('shasum', 'Desconocido')
        
        outfile_path = malware.get('outfile', '')
        
        possible_paths = []
        if outfile_path:
            possible_paths.append(outfile_path)

            if not outfile_path.startswith('/'):
                possible_paths.append('/' + outfile_path)

            app_dir = os.path.dirname(os.path.abspath(__file__))
            possible_paths.append(os.path.join(app_dir, outfile_path))

            root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            possible_paths.append(os.path.join(root_dir, outfile_path))

            file_name = os.path.basename(outfile_path)
            common_dirs = [
                '/var/lib/cowrie/downloads',
                '/opt/cowrie/var/lib/cowrie/downloads',
                '/home/cowrie/cowrie/var/lib/cowrie/downloads',
                '/app/cowrie/var/lib/cowrie/downloads',
                '/var/lib/docker/volumes/honeypot-web_cowrie_dl/_data',
                '/var/lib/docker/volumes/cowrie_dl/_data'
            ]
            
            docker_volume_dirs = [
                '/malware_files',
                '/host_malware',
                '/malware_data',
                '/var/lib/docker/volumes/honeypot-web_cowrie_dl/_data',
                '/var/lib/docker/volumes/cowrie_dl/_data'
            ]
            for docker_dir in docker_volume_dirs:
                docker_path = os.path.join(docker_dir, file_name)
                possible_paths.append(docker_path)
                app.logger.info(f"Añadiendo ruta a intentar: {docker_path}")
                
                if os.path.exists(docker_path):
                    app.logger.info(f"¡La ruta existe!: {docker_path}")
                    try:
                        with open(docker_path, 'rb') as test_file:
                            file_size = len(test_file.read(10))
                            app.logger.info(f"✅ ¡Archivo leído correctamente! Tamaño inicial: {file_size} bytes")
                    except Exception as read_err:
                        app.logger.error(f"❌ Error al leer archivo: {str(read_err)}")
                else:
                    app.logger.info(f"La ruta no existe: {docker_path}")
            

            for common_dir in common_dirs:
                if os.path.exists(common_dir):
                    possible_paths.append(os.path.join(common_dir, file_name))
        
        found_path = None
        for path in possible_paths:
            if os.path.exists(path):
                found_path = path
                app.logger.info(f"Archivo de malware encontrado en: {path}")
                break
        
        if found_path:
            try:
                app.logger.info(f"Leyendo archivo de malware Telnet: {found_path}")
                
                try:
                    file_type_output = subprocess.check_output(['file', found_path], stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
                    file_type = file_type_output.split(':', 1)[1].strip() if ':' in file_type_output else file_type_output.strip()
                    malware['filetype'] = file_type
                except (subprocess.SubprocessError, FileNotFoundError, IndexError):
                    malware['filetype'] = "Binario (tipo no determinado)"
                
                MAX_SIZE = 102400
                with open(found_path, 'rb') as f:
                    file_content = f.read(MAX_SIZE)
                

                is_binary = False
                try:
                    file_content.decode('utf-8')
                except UnicodeDecodeError:
                    is_binary = True
                
                try:
                    strings_output = subprocess.check_output(['strings', found_path], stderr=subprocess.STDOUT)
                    strings_list = strings_output.decode('utf-8', errors='ignore').splitlines()
                    malware['strings'] = strings_list[:1000] if len(strings_list) > 1000 else strings_list
                except (subprocess.SubprocessError, FileNotFoundError):
                    strings_pattern = re.compile(b'[\x20-\x7E]{4,}')
                    strings_list = [match.group().decode('ascii') for match in strings_pattern.finditer(file_content)]
                    malware['strings'] = strings_list[:1000] if len(strings_list) > 1000 else strings_list
                
                hex_view = ""
                hex_bytes = binascii.hexlify(file_content).decode('utf-8')
                bytes_per_row = 16
                
                for i in range(0, len(hex_bytes), bytes_per_row * 2):
                    row_hex = hex_bytes[i:i + bytes_per_row * 2]
                    hex_chars = [row_hex[j:j+2] for j in range(0, len(row_hex), 2)]
                    hex_str = ' '.join(hex_chars)
                    
                    offset = i // 2
                    offset_str = f"{offset:08x}"
                    
                    ascii_chars = []
                    for j in range(0, len(row_hex), 2):
                        if j < len(row_hex):
                            byte_val = int(row_hex[j:j+2], 16)
                            if 32 <= byte_val <= 126:
                                ascii_chars.append(chr(byte_val))
                            else:
                                ascii_chars.append('.')
                    ascii_str = ''.join(ascii_chars)
                    
                    hex_view += f'<div class="byte-ascii"><div class="byte-offset">{offset_str}: </div><div class="byte-hex">{hex_str}</div><div class="byte-text">{ascii_str}</div></div>\n'
                
                malware['hex_view'] = hex_view
                
                malware['file_size_human'] = formatFileSize(len(file_content))
                malware['file_size_bytes'] = len(file_content)
                
                if 'strings' in malware:
                    extracted_strings = malware['strings']
                    del malware['strings']
                    malware['strings'] = extracted_strings
                
            except Exception as e:
                app.logger.error(f"Error procesando archivo de malware Telnet: {str(e)}")
                app.logger.error(traceback.format_exc())
                malware['processing_error'] = str(e)
                
                malware['strings'] = [
                    f"Error al procesar archivo: {str(e)}",
                    f"Ruta: {found_path}",
                    f"Hash: {malware.get('shasum', 'N/A')}",
                    f"Tamaño: {malware.get('size', 0)} bytes"
                ]
                malware['hex_view'] = "<div class='byte-ascii'><div class='byte-hex'>Error al generar vista hexadecimal</div></div>"
        else:
            app.logger.warning(f"Archivo de malware no encontrado en el sistema: {outfile_path}")
            malware['strings'] = [
                "Archivo no encontrado en el sistema",
                f"Rutas probadas: {', '.join(possible_paths)}",
                f"Hash: {malware.get('shasum', 'N/A')}",
                f"Tamaño: {malware.get('size', 0)} bytes"
            ]
            
            malware['hex_view'] = "<div class='byte-ascii'><div class='byte-hex'>Archivo no encontrado en el sistema. Revisa los permisos o ajusta las rutas de búsqueda.</div></div>"


        if 'country' not in malware and malware.get('ip') and malware.get('ip') != 'Desconocido':
            ip_info = ip_cache.get_ip_info(malware.get('ip'))
            if ip_info:
                malware['country'] = ip_info.get('country', 'Desconocido')
                malware['city'] = ip_info.get('city', '')
                malware['country_code'] = ip_info.get('country_code', '').lower()
                malware['is_malicious'] = ip_info.get('is_malicious', False)
        
        return jsonify(malware)
    except Exception as e:
        logger.error(f"Error al obtener detalles de malware Telnet: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/combined_malware')
@login_required
def get_combined_malware():
    try:
        if not mongodb_client.is_connected():
            if not mongodb_client.connect():
                return jsonify([])
        
        colecciones = mongodb_client.db.list_collection_names()
        app.logger.info(f"Colecciones disponibles para malware combinado: {colecciones}")
        
        malware_by_hash = {}
        
        try:
            downloads = list(mongodb_client.db.downloads.find({}).sort("timestamp", -1))
            app.logger.info(f"Encontrados {len(downloads)} registros en colección 'downloads'")
            
            for item in downloads:
                file_hash = item.get('shasum', '')
                
                if not file_hash:
                    continue
                

                if file_hash in malware_by_hash:
                    existing_timestamp = malware_by_hash[file_hash].get('timestamp', '')
                    current_timestamp = item.get('timestamp', '')
                    if not existing_timestamp or (current_timestamp and current_timestamp > existing_timestamp):
                        pass
                    else:
                        continue
                
                filename = f"{file_hash}.bin"
                
                malware_item = {
                    '_id': str(item['_id']),
                    'protocol': 'ssh',
                    'ip': item.get('src_ip', 'Desconocido'),
                    'filename': filename,
                    'outfile': item.get('outfile', ''),
                    'destpath': item.get('destfile', ''),
                    'filesize': item.get('size', 0),
                    'timestamp': item.get('timestamp', datetime.now().isoformat()),
                    'filetype': 'Binario',
                    'file_hash': file_hash,
                    'message': item.get('message', '')
                }
                

                system = item.get('system', '')
                if 'telnet' in system.lower():
                    malware_item['protocol'] = 'telnet'
                
                if file_hash:
                    possible_paths = [
                        f'/malware_files/{file_hash}',
                        f'/host_malware/{file_hash}'
                    ]
                    
                    for path in possible_paths:
                        if os.path.exists(path):
                            try:
                                real_size = os.path.getsize(path)
                                if real_size > 0:
                                    malware_item['filesize'] = real_size
                                    app.logger.info(f"Actualizado tamaño real del archivo {file_hash}: {real_size} bytes")
                                break
                            except Exception as e:
                                app.logger.error(f"Error al leer tamaño del archivo {path}: {str(e)}")
                
                malware_by_hash[file_hash] = malware_item
                
        except Exception as e:
            app.logger.error(f"Error al acceder a colección 'downloads': {str(e)}")
        
        try:
            if 'malware' in colecciones:
                malware_items = list(mongodb_client.db.malware.find({}).sort("timestamp", -1))
                app.logger.info(f"Encontrados {len(malware_items)} registros en colección 'malware'")
                
                for item in malware_items:
                    file_hash = item.get('shasum', '')
                    
                    if not file_hash:
                        continue
                    

                    if file_hash in malware_by_hash:
                        existing_timestamp = malware_by_hash[file_hash].get('timestamp', '')
                        current_timestamp = item.get('timestamp', '')
                        if not existing_timestamp or (current_timestamp and current_timestamp > existing_timestamp):
                            pass
                        else:
                            continue
                    
                    filename = f"{file_hash}.bin"
                    
                    malware_item = {
                        '_id': str(item['_id']),
                        'protocol': 'ssh',
                        'ip': item.get('src_ip', 'Desconocido'),
                        'filename': filename,
                        'outfile': item.get('outfile', ''),
                        'destpath': item.get('destfile', ''),
                        'filesize': item.get('size', 0),
                        'timestamp': item.get('timestamp', datetime.now().isoformat()),
                        'filetype': 'Binario',
                        'file_hash': file_hash,
                        'message': item.get('message', '')
                    }
                        
                    system = item.get('system', '')
                    if 'telnet' in system.lower():
                        malware_item['protocol'] = 'telnet'
                        
                    if file_hash:
                        possible_paths = [
                            f'/malware_files/{file_hash}',
                            f'/host_malware/{file_hash}'
                        ]
                        
                        for path in possible_paths:
                            if os.path.exists(path):
                                try:
                                    real_size = os.path.getsize(path)
                                    if real_size > 0:
                                        malware_item['filesize'] = real_size
                                        app.logger.info(f"Actualizado tamaño real del archivo {file_hash}: {real_size} bytes")
                                    break
                                except Exception as e:
                                    app.logger.error(f"Error al leer tamaño del archivo {path}: {str(e)}")
                    
                    malware_by_hash[file_hash] = malware_item
                    
        except Exception as e:
            app.logger.error(f"Error al acceder a colección 'malware': {str(e)}")
        
        try:
            malware_dirs = [
                '/malware_files',
                '/host_malware'
            ]
            
            current_time = datetime.now().isoformat()
            
            for dir_path in malware_dirs:
                if os.path.exists(dir_path) and os.path.isdir(dir_path):
                    app.logger.info(f"Escaneando directorio físico: {dir_path}")
                    try:
                        files = os.listdir(dir_path)
                        app.logger.info(f"Encontrados {len(files)} archivos en {dir_path}")
                        
                        for filename in files:
                            if filename.startswith('.') or os.path.isdir(os.path.join(dir_path, filename)):
                                continue
                            
                            file_hash = filename
                            
                            if file_hash in malware_by_hash:
                                continue
                            
                            file_path = os.path.join(dir_path, filename)
                            try:
                                file_stat = os.stat(file_path)
                                file_size = file_stat.st_size
                                file_timestamp = datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                                

                                fake_id = f"physical_{file_hash}"
                                
                                malware_item = {
                                    '_id': fake_id,
                                    'protocol': 'unknown',
                                    'ip': 'Desconocido',
                                    'filename': f"{file_hash}.bin",
                                    'outfile': file_path,
                                    'destpath': '',
                                    'filesize': file_size,
                                    'timestamp': file_timestamp,
                                    'filetype': 'Binario',
                                    'file_hash': file_hash,
                                    'message': 'Archivo encontrado en el sistema de archivos sin registro en MongoDB',
                                    'physical_only': True
                                }
                                
                                malware_by_hash[file_hash] = malware_item
                                app.logger.info(f"Añadido archivo físico sin registro en MongoDB: {file_hash} ({formatFileSize(file_size)})")
                                
                            except Exception as e:
                                app.logger.error(f"Error procesando archivo físico {file_path}: {str(e)}")
                    
                    except Exception as e:
                        app.logger.error(f"Error listando archivos en {dir_path}: {str(e)}")
        
        except Exception as e:
            app.logger.error(f"Error escaneando directorios físicos: {str(e)}")
        
        malware_data = list(malware_by_hash.values())
        
        if not malware_data:
            app.logger.warning("No se encontraron archivos malware")
            return jsonify([{
                "_id": "placeholder",
                "ip": "0.0.0.0",
                "protocol": "ssh/telnet",
                "filename": "No hay archivos malware disponibles",
                "filesize": 0,
                "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "filetype": "N/A",
                "file_hash": "N/A",
                "message": "No se han capturado archivos malware todavía"
            }])
        
        protocol = request.args.get('protocol', 'all')
        if protocol != 'all' and protocol != 'unknown':
            malware_data = [item for item in malware_data if item['protocol'] == protocol]
        
        malware_data.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        app.logger.info(f"Devolviendo {len(malware_data)} registros de malware únicos (agrupados por hash)")
        return jsonify(malware_data)
    except Exception as e:
        logger.error(f"Error obteniendo datos combinados de malware: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify([])

@app.route('/api/ssh_top_ips')
@login_required
def get_ssh_top_ips():
    try:
        if not mongodb_client.is_connected():
            logger.error("No se pudo conectar a MongoDB para obtener top IPs SSH")
            if not mongodb_client.connect():
                return jsonify([])
        
        login_ips = {}
        
        ssh_logins = list(mongodb_client.db.sessions.find({
            "protocol": "ssh",
            "eventid": {"$in": ["cowrie.login.success", "cowrie.login.failed", "cowrie.session.connect"]}
        }, projection={'src_ip': 1, 'timestamp': 1}))
        
        telnet_logins = list(mongodb_client.db.sessions.find({
            "protocol": "telnet",
            "eventid": {"$in": ["cowrie.login.success", "cowrie.login.failed", "telnet.login", "cowrie.session.connect"]}
        }, projection={'src_ip': 1, 'timestamp': 1}))
        
        for login in ssh_logins:
            ip = login.get('src_ip')
            if not ip:
                continue
            
            if ip not in login_ips:

                ipinfo_data = ip_cache.get_ip_info(ip)
                
                login_ips[ip] = {
                    'ip': ip,
                    'country': ipinfo_data.get('country', 'Desconocido'),
                    'city': ipinfo_data.get('city', ''),
                    'country_code': ipinfo_data.get('country_code', '').lower(),
                    'org': ipinfo_data.get('org', 'Desconocida'),
                    'is_malicious': ip_cache.is_malicious_ip(ip),
                    'is_vpn': is_anonymous_connection(ipinfo_data),
                    'ssh_login_count': 0,
                    'telnet_login_count': 0,
                    'ssh_command_count': 0,
                    'telnet_command_count': 0,
                    'malware_count': 0,
                    'last_seen': login.get('timestamp', '')
                }
            
            login_ips[ip]['ssh_login_count'] += 1
            
            if login.get('timestamp') and (not login_ips[ip]['last_seen'] or login.get('timestamp') > login_ips[ip]['last_seen']):
                login_ips[ip]['last_seen'] = login.get('timestamp')
        
        for login in telnet_logins:
            ip = login.get('src_ip')
            if not ip:
                continue
            
            if ip not in login_ips:
                ipinfo_data = ip_cache.get_ip_info(ip)
                
                login_ips[ip] = {
                    'ip': ip,
                    'country': ipinfo_data.get('country', 'Desconocido'),
                    'city': ipinfo_data.get('city', ''),
                    'country_code': ipinfo_data.get('country_code', '').lower(),
                    'org': ipinfo_data.get('org', 'Desconocida'),
                    'is_malicious': ip_cache.is_malicious_ip(ip),
                    'is_vpn': is_anonymous_connection(ipinfo_data),
                    'ssh_login_count': 0,
                    'telnet_login_count': 0,
                    'ssh_command_count': 0,
                    'telnet_command_count': 0,
                    'malware_count': 0,
                    'last_seen': login.get('timestamp', '')
                }
            
            login_ips[ip]['telnet_login_count'] += 1
            
            if login.get('timestamp') and (not login_ips[ip]['last_seen'] or login.get('timestamp') > login_ips[ip]['last_seen']):
                login_ips[ip]['last_seen'] = login.get('timestamp')
        
        ssh_commands = list(mongodb_client.db.sessions.find({
            "protocol": "ssh",
            "eventid": {"$in": ["cowrie.command.input", "cowrie.command.success"]}
        }, projection={'src_ip': 1, 'timestamp': 1}))
        
        for cmd in ssh_commands:
            ip = cmd.get('src_ip')
            if not ip or ip not in login_ips:
                continue
            
            login_ips[ip]['ssh_command_count'] += 1
                
            if cmd.get('timestamp') and (not login_ips[ip]['last_seen'] or cmd.get('timestamp') > login_ips[ip]['last_seen']):
                login_ips[ip]['last_seen'] = cmd.get('timestamp')
        
        telnet_commands = list(mongodb_client.db.sessions.find({
            "protocol": "telnet",
            "eventid": {"$in": ["cowrie.command.input", "cowrie.command.success", "telnet.command"]}
        }, projection={'src_ip': 1, 'timestamp': 1}))
        
        for cmd in telnet_commands:
            ip = cmd.get('src_ip')
            if not ip or ip not in login_ips:
                continue
            
            login_ips[ip]['telnet_command_count'] += 1
            
            if cmd.get('timestamp') and (not login_ips[ip]['last_seen'] or cmd.get('timestamp') > login_ips[ip]['last_seen']):
                login_ips[ip]['last_seen'] = cmd.get('timestamp')
                
        ip_cache.save_cache()
        
        if not login_ips:
            login_ips["192.168.1.1"] = {
                'ip': "192.168.1.1",
                'country': "Ejemplo",
                'city': "Ciudad Ejemplo",
                'country_code': "es",
                'org': "Organización Ejemplo",
                'is_malicious': False,
                'is_vpn': False,
                'ssh_login_count': 1,
                'telnet_login_count': 0,
                'ssh_command_count': 0,
                'telnet_command_count': 0,
                'malware_count': 0,
                'last_seen': datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            }
        
        ip_list = list(login_ips.values())
        ip_list.sort(
            key=lambda x: (x['ssh_login_count'] + x['telnet_login_count'] + x['ssh_command_count'] + x['telnet_command_count'] + x['malware_count']),
            reverse=True
        )
        
        return jsonify(ip_list[:25])
        
    except Exception as e:
        logger.error(f"Error al obtener top IPs SSH/Telnet: {str(e)}")
        return jsonify([])

@app.route('/api/ssh_statistics')
@login_required
def get_ssh_statistics():
    try:
        if not mongodb_client.is_connected():
            logger.error("No se pudo conectar a MongoDB para obtener estadísticas SSH")
            if not mongodb_client.connect():
                return jsonify({})
        
        ssh_statistics = getattr(get_ssh_statistics, 'cached_stats', None)
        
        now = datetime.now()
        if ssh_statistics and hasattr(get_ssh_statistics, 'cache_time'):
            cache_age = (now - get_ssh_statistics.cache_time).total_seconds()
            if cache_age < 60:
                return jsonify(ssh_statistics)
        
        ssh_login_attempts = mongodb_client.db["auth"].count_documents({
            "system": {"$regex": "SSH", "$options": "i"},
            "eventid": {"$in": ["cowrie.login.success", "cowrie.login.failed"]}
        })
        
        telnet_login_attempts = mongodb_client.db["auth"].count_documents({
            "system": {"$regex": "Telnet", "$options": "i"},
            "eventid": {"$in": ["cowrie.login.success", "cowrie.login.failed"]}
        })
        
        # Contar comandos SSH/Telnet usando la colección input
        ssh_commands = mongodb_client.db["input"].count_documents({
            "system": {"$regex": "SSH", "$options": "i"},
            "eventid": {"$in": ["cowrie.command.input"]}
        })
        
        telnet_commands = mongodb_client.db["input"].count_documents({
            "system": {"$regex": "Telnet", "$options": "i"},
            "eventid": {"$in": ["cowrie.command.input"]}
        })
        
        # Contar archivos maliciosos (malware) usando la colección downloads
        ssh_malware = mongodb_client.db["downloads"].count_documents({
            "system": {"$regex": "SSH", "$options": "i"},
            "eventid": "cowrie.session.file_download"
        })
        
        telnet_malware = mongodb_client.db["downloads"].count_documents({
            "system": {"$regex": "Telnet", "$options": "i"},
            "eventid": "cowrie.session.file_download"
        })
        

        try:
            malware_paths = [
                '/var/lib/docker/volumes/honeypot-web_cowrie_dl/_data',
                '/malware_files',
                '/host_malware'
            ]
            
            physical_malware_count = 0
            
            for path in malware_paths:
                if os.path.exists(path) and os.path.isdir(path):
                    try:
                        files = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f)) and not f.startswith('.')]
                        physical_malware_count += len(files)
                        logger.info(f"Contados {len(files)} archivos malware físicos en {path}")
                    except Exception as e:
                        logger.error(f"Error contando archivos en {path}: {str(e)}")
            

            if physical_malware_count > 0:
                logger.info(f"Usando conteo físico para malware: {physical_malware_count} archivos")
                

                total_mongodb_malware = ssh_malware + telnet_malware
                
                if total_mongodb_malware > 0:
                    ssh_ratio = ssh_malware / total_mongodb_malware
                    telnet_ratio = telnet_malware / total_mongodb_malware
                    
                    ssh_malware = int(physical_malware_count * ssh_ratio)
                    telnet_malware = physical_malware_count - ssh_malware
                else:
                    ssh_malware = physical_malware_count
                    telnet_malware = 0
        except Exception as e:
            logger.error(f"Error al contar archivos malware físicos: {str(e)}")
        
        all_ssh_logins = list(mongodb_client.db["auth"].find({
            "system": {"$regex": "SSH", "$options": "i"}
        }, projection={'src_ip': 1, '_id': 0, 'timestamp': 1}))
        
        all_telnet_logins = list(mongodb_client.db["auth"].find({
            "system": {"$regex": "Telnet", "$options": "i"}
        }, projection={'src_ip': 1, '_id': 0, 'timestamp': 1}))
        
        login_events = all_ssh_logins + all_telnet_logins
        
        ssh_usernames = mongodb_client.db["auth"].aggregate([
            {
                "$match": {
                    "username": {
                        "$exists": True, 
                        "$ne": None, 
                        "$ne": "", 
                        "$ne": "desconocido",
                        "$ne": "Desconocida",
                        "$nin": ["Desconocida", "desconocida"],
                        "$not": {"$regex": "GET|HTTP|User-Agent|Mozilla|HEAD|POST|zgrab|Host:|Connection:|Accept:|Accept-Encoding: gzip|Content-"}
                    }
                }
            },
            {
                "$group": {
                    "_id": "$username",
                    "count": {"$sum": 1}
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "username": "$_id",
                    "count": 1
                }
            },
            {
                "$sort": {"count": -1}
            }
        ])
        
        ssh_passwords = mongodb_client.db["auth"].aggregate([
            {
                "$match": {
                    "password": {
                        "$exists": True, 
                        "$ne": None,
                        "$ne": "",
                        "$ne": "desconocida",
                        "$ne": "Desconocida",
                        "$nin": ["Desconocida", "desconocida"],
                        "$not": {"$regex": "GET|HTTP|User-Agent|Mozilla|HEAD|POST|zgrab|Host:|Connection:|Accept:|Accept-Encoding: gzip|Content-|\\*/\\*|[Cc]url"}
                    }
                }
            },
            {
                "$group": {
                    "_id": "$password",
                    "count": {"$sum": 1}
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "password": "$_id",
                    "count": 1
                }
            },
            {
                "$sort": {"count": -1}
            }
        ])
        
        ssh_commands_top = mongodb_client.db["input"].aggregate([
            {
                "$match": {
                    "input": {
                        "$exists": True, 
                        "$ne": None, 
                        "$ne": "", 
                        "$not": {"$regex": "GET|HTTP|User-Agent|Mozilla|HEAD|POST|zgrab|Host:|Connection:|Accept:|Accept-Encoding: gzip|Content-|\\*/\\*|[Cc]url|Desconocida"}
                    },
                    "eventid": "cowrie.command.input"
                }
            },
            {
                "$group": {
                    "_id": "$input",
                    "count": {"$sum": 1}
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "command": "$_id",
                    "count": 1
                }
            },
            {
                "$sort": {"count": -1}
            }
        ])
        
        country_data = {}
        for login in login_events:
            ip = login.get('src_ip', '')
            if not ip:
                continue
                
            ipinfo_data = ip_cache.get_ip_info(ip)
            country = ipinfo_data.get('country', 'Desconocido')
            country_code = ipinfo_data.get('country_code', '').lower()
            
            if country not in country_data:
                country_data[country] = {
                    'country': country,
                    'country_code': country_code,
                    'count': 0
                }
            country_data[country]['count'] += 1
        
        countries_data = list(country_data.values())
        countries_data.sort(key=lambda x: x['count'], reverse=True)
        

        hourly_chart = generate_ssh_hourly_events_chart(all_ssh_logins + all_telnet_logins)
        
        daily_chart = generate_ssh_daily_events_chart(all_ssh_logins + all_telnet_logins)
        
        result = {
            'login_attempts': ssh_login_attempts + telnet_login_attempts,
            'ssh_login_attempts': ssh_login_attempts,
            'telnet_login_attempts': telnet_login_attempts,
            'commands': ssh_commands + telnet_commands,
            'ssh_commands': ssh_commands,
            'telnet_commands': telnet_commands,
            'malware': ssh_malware + telnet_malware,
            'ssh_malware': ssh_malware,
            'telnet_malware': telnet_malware,
            'countries': len(countries_data),
            'countries_data': countries_data,
            'top_usernames': list(ssh_usernames),
            'top_passwords': list(ssh_passwords),
            'top_commands': list(ssh_commands_top),
            'unique_ips': len(set(login.get('src_ip') for login in login_events if login.get('src_ip'))),
            'hourly_chart': hourly_chart,
            'daily_chart': daily_chart,
            'last_updated': datetime.now().isoformat()
        }
        
        get_ssh_statistics.cached_stats = result
        get_ssh_statistics.cache_time = now
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error en get_ssh_statistics: {str(e)}")
        return jsonify(getattr(get_ssh_statistics, 'cached_stats', {}))

def generate_ssh_hourly_events_chart(events):

    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import io
        import base64
        from matplotlib.ticker import MaxNLocator
        import numpy as np
        from collections import defaultdict
        
        if not events or len(events) < 5:
            logger.warning("No hay suficientes eventos para generar el gráfico por hora en SSH/Telnet")
            return None
        
        events_by_hour = defaultdict(int)
        
        today = datetime.now().strftime('%Y-%m-%d')
        logger.info(f"Generando gráfico horario SSH/Telnet para la fecha: {today}")
        
        for event in events:
            timestamp = event.get('timestamp')
            if not timestamp:
                continue
                
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                hour_key = f"{dt.hour:02d}:00"
                events_by_hour[hour_key] += 1
            except (ValueError, TypeError) as e:
                logger.error(f"Error procesando timestamp en gráfico por hora: {str(e)}")
                continue
        
        if not events_by_hour:
            for hour in range(24):
                hour_key = f"{hour:02d}:00"
                events_by_hour[hour_key] = 0
        

        sorted_hours = sorted(events_by_hour.items())
        hours = [h[0] for h in sorted_hours]
        counts = [h[1] for h in sorted_hours]


        avg_count = sum(counts) / len(counts) if counts else 0

        plt.figure(figsize=(12, 6), dpi=120)
        plt.style.use('ggplot')
        plt.grid(True, linestyle='--', alpha=0.6, axis='y')
        
        bars = plt.bar(range(len(hours)), counts, width=0.6, color='#3498db', alpha=0.7)
        for bar in bars:
            bar.set_edgecolor('#2980b9')
            bar.set_linewidth(1.5)
        
        plt.axhline(y=avg_count, color='r', linestyle='-', alpha=0.6,
                   label=f'Promedio: {avg_count:.1f}')
        plt.legend()
        
        plt.xticks(range(len(hours)), hours, rotation=45, fontsize=10)
        plt.yticks(fontsize=10)
        plt.xlabel('Hora', fontsize=14, fontweight='bold')
        plt.ylabel('Número de eventos', fontsize=14, fontweight='bold')
        plt.title(f'Eventos SSH/Telnet por Hora - {today}', fontsize=18, fontweight='bold', pad=20)
        
        for i, count in enumerate(counts):
            if count > 0:
                plt.annotate(str(count), (i, count), textcoords="offset points",
                             xytext=(0, 5), ha='center', fontsize=11, fontweight='bold',
                             bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))
        
        plt.margins(0.05)
        max_count = max(counts) if counts else 0
        plt.ylim(0, max(max_count * 1.2, 1))
        
        ax = plt.gca()
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_linewidth(0.5)
        ax.spines['bottom'].set_linewidth(0.5)
        
        plt.tight_layout()

        img_bytes = io.BytesIO()
        plt.savefig(img_bytes, format='png', bbox_inches='tight', dpi=120)
        img_bytes.seek(0)
        img_base64 = base64.b64encode(img_bytes.read()).decode('utf-8')
        plt.close()
        
        return img_base64
        
    except Exception as e:
        logger.error(f"Error generando gráfico horario SSH/Telnet: {str(e)}")
        return None

def generate_ssh_daily_events_chart(events):

    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
        import io
        import base64
        import numpy as np
        from datetime import timedelta
        from collections import defaultdict
        
        if not events or len(events) < 5:
            logger.warning("No hay suficientes eventos para generar el gráfico por día en SSH/Telnet")
            return None
        
        events_by_day = defaultdict(int)
        
        for event in events:
            timestamp = event.get('timestamp')
            if not timestamp:
                continue
                
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                day_key = dt.strftime('%d/%m')
                events_by_day[day_key] += 1
            except (ValueError, TypeError) as e:
                logger.error(f"Error procesando timestamp en gráfico por día: {str(e)}")
                continue
        
        if len(events_by_day) < 2:
            logger.warning("No hay suficientes días para generar el gráfico en SSH/Telnet")
            return None
            
        sorted_days_data = sorted(events_by_day.items(), key=lambda x: datetime.strptime(x[0], "%d/%m"))
        days = [d[0] for d in sorted_days_data]
        counts = [d[1] for d in sorted_days_data]

        avg_count = sum(counts) / len(counts) if counts else 0

        plt.figure(figsize=(12, 6), dpi=120)
        plt.style.use('ggplot')
        plt.grid(True, linestyle='--', alpha=0.6, axis='y')
        

        bars = plt.bar(range(len(days)), counts, width=0.6, color='#3498db', alpha=0.7)
        for bar in bars:
            bar.set_edgecolor('#2980b9')
            bar.set_linewidth(1.5)
        
        plt.axhline(y=avg_count, color='r', linestyle='-', alpha=0.6,
                   label=f'Promedio: {avg_count:.1f}')
        plt.legend()
        
        plt.xticks(range(len(days)), days, rotation=45, fontsize=10)
        plt.yticks(fontsize=10)
        plt.xlabel('Fecha', fontsize=14, fontweight='bold')
        plt.ylabel('Número de eventos', fontsize=14, fontweight='bold')
        plt.title(f'Eventos SSH/Telnet por Día', fontsize=18, fontweight='bold', pad=20)
        
        for i, count in enumerate(counts):
            if count > 0:
                plt.annotate(str(count), (i, count), textcoords="offset points",
                             xytext=(0, 5), ha='center', fontsize=11, fontweight='bold',
                             bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))
        
        plt.margins(0.05)
        max_count = max(counts) if counts else 0
        plt.ylim(0, max(max_count * 1.2, 1))
        
        ax = plt.gca()
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_linewidth(0.5)
        ax.spines['bottom'].set_linewidth(0.5)
        
        plt.tight_layout()

        img_bytes = io.BytesIO()
        plt.savefig(img_bytes, format='png', bbox_inches='tight', dpi=120)
        img_bytes.seek(0)
        img_base64 = base64.b64encode(img_bytes.read()).decode('utf-8')
        plt.close()
        
        return img_base64
    except Exception as e:
        logger.error(f"Error generando gráfico diario SSH/Telnet: {str(e)}")
        return None

@app.route('/api/ssh_login_details/<login_id>')
@login_required
def get_ssh_login_details(login_id):
    try:
        if not mongodb_client.is_connected():
            if not mongodb_client.connect():
                return jsonify({"status": "error", "message": "No se pudo conectar a MongoDB"}), 500
        
        login = mongodb_client.db["auth"].find_one({"_id": ObjectId(login_id)})
        
        if not login:
            return jsonify({"status": "error", "message": "Login no encontrado"}), 404
        
        login['_id'] = str(login['_id'])
        
        login['ip'] = login.get('src_ip', 'Desconocido')
        login['username'] = login.get('username', 'Desconocido')
        login['password'] = login.get('password', 'Desconocida')
        login['date'] = login.get('timestamp', 'N/A')
        login['protocol'] = login.get('system', '').split(',')[0]
        login['success'] = login.get('eventid') == 'cowrie.login.success'
        

        if 'country' not in login and login.get('ip') and login.get('ip') != 'Desconocido':
            ip_info = ip_cache.get_ip_info(login.get('ip'))
            if ip_info:
                login['country'] = ip_info.get('country', 'Desconocido')
                login['city'] = ip_info.get('city', '')
                login['country_code'] = ip_info.get('country_code', '').lower()
                login['is_malicious'] = ip_info.get('is_malicious', False)
        
        return jsonify(login)
    except Exception as e:
        logger.error(f"Error al obtener detalles de login SSH: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/ssh_command_details/<command_id>')
@login_required
def get_ssh_command_details(command_id):
    try:
        if not mongodb_client.is_connected():
            if not mongodb_client.connect():
                return jsonify({"status": "error", "message": "No se pudo conectar a MongoDB"}), 500
        
        command = mongodb_client.db["input"].find_one({"_id": ObjectId(command_id)})
        
        if not command:
            return jsonify({"status": "error", "message": "Comando no encontrado"}), 404
        
        command['_id'] = str(command['_id'])
        
        command['ip'] = command.get('src_ip', 'Desconocido')
        command['command'] = command.get('input', 'Comando desconocido')
        command['date'] = command.get('timestamp', 'N/A')
        command['protocol'] = command.get('system', '').split(',')[0]
        

        if 'country' not in command and command.get('ip') and command.get('ip') != 'Desconocido':
            ip_info = ip_cache.get_ip_info(command.get('ip'))
            if ip_info:
                command['country'] = ip_info.get('country', 'Desconocido')
                command['city'] = ip_info.get('city', '')
                command['country_code'] = ip_info.get('country_code', '').lower()
                command['is_malicious'] = ip_info.get('is_malicious', False)
        
        return jsonify(command)
    except Exception as e:
        logger.error(f"Error al obtener detalles de comando SSH: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/ssh_malware_details/<malware_id>')
@login_required
def get_ssh_malware_details(malware_id):

    try:
        app.logger.info("====== DIAGNÓSTICO DE SISTEMA DE ARCHIVOS ======")
        key_dirs = ['/malware_files', '/host_malware', '/var/lib/docker/volumes/honeypot-web_cowrie_dl/_data']
        for dir_path in key_dirs:
            if os.path.exists(dir_path):
                app.logger.info(f"✅ Directorio existe: {dir_path}")
                try:
                    files = os.listdir(dir_path)
                    app.logger.info(f"   Contenido ({len(files)} archivos): {', '.join(files[:10])}{'...' if len(files) > 10 else ''}")
                except Exception as e:
                    app.logger.info(f"   ❌ Error al listar contenido: {str(e)}")
            else:
                app.logger.info(f"❌ Directorio NO existe: {dir_path}")
        app.logger.info("====== FIN DIAGNÓSTICO DE SISTEMA DE ARCHIVOS ======")
    except Exception as e:
        app.logger.info(f"Error en diagnóstico: {str(e)}")
    
    try:
        if malware_id.startswith('physical_'):
            file_hash = malware_id.replace('physical_', '')
            app.logger.info(f"Procesando archivo físico con hash: {file_hash}")
            
            possible_paths = [
                f'/malware_files/{file_hash}',
                f'/host_malware/{file_hash}'
            ]
            
            found_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    found_path = path
                    app.logger.info(f"Archivo físico encontrado en: {path}")
                    break
            
            if not found_path:
                error_msg = f"Archivo físico no encontrado en el sistema. Rutas probadas: {', '.join(possible_paths)}"
                app.logger.error(error_msg)
                return jsonify({
                    "_id": malware_id,
                    "error": error_msg,
                    "file_hash": file_hash,
                    "timestamp": datetime.now().isoformat()
                })
            
            file_stat = os.stat(found_path)
            file_size = file_stat.st_size
            file_timestamp = datetime.fromtimestamp(file_stat.st_mtime).isoformat()
            
            malware = {
                "_id": malware_id,
                "protocol": "unknown",
                "ip": "Desconocido",
                "filename": f"{file_hash}.bin",
                "outfile": found_path,
                "filesize": file_size,
                "file_size_bytes": file_size,
                "file_size_human": formatFileSize(file_size),
                "timestamp": file_timestamp,
                "filetype": "Binario",
                "file_hash": file_hash,
                "message": "Archivo encontrado en el sistema de archivos sin registro en MongoDB",
                "physical_only": True
            }
            
            try:
                with open(found_path, 'rb') as f:
                    file_content = f.read()
                
                malware['file_content'] = base64.b64encode(file_content).decode('utf-8')
                
                malware['hex_view'] = generate_hex_view(file_content[:8192])  # Limitar a primeros 8KB
                
                malware['strings'] = extract_strings(file_content[:16384])  # Limitar a primeros 16KB
                
            except Exception as e:
                app.logger.error(f"Error leyendo archivo físico: {str(e)}")
                app.logger.error(traceback.format_exc())
                malware['processing_error'] = str(e)
            
            return jsonify(malware)
        

        if not mongodb_client.is_connected():
            logger.error("No se pudo conectar a MongoDB para obtener detalles de malware SSH")
            if not mongodb_client.connect():
                return jsonify({"status": "error", "message": "No se pudo conectar a MongoDB"}), 500
        
        if malware_id == "placeholder":
            return jsonify({
                "_id": "placeholder",
                "ip": "0.0.0.0",
                "protocol": "ssh",
                "filename": "No hay archivos malware disponibles",
                "size": 0,
                "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "shasum": "N/A",
                "message": "No se han capturado archivos malware todavía"
            })
        
        malware = None
        for collection_name in ["downloads", "malware", "download"]:
            try:
                malware = mongodb_client.db[collection_name].find_one({"_id": ObjectId(malware_id)})
                if malware:
                    app.logger.info(f"Malware {malware_id} encontrado en la colección {collection_name}")
                    break
            except Exception as e:
                app.logger.error(f"Error accediendo a colección {collection_name}: {str(e)}")
        
        if not malware:
            return jsonify({"status": "error", "message": "Archivo malware no encontrado"}), 404
        
        destfile = malware.get('destfile', 'unknown.bin')
        filename = destfile.split('/')[-1] if '/' in destfile else destfile
        
        malware['_id'] = str(malware['_id'])
        
        malware['ip'] = malware.get('src_ip', 'Desconocido')
        malware['filename'] = filename
        malware['destpath'] = malware.get('destfile', '')
        malware['outfile'] = malware.get('outfile', '')
        malware['filesize'] = malware.get('size', 0)
        malware['date'] = malware.get('timestamp', 'N/A')
        malware['protocol'] = 'ssh'
        

        system = malware.get('system', '')
        if 'telnet' in system.lower():
            malware['protocol'] = 'telnet'
            
        malware['file_hash'] = malware.get('shasum', 'Desconocido')
        

        outfile_path = malware.get('outfile', '')
        

        possible_paths = []
        if outfile_path:

            possible_paths.append(outfile_path)
            

            if not outfile_path.startswith('/'):
                possible_paths.append('/' + outfile_path)
            

            app_dir = os.path.dirname(os.path.abspath(__file__))
            possible_paths.append(os.path.join(app_dir, outfile_path))
            

            root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            possible_paths.append(os.path.join(root_dir, outfile_path))
            

            file_name = os.path.basename(outfile_path)
            common_dirs = [
                '/var/lib/cowrie/downloads',
                '/opt/cowrie/var/lib/cowrie/downloads',
                '/home/cowrie/cowrie/var/lib/cowrie/downloads',
                '/app/cowrie/var/lib/cowrie/downloads',
                '/var/lib/docker/volumes/honeypot-web_cowrie_dl/_data',
                '/var/lib/docker/volumes/cowrie_dl/_data'
            ]
            
            docker_volume_dirs = [
                '/malware_files',
                '/host_malware',
                '/malware_data',
                '/var/lib/docker/volumes/honeypot-web_cowrie_dl/_data',
                '/var/lib/docker/volumes/cowrie_dl/_data'
            ]
            for docker_dir in docker_volume_dirs:
                docker_path = os.path.join(docker_dir, file_name)
                possible_paths.append(docker_path)
                app.logger.info(f"Añadiendo ruta a intentar: {docker_path}")
                
                if os.path.exists(docker_path):
                    app.logger.info(f"¡La ruta existe!: {docker_path}")
                    try:
                        with open(docker_path, 'rb') as test_file:
                            file_size = len(test_file.read(10))
                            app.logger.info(f"✅ ¡Archivo leído correctamente! Tamaño inicial: {file_size} bytes")
                    except Exception as read_err:
                        app.logger.error(f"❌ Error al leer archivo: {str(read_err)}")
                else:
                    app.logger.info(f"La ruta no existe: {docker_path}")
            

            for common_dir in common_dirs:
                if os.path.exists(common_dir):
                    possible_paths.append(os.path.join(common_dir, file_name))
        
        found_path = None
        for path in possible_paths:
            if os.path.exists(path):
                found_path = path
                app.logger.info(f"Archivo de malware encontrado en: {path}")
                break
        
        if found_path:
            try:
                app.logger.info(f"Leyendo archivo de malware: {found_path}")
                
                try:
                    file_type_output = subprocess.check_output(['file', found_path], stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
                    file_type = file_type_output.split(':', 1)[1].strip() if ':' in file_type_output else file_type_output.strip()
                    malware['filetype'] = file_type
                except (subprocess.SubprocessError, FileNotFoundError, IndexError):
                    malware['filetype'] = "Binario (tipo no determinado)"
                
                MAX_SIZE = 102400
                with open(found_path, 'rb') as f:
                    file_content = f.read(MAX_SIZE)
                

                is_binary = False
                try:
                    file_content.decode('utf-8')
                except UnicodeDecodeError:
                    is_binary = True
                

                try:
                    strings_output = subprocess.check_output(['strings', found_path], stderr=subprocess.STDOUT)
                    strings_list = strings_output.decode('utf-8', errors='ignore').splitlines()
                    malware['strings'] = strings_list[:1000] if len(strings_list) > 1000 else strings_list
                except (subprocess.SubprocessError, FileNotFoundError):
                    strings_pattern = re.compile(b'[\x20-\x7E]{4,}')  # 4+ caracteres ASCII imprimibles
                    strings_list = [match.group().decode('ascii') for match in strings_pattern.finditer(file_content)]
                    malware['strings'] = strings_list[:1000] if len(strings_list) > 1000 else strings_list
                
                hex_view = ""
                hex_bytes = binascii.hexlify(file_content).decode('utf-8')
                bytes_per_row = 16
                
                for i in range(0, len(hex_bytes), bytes_per_row * 2):
                    row_hex = hex_bytes[i:i + bytes_per_row * 2]
                    hex_chars = [row_hex[j:j+2] for j in range(0, len(row_hex), 2)]
                    hex_str = ' '.join(hex_chars)
                    
                    offset = i // 2
                    offset_str = f"{offset:08x}"
                    
                    ascii_chars = []
                    for j in range(0, len(row_hex), 2):
                        if j < len(row_hex):
                            byte_val = int(row_hex[j:j+2], 16)
                            if 32 <= byte_val <= 126:
                                ascii_chars.append(chr(byte_val))
                            else:
                                ascii_chars.append('.')
                    ascii_str = ''.join(ascii_chars)

                    hex_view += f'<div class="byte-ascii"><div class="byte-offset">{offset_str}: </div><div class="byte-hex">{hex_str}</div><div class="byte-text">{ascii_str}</div></div>\n'
                
                malware['hex_view'] = hex_view
                

                malware['file_size_human'] = formatFileSize(len(file_content))
                malware['file_size_bytes'] = len(file_content)

                if 'strings' in malware:

                    extracted_strings = malware['strings']

                    del malware['strings']

                    malware['strings'] = extracted_strings
                
            except Exception as e:
                app.logger.error(f"Error procesando archivo de malware: {str(e)}")
                app.logger.error(traceback.format_exc())
                malware['processing_error'] = str(e)

                malware['strings'] = [
                    f"Error al procesar archivo: {str(e)}",
                    f"Ruta: {found_path}",
                    f"Hash: {malware.get('shasum', 'N/A')}",
                    f"Tamaño: {malware.get('size', 0)} bytes"
                ]
                malware['hex_view'] = "<div class='byte-ascii'><div class='byte-hex'>Error al generar vista hexadecimal</div></div>"
        else:
            app.logger.warning(f"Archivo de malware no encontrado en el sistema: {outfile_path}")

            malware['strings'] = [
                "Archivo no encontrado en el sistema",
                f"Rutas probadas: {', '.join(possible_paths)}",
                f"Hash: {malware.get('shasum', 'N/A')}",
                f"Tamaño: {malware.get('size', 0)} bytes"
            ]
            

            malware['hex_view'] = "<div class='byte-ascii'><div class='byte-hex'>Archivo no encontrado en el sistema. Revisa los permisos o ajusta las rutas de búsqueda.</div></div>"
        

        if 'country' not in malware and malware.get('ip') and malware.get('ip') != 'Desconocido':
            ip_info = ip_cache.get_ip_info(malware.get('ip'))
            if ip_info:
                malware['country'] = ip_info.get('country', 'Desconocido')
                malware['city'] = ip_info.get('city', '')
                malware['country_code'] = ip_info.get('country_code', '').lower()
                malware['is_malicious'] = ip_info.get('is_malicious', False)
        
        return jsonify(malware)
    except Exception as e:
        logger.error(f"Error al obtener detalles de malware SSH: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"status": "error", "message": str(e)}), 500


def formatFileSize(bytes):
    if not bytes or bytes == 0:
        return '0 Bytes'
    
    sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while bytes >= 1024 and i < len(sizes) - 1:
        bytes /= 1024
        i += 1
    
    return f"{bytes:.2f} {sizes[i]}"

def generate_hex_view(file_content):

    hex_view = ""
    bytes_per_row = 16
    

    if isinstance(file_content, str):
        try:
            file_content = file_content.encode('utf-8')
        except Exception as e:
            return f"Error convirtiendo a bytes: {str(e)}"
    

    hex_bytes = binascii.hexlify(file_content).decode('utf-8')
    
    for i in range(0, len(hex_bytes), bytes_per_row * 2):

        row_hex = hex_bytes[i:i + bytes_per_row * 2]

        hex_chars = [row_hex[j:j+2] for j in range(0, len(row_hex), 2)]
        hex_str = ' '.join(hex_chars)
        

        offset = i // 2
        offset_str = f"{offset:08x}"
        

        ascii_chars = []
        for j in range(0, len(row_hex), 2):
            if j < len(row_hex):
                byte_val = int(row_hex[j:j+2], 16)
                if 32 <= byte_val <= 126:
                    ascii_chars.append(chr(byte_val))
                else:
                    ascii_chars.append('.')
        ascii_str = ''.join(ascii_chars)
        

        hex_view += f'<div class="byte-ascii"><div class="byte-offset">{offset_str}: </div><div class="byte-hex">{hex_str}</div><div class="byte-text">{ascii_str}</div></div>\n'
    
    return hex_view

def extract_strings(file_content, min_length=4):

    if not file_content:
        return ["No hay contenido para extraer strings"]

    if isinstance(file_content, str):
        try:
            file_content = file_content.encode('utf-8')
        except Exception as e:
            return [f"Error convirtiendo a bytes: {str(e)}"]
    

    strings_pattern = re.compile(b'[\x20-\x7E]{' + str(min_length).encode() + b',}')
    strings_list = [match.group().decode('ascii', errors='ignore') for match in strings_pattern.finditer(file_content)]
    

    return strings_list[:1000] if len(strings_list) > 1000 else strings_list

@app.route('/api/telnet_login_details/<login_id>')
@login_required
def get_telnet_login_details(login_id):

    try:

        from bson.objectid import ObjectId
        

        if not ObjectId.is_valid(login_id):
            return jsonify({"error": "ID inválido"}), 400
        

        login = mongodb_client.db.telnet_events.find_one({"_id": ObjectId(login_id)})
        
        if not login:

            login = mongodb_client.db.sessions.find_one({"_id": ObjectId(login_id)})
            
            if not login:
                return jsonify({
                    "error": "Login no encontrado",
                    "ip": "0.0.0.0",
                    "username": "desconocido",
                    "password": "desconocido",
                    "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "country": "Desconocido",
                    "protocol": "telnet"
                }), 404
        

        login["_id"] = str(login["_id"])
        

        login["protocol"] = "telnet"
        

        if 'src_ip' in login and 'ip' not in login:
            login['ip'] = login['src_ip']
        elif 'ip' not in login:
            login['ip'] = "0.0.0.0"
            
        if 'username' not in login:
            login['username'] = "desconocido"
            
        if 'password' not in login:
            login['password'] = "desconocido"
            
        if 'timestamp' not in login:
            login['timestamp'] = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            

        if 'country' not in login:
            login['country'] = "Desconocido"
        
        return jsonify(login)
    except Exception as e:
        app.logger.error(f"Error obteniendo detalles de login Telnet: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/telnet_command_details/<command_id>')
@login_required
def get_telnet_command_details(command_id):

    try:

        from bson.objectid import ObjectId
        

        if not ObjectId.is_valid(command_id):
            return jsonify({"error": "ID inválido"}), 400
        
        command = mongodb_client.db.telnet_events.find_one({"_id": ObjectId(command_id)})
        
        if not command:
            command = mongodb_client.db.sessions.find_one({"_id": ObjectId(command_id)})
            
            if not command:
                return jsonify({
                    "error": "Comando no encontrado",
                    "ip": "0.0.0.0",
                    "command": "No hay comandos registrados",
                    "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "country": "Desconocido",
                    "protocol": "telnet"
                }), 404
        
        command["_id"] = str(command["_id"])
        
        command["protocol"] = "telnet"
        
        if 'src_ip' in command and 'ip' not in command:
            command['ip'] = command['src_ip']
        elif 'ip' not in command:
            command['ip'] = "0.0.0.0"
            
        if 'command' not in command and 'input' in command:
            command['command'] = command['input']
        elif 'command' not in command:
            command['command'] = "No hay comandos registrados"
            
        if 'timestamp' not in command:
            command['timestamp'] = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            
        if 'country' not in command:
            command['country'] = "Desconocido"
        
        return jsonify(command)
    except Exception as e:
        app.logger.error(f"Error obteniendo detalles del comando Telnet: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/telnet_malware_details/<malware_id>')
@login_required
def get_telnet_malware_details(malware_id):
    try:
        if not mongodb_client.is_connected():
            if not mongodb_client.connect():
                return jsonify({"status": "error", "message": "No se pudo conectar a MongoDB"}), 500
        
        if malware_id == "placeholder":
            return jsonify({
                "_id": "placeholder",
                "ip": "0.0.0.0",
                "protocol": "telnet",
                "filename": "No disponible",
                "size": 0,
                "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "shasum": "N/A",
                "strings": ["No hay datos disponibles"],
                "hex_view": "<div class='byte-ascii'><div class='byte-hex'>No hay datos disponibles</div></div>"
            })
        
        malware = None
        for collection_name in ["downloads", "malware", "download"]:
            try:
                malware = mongodb_client.db[collection_name].find_one({"_id": ObjectId(malware_id)})
                if malware:
                    app.logger.info(f"Malware {malware_id} encontrado en la colección {collection_name}")
                    break
            except Exception as e:
                app.logger.error(f"Error accediendo a colección {collection_name}: {str(e)}")
        
        if not malware:
            return jsonify({"status": "error", "message": "Archivo malware no encontrado"}), 404
        
        destfile = malware.get('destfile', 'unknown.bin')
        filename = destfile.split('/')[-1] if '/' in destfile else destfile
        
        malware['_id'] = str(malware['_id'])
        
        malware['ip'] = malware.get('src_ip', 'Desconocido')
        malware['filename'] = filename
        malware['destpath'] = malware.get('destfile', '')
        malware['outfile'] = malware.get('outfile', '')
        malware['filesize'] = malware.get('size', 0)
        malware['date'] = malware.get('timestamp', 'N/A')
        malware['protocol'] = 'telnet'
        
        system = malware.get('system', '')
        if 'ssh' in system.lower() and 'telnet' not in system.lower():
            malware['protocol'] = 'ssh'
            
        malware['file_hash'] = malware.get('shasum', 'Desconocido')
        
        outfile_path = malware.get('outfile', '')
        

        possible_paths = []
        if outfile_path:
            possible_paths.append(outfile_path)
            
            if not outfile_path.startswith('/'):
                possible_paths.append('/' + outfile_path)
            
            app_dir = os.path.dirname(os.path.abspath(__file__))
            possible_paths.append(os.path.join(app_dir, outfile_path))
            
            root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            possible_paths.append(os.path.join(root_dir, outfile_path))
            
            file_name = os.path.basename(outfile_path)
            common_dirs = [
                '/var/lib/cowrie/downloads',
                '/opt/cowrie/var/lib/cowrie/downloads',
                '/home/cowrie/cowrie/var/lib/cowrie/downloads',
                '/app/cowrie/var/lib/cowrie/downloads',
                '/var/lib/docker/volumes/honeypot-web_cowrie_dl/_data',
                '/var/lib/docker/volumes/cowrie_dl/_data'
            ]
            

            docker_volume_dirs = [
                '/malware_files',
                '/host_malware',
                '/malware_data',
                '/var/lib/docker/volumes/honeypot-web_cowrie_dl/_data',
                '/var/lib/docker/volumes/cowrie_dl/_data'
            ]
            for docker_dir in docker_volume_dirs:
                docker_path = os.path.join(docker_dir, file_name)
                possible_paths.append(docker_path)
                app.logger.info(f"Añadiendo ruta a intentar: {docker_path}")
                
                if os.path.exists(docker_path):
                    app.logger.info(f"¡La ruta existe!: {docker_path}")
                    try:
                        with open(docker_path, 'rb') as test_file:
                            file_size = len(test_file.read(10))
                            app.logger.info(f"✅ ¡Archivo leído correctamente! Tamaño inicial: {file_size} bytes")
                    except Exception as read_err:
                        app.logger.error(f"❌ Error al leer archivo: {str(read_err)}")
                else:
                    app.logger.info(f"La ruta no existe: {docker_path}")
            

            for common_dir in common_dirs:
                if os.path.exists(common_dir):
                    possible_paths.append(os.path.join(common_dir, file_name))
        

        found_path = None
        for path in possible_paths:
            if os.path.exists(path):
                found_path = path
                app.logger.info(f"Archivo de malware encontrado en: {path}")
                break
        
        if found_path:
            try:
                app.logger.info(f"Leyendo archivo de malware Telnet: {found_path}")
                
                try:
                    file_type_output = subprocess.check_output(['file', found_path], stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
                    file_type = file_type_output.split(':', 1)[1].strip() if ':' in file_type_output else file_type_output.strip()
                    malware['filetype'] = file_type
                except (subprocess.SubprocessError, FileNotFoundError, IndexError):
                    malware['filetype'] = "Binario (tipo no determinado)"
                

                MAX_SIZE = 102400
                with open(found_path, 'rb') as f:
                    file_content = f.read(MAX_SIZE)
                

                is_binary = False
                try:
                    file_content.decode('utf-8')
                except UnicodeDecodeError:
                    is_binary = True
                

                try:
                    strings_output = subprocess.check_output(['strings', found_path], stderr=subprocess.STDOUT)
                    strings_list = strings_output.decode('utf-8', errors='ignore').splitlines()

                    malware['strings'] = strings_list[:1000] if len(strings_list) > 1000 else strings_list
                except (subprocess.SubprocessError, FileNotFoundError):

                    strings_pattern = re.compile(b'[\x20-\x7E]{4,}')
                    strings_list = [match.group().decode('ascii') for match in strings_pattern.finditer(file_content)]
                    malware['strings'] = strings_list[:1000] if len(strings_list) > 1000 else strings_list
                

                hex_view = ""
                hex_bytes = binascii.hexlify(file_content).decode('utf-8')
                bytes_per_row = 16
                
                for i in range(0, len(hex_bytes), bytes_per_row * 2):

                    row_hex = hex_bytes[i:i + bytes_per_row * 2]

                    hex_chars = [row_hex[j:j+2] for j in range(0, len(row_hex), 2)]
                    hex_str = ' '.join(hex_chars)
                    

                    offset = i // 2
                    offset_str = f"{offset:08x}"
                    

                    ascii_chars = []
                    for j in range(0, len(row_hex), 2):
                        if j < len(row_hex):
                            byte_val = int(row_hex[j:j+2], 16)
                            if 32 <= byte_val <= 126:
                                ascii_chars.append(chr(byte_val))
                            else:
                                ascii_chars.append('.')
                    ascii_str = ''.join(ascii_chars)
                    

                    hex_view += f'<div class="byte-ascii"><div class="byte-offset">{offset_str}: </div><div class="byte-hex">{hex_str}</div><div class="byte-text">{ascii_str}</div></div>\n'
                
                malware['hex_view'] = hex_view
                

                malware['file_size_human'] = formatFileSize(len(file_content))
                malware['file_size_bytes'] = len(file_content)
                

                if 'strings' in malware:

                    extracted_strings = malware['strings']

                    del malware['strings']

                    malware['strings'] = extracted_strings
                
            except Exception as e:
                app.logger.error(f"Error procesando archivo de malware Telnet: {str(e)}")
                app.logger.error(traceback.format_exc())
                malware['processing_error'] = str(e)
                

                malware['strings'] = [
                    f"Error al procesar archivo: {str(e)}",
                    f"Ruta: {found_path}",
                    f"Hash: {malware.get('shasum', 'N/A')}",
                    f"Tamaño: {malware.get('size', 0)} bytes"
                ]
                malware['hex_view'] = "<div class='byte-ascii'><div class='byte-hex'>Error al generar vista hexadecimal</div></div>"
        else:
            app.logger.warning(f"Archivo de malware no encontrado en el sistema: {outfile_path}")

            malware['strings'] = [
                "Archivo no encontrado en el sistema",
                f"Rutas probadas: {', '.join(possible_paths)}",
                f"Hash: {malware.get('shasum', 'N/A')}",
                f"Tamaño: {malware.get('size', 0)} bytes"
            ]
            

            malware['hex_view'] = "<div class='byte-ascii'><div class='byte-hex'>Archivo no encontrado en el sistema. Revisa los permisos o ajusta las rutas de búsqueda.</div></div>"

        if 'country' not in malware and malware.get('ip') and malware.get('ip') != 'Desconocido':
            ip_info = ip_cache.get_ip_info(malware.get('ip'))
            if ip_info:
                malware['country'] = ip_info.get('country', 'Desconocido')
                malware['city'] = ip_info.get('city', '')
                malware['country_code'] = ip_info.get('country_code', '').lower()
                malware['is_malicious'] = ip_info.get('is_malicious', False)
        
        return jsonify(malware)
    except Exception as e:
        logger.error(f"Error al obtener detalles de malware Telnet: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/ssh_malware_download/<malware_id>')
@login_required
def download_ssh_malware(malware_id):

    try:
)
        if malware_id.startswith('physical_'):

            file_hash = malware_id.replace('physical_', '')
            app.logger.info(f"Procesando descarga de archivo físico con hash: {file_hash}")
            

            possible_paths = [
                f'/malware_files/{file_hash}',
                f'/host_malware/{file_hash}'
            ]
            
            found_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    found_path = path
                    app.logger.info(f"Archivo físico encontrado para descarga en: {path}")
                    break
            
            if not found_path:
                error_msg = f"Archivo físico no encontrado en el sistema para descarga. Rutas probadas: {', '.join(possible_paths)}"
                app.logger.error(error_msg)
                return jsonify({"error": error_msg}), 404
                

            original_filename = f"{file_hash}.bin"
            

            zip_password = "infected"
            

            return create_password_protected_zip(found_path, original_filename, zip_password, file_hash)
            

        if not mongodb_client.is_connected():
            if not mongodb_client.connect():
                return jsonify({"error": "No se pudo conectar a MongoDB"}), 500
        

        malware = None
        for collection_name in ["downloads", "malware", "download"]:
            try:
                malware = mongodb_client.db[collection_name].find_one({"_id": ObjectId(malware_id)})
                if malware:
                    logger.info(f"Malware {malware_id} encontrado en la colección {collection_name}")
                    break
            except Exception as e:
                logger.error(f"Error accediendo a colección {collection_name}: {str(e)}")
        
        if not malware:
            return jsonify({"error": "Archivo malware no encontrado en base de datos"}), 404
        

        outfile_path = malware.get('outfile', '')
        

        possible_paths = []
        found_path = None
        
        if outfile_path:

            possible_paths.append(outfile_path)
            

            if not outfile_path.startswith('/'):
                possible_paths.append('/' + outfile_path)
            

            app_dir = os.path.dirname(os.path.abspath(__file__))
            possible_paths.append(os.path.join(app_dir, outfile_path))
            

            root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            possible_paths.append(os.path.join(root_dir, outfile_path))
            

            file_name = os.path.basename(outfile_path)
            common_dirs = [
                '/var/lib/cowrie/downloads',
                '/opt/cowrie/var/lib/cowrie/downloads',
                '/home/cowrie/cowrie/var/lib/cowrie/downloads',
                '/app/cowrie/var/lib/cowrie/downloads',

                '/var/lib/docker/volumes/honeypot-web_cowrie_dl/_data',
                '/var/lib/docker/volumes/cowrie_dl/_data'
            ]
            

            docker_volume_dirs = [
                '/malware_files',
                '/host_malware',
                '/malware_data',
                '/var/lib/docker/volumes/honeypot-web_cowrie_dl/_data',
                '/var/lib/docker/volumes/cowrie_dl/_data'
            ]
            for docker_dir in docker_volume_dirs:
                docker_path = os.path.join(docker_dir, file_name)
                possible_paths.append(docker_path)
            

            for common_dir in common_dirs:
                if os.path.exists(common_dir):
                    possible_paths.append(os.path.join(common_dir, file_name))

            for path in possible_paths:
                if os.path.exists(path):
                    found_path = path
                    logger.info(f"Archivo de malware encontrado en: {path}")
                    break
        
        if not found_path:
            return jsonify({"error": f"Archivo no encontrado en el sistema. Rutas probadas: {', '.join(possible_paths)}"}), 404
        

        destfile = malware.get('destfile', 'malware.bin')
        filename = destfile.split('/')[-1] if '/' in destfile else destfile
        

        _, ext = os.path.splitext(filename)
        if not ext:
            ext = '.bin'
        

        safe_filename = f"malware_{malware_id}{ext}"
        

        zip_password = "infected"
        

        return create_password_protected_zip(found_path, safe_filename, zip_password, malware_id)
        
    except Exception as e:
        logging.error(f"Error al descargar malware SSH: {str(e)}")
        logging.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

def create_password_protected_zip(file_path, original_filename, password, file_id):

    try:

        temp_dir = os.path.join(tempfile.gettempdir(), 'malware_downloads')
        os.makedirs(temp_dir, exist_ok=True)
        

        zip_filename = f"malware_{file_id}.zip"
        zip_path = os.path.join(temp_dir, zip_filename)
        

        if os.path.exists(zip_path):
            os.remove(zip_path)
        

        import zipfile
        

        with open(file_path, 'rb') as f:
            malware_content = f.read()
        

        pyminizip = None
        try:
            import pyminizip
        except ImportError:
            logger.warning("Biblioteca pyminizip no disponible. Usando zipfile sin encriptación AES.")
        
        if pyminizip:

            temp_file = os.path.join(temp_dir, original_filename)
            with open(temp_file, 'wb') as f:
                f.write(malware_content)
            

            pyminizip.compress(temp_file, None, zip_path, password, 5)
            

            os.remove(temp_file)
        else:

            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:

                zf.writestr(zipfile.ZipInfo(original_filename), malware_content, 
                           pwd=password.encode('utf-8'))
        

        logger.info(f"Enviando archivo malware protegido con contraseña ZIP: {zip_path}")
        

        response = send_file(
            zip_path,
            as_attachment=True,
            download_name=zip_filename,
            mimetype='application/zip'
        )

        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Warning'] = 'Este archivo contiene malware. La contraseña del ZIP es: infected'
        

        flash(f'Archivo descargado como ZIP protegido. La contraseña es: infected', 'info')
        
        return response
        
    except Exception as e:
        logger.error(f"Error creando ZIP protegido: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Error creando ZIP protegido: {str(e)}"}), 500

@app.route('/api/telnet_malware_download/<malware_id>')
@login_required
def download_telnet_malware(malware_id):

    try:

        if not mongodb_client.is_connected():
            if not mongodb_client.connect():
                return jsonify({"error": "No se pudo conectar a MongoDB"}), 500
        

        malware = None
        for collection_name in ["downloads", "malware", "download"]:
            try:
                malware = mongodb_client.db[collection_name].find_one({"_id": ObjectId(malware_id)})
                if malware:
                    logger.info(f"Malware {malware_id} encontrado en la colección {collection_name}")
                    break
            except Exception as e:
                logger.error(f"Error accediendo a colección {collection_name}: {str(e)}")
        
        if not malware:
            return jsonify({"error": "Archivo malware no encontrado en base de datos"}), 404
        

        outfile_path = malware.get('outfile', '')
        

        possible_paths = []
        found_path = None
        
        if outfile_path:

            possible_paths.append(outfile_path)
            

            if not outfile_path.startswith('/'):
                possible_paths.append('/' + outfile_path)
            
            app_dir = os.path.dirname(os.path.abspath(__file__))
            possible_paths.append(os.path.join(app_dir, outfile_path))
            
            root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            possible_paths.append(os.path.join(root_dir, outfile_path))
            
            file_name = os.path.basename(outfile_path)
            common_dirs = [
                '/var/lib/cowrie/downloads',
                '/opt/cowrie/var/lib/cowrie/downloads',
                '/home/cowrie/cowrie/var/lib/cowrie/downloads',
                '/app/cowrie/var/lib/cowrie/downloads',
                '/var/lib/docker/volumes/honeypot-web_cowrie_dl/_data',
                '/var/lib/docker/volumes/cowrie_dl/_data'
            ]
            
            docker_volume_dirs = [
                '/malware_files',
                '/host_malware',
                '/malware_data',
                '/var/lib/docker/volumes/honeypot-web_cowrie_dl/_data',  #
                '/var/lib/docker/volumes/cowrie_dl/_data'
            ]
            for docker_dir in docker_volume_dirs:
                docker_path = os.path.join(docker_dir, file_name)
                possible_paths.append(docker_path)
                app.logger.info(f"Añadiendo ruta a intentar: {docker_path}")
                
                if os.path.exists(docker_path):
                    app.logger.info(f"¡La ruta existe!: {docker_path}")
                    try:
                        with open(docker_path, 'rb') as test_file:
                            file_size = len(test_file.read(10))
                            app.logger.info(f"✅ ¡Archivo leído correctamente! Tamaño inicial: {file_size} bytes")
                    except Exception as read_err:
                        app.logger.error(f"❌ Error al leer archivo: {str(read_err)}")
                else:
                    app.logger.info(f"La ruta no existe: {docker_path}")
            

            for common_dir in common_dirs:
                if os.path.exists(common_dir):
                    possible_paths.append(os.path.join(common_dir, file_name))
        

        found_path = None
        for path in possible_paths:
            if os.path.exists(path):
                found_path = path
                logger.info(f"Archivo de malware encontrado en: {path}")
                break
        
        if not found_path:
            return jsonify({"error": f"Archivo no encontrado en el sistema. Rutas probadas: {', '.join(possible_paths)}"}), 404
        

        destfile = malware.get('destfile', 'malware.bin')
        filename = destfile.split('/')[-1] if '/' in destfile else destfile
        

        _, ext = os.path.splitext(filename)
        if not ext:
            ext = '.bin'

        safe_filename = f"malware_{malware_id}{ext}"

        zip_password = "infected"
        

        return create_password_protected_zip(found_path, safe_filename, zip_password, malware_id)
        
    except Exception as e:
        logging.error(f"Error al descargar malware Telnet: {str(e)}")
        logging.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/ftp_malware_download/<malware_id>')
@login_required
def download_ftp_malware(malware_id):
    try:
        return jsonify({"error": "No hay archivos FTP disponibles para descargar"}), 404
    except Exception as e:
        logging.error(f"Error al descargar archivo FTP: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/top_commands')
@login_required
def get_top_commands():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        if not mongodb_client.is_connected():
            app.logger.error("MongoDB no está conectado")
            if not mongodb_client.connect():
                return jsonify({"commands": [], "total": 0, "page": page, "per_page": per_page})
        
        pipeline = [
            {
                "$match": {
                    "input": {
                        "$exists": True, 
                        "$ne": None, 
                        "$ne": "", 
                        "$not": {"$regex": "GET|HTTP|User-Agent|Mozilla|HEAD|POST|zgrab|Host:|Connection:|Accept:|Accept-Encoding: gzip|Content-|\\*/\\*|[Cc]url|Desconocida"}
                    },
                    "eventid": "cowrie.command.input"
                }
            },
            {
                "$group": {
                    "_id": "$input",
                    "count": {"$sum": 1},
                    "last_used": {"$max": "$timestamp"},
                    "first_used": {"$min": "$timestamp"}
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "command": "$_id",
                    "count": 1,
                    "last_used": 1,
                    "first_used": 1
                }
            },
            {
                "$sort": {"count": -1}
            }
        ]
        

        commands = list(mongodb_client.db["input"].aggregate(pipeline))
        

        total = len(commands)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        

        commands_page = commands[start_idx:end_idx] if start_idx < total else []
        
        return jsonify({
            "commands": commands_page,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page
        })
    except Exception as e:
        app.logger.error(f"Error obteniendo comandos más utilizados: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({"commands": [], "total": 0, "page": page, "per_page": per_page})

if __name__ == '__main__':
    try:
        logger.info("Iniciando servidor del dashboard local...")

        if app.config['ENABLE_HTTPS']:
            logger.info("Iniciando servidor con soporte HTTPS")
            ssl_context = (app.config['SSL_CERT_PATH'], app.config['SSL_KEY_PATH'])
            

            if not os.path.exists(app.config['SSL_CERT_PATH']):
                logger.error(f"Certificado SSL no encontrado en: {app.config['SSL_CERT_PATH']}")
            if not os.path.exists(app.config['SSL_KEY_PATH']):
                logger.error(f"Clave SSL no encontrada en: {app.config['SSL_KEY_PATH']}")
                

            app.run(host='0.0.0.0', port=8443, ssl_context=ssl_context, debug=False)
        else:
            logger.info("Iniciando servidor sin soporte HTTPS")

            app.run(host='0.0.0.0', port=8080, debug=False)
    except Exception as e:
        logger.error(f"Error crítico al iniciar el servidor: {str(e)}")
        logger.error(traceback.format_exc())

        time.sleep(10) 
        