import os
import logging
import pymongo
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
import json
import time


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('db')


class DummyDB:

    def __getattr__(self, name):
        return DummyCollection()

class DummyCollection:

    def __getattr__(self, name):
        return self._dummy_method
        
    def _dummy_method(self, *args, **kwargs):

        return None

class MongoDBClient:
    def __init__(self):


        self.mongo_uri = os.environ.get('MONGODB_URI')
        

        if not self.mongo_uri:
            mongo_user = os.environ.get('MONGO_APP_USER')
            mongo_password = os.environ.get('MONGO_APP_PASSWORD')
            mongo_host = os.environ.get('MONGO_HOST', 'mongodb')
            mongo_port = os.environ.get('MONGO_PORT', '27017')
            mongo_db = os.environ.get('MONGO_DATABASE', 'honeypot')
            mongo_auth_db = os.environ.get('MONGO_AUTH_DATABASE', 'admin')
            

            if mongo_user and mongo_password:
                self.mongo_uri = f"mongodb://{mongo_user}:{mongo_password}@{mongo_host}:{mongo_port}/{mongo_db}?authSource={mongo_auth_db}"
            else:
                self.mongo_uri = f"mongodb://{mongo_host}:{mongo_port}/{mongo_db}"
        

        if not self.mongo_uri:
            self.mongo_uri = 'mongodb://localhost:27017/honeypot'
            
        logger.info(f"Usando URI de MongoDB: {self.mongo_uri.replace(self.mongo_uri.split('@')[0], 'mongodb://***:***')}")
        
        self.client = None
        self.db = None
        self.connect()
        

        for i in range(5):
            if self.connect():
                break
            logger.info(f"Intento {i+1} de conexión a MongoDB fallido, esperando 2 segundos...")
            time.sleep(2)

    def connect(self):

        try:

            if self.client:
                try:
                    self.client.close()
                except:
                    pass
                
            self.client = pymongo.MongoClient(self.mongo_uri, serverSelectionTimeoutMS=5000)

            self.client.server_info()
            

            db_name = self.mongo_uri.split('/')[-1]

            if '?' in db_name:
                db_name = db_name.split('?')[0]
                
            self.db = self.client[db_name]
            logger.info(f"Conexión a MongoDB establecida correctamente: {db_name}")
            

            self._ensure_collections_exist()
            

            self._create_indexes()
            
            return True
        except Exception as e:
            logger.error(f"Error al conectar a MongoDB: {str(e)}")
            return False
            
    def _ensure_collections_exist(self):

        try:
            collections = ['login_attempts', 'ips', 'activity_logs', 'attacks', 
                          'web_requests', 'contacts', 'usernames', 'passwords']
            for collection in collections:
                if collection not in self.db.list_collection_names():
                    self.db.create_collection(collection)
                    logger.info(f"Colección '{collection}' creada")
        except Exception as e:
            logger.error(f"Error al crear colecciones: {str(e)}")
            
    def _create_indexes(self):

        try:

            self.db.login_attempts.create_index("timestamp")
            self.db.login_attempts.create_index("ip")
            self.db.login_attempts.create_index("username")
            

            self.db.ips.create_index("ip", unique=True)
            self.db.ips.create_index("first_seen")
            self.db.ips.create_index("last_seen")
            self.db.ips.create_index("is_malicious")
            self.db.ips.create_index("is_vpn")
            

            self.db.web_requests.create_index("timestamp")
            self.db.web_requests.create_index("ip")
            self.db.web_requests.create_index("path")
            

            self.db.attacks.create_index("timestamp")
            self.db.attacks.create_index("ip")
            self.db.attacks.create_index("attack_type")
            

            self.db.usernames.create_index("username", unique=True)
            self.db.passwords.create_index("password", unique=True)
            

            self.db.contacts.create_index("timestamp")
            self.db.contacts.create_index("ip")
            
            logger.info("Índices de MongoDB creados correctamente")
        except Exception as e:
            logger.error(f"Error al crear índices en MongoDB: {str(e)}")

    def is_connected(self) -> bool:

        if not self.client:
            return False
        try:
            self.client.server_info()
            return True
        except:
            return False

    def close(self):

        if self.client:
            self.client.close()
            self.client = None
            self.db = None
            logger.info("Conexión a MongoDB cerrada")


    def insert_one(self, collection: str, document: Dict) -> Optional[str]:

        try:
            if not self.is_connected():
                if not self.connect():
                    logger.error(f"No se pudo reconectar a MongoDB para insertar en {collection}")
                    return None
            
            result = self.db[collection].insert_one(document)
            logger.debug(f"Documento insertado en {collection}: {result.inserted_id}")
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error al insertar documento en {collection}: {str(e)}")

            self.connect()
            return None

    def insert_many(self, collection: str, documents: List[Dict]) -> Optional[List[str]]:

        try:
            if not self.is_connected():
                if not self.connect():
                    logger.error(f"No se pudo reconectar a MongoDB para insertar múltiples en {collection}")
                    return None
            
            if not documents:
                return []
                
            result = self.db[collection].insert_many(documents)
            logger.debug(f"Documentos insertados en {collection}: {len(result.inserted_ids)}")
            return [str(id) for id in result.inserted_ids]
        except Exception as e:
            logger.error(f"Error al insertar documentos en {collection}: {str(e)}")

            self.connect()
            return None

    def find(self, collection: str, query: Dict = None, projection: Dict = None, 
             sort: List = None, limit: int = 0, skip: int = 0) -> List[Dict]:

        try:
            if not self.is_connected():
                if not self.connect():
                    logger.error(f"No se pudo reconectar a MongoDB para buscar en {collection}")
                    return []
            
            cursor = self.db[collection].find(query or {}, projection or {})
            
            if sort:
                cursor = cursor.sort(sort)
            
            if skip:
                cursor = cursor.skip(skip)
                
            if limit:
                cursor = cursor.limit(limit)
                
            result = list(cursor)
            logger.debug(f"Encontrados {len(result)} documentos en {collection}")
            return result
        except Exception as e:
            logger.error(f"Error al buscar documentos en {collection}: {str(e)}")

            self.connect()
            return []

    def find_one(self, collection: str, query: Dict, projection: Dict = None) -> Optional[Dict]:

        try:
            if not self.is_connected():
                if not self.connect():
                    logger.error(f"No se pudo reconectar a MongoDB para buscar en {collection}")
                    return None
            
            result = self.db[collection].find_one(query, projection or {})
            return result
        except Exception as e:
            logger.error(f"Error al buscar documento en {collection}: {str(e)}")

            self.connect()
            return None

    def update_one(self, collection: str, query: Dict, update: Dict, upsert: bool = False) -> bool:

        try:
            if not self.is_connected():
                if not self.connect():
                    logger.error(f"No se pudo reconectar a MongoDB para actualizar en {collection}")
                    return False
            
            result = self.db[collection].update_one(query, update, upsert=upsert)
            success = result.acknowledged
            logger.debug(f"Documento en {collection} actualizado: {success}")
            return success
        except Exception as e:
            logger.error(f"Error al actualizar documento en {collection}: {str(e)}")

            self.connect()
            return False

    def delete_one(self, collection: str, query: Dict) -> bool:

        try:
            if not self.is_connected():
                if not self.connect():
                    logger.error(f"No se pudo reconectar a MongoDB para eliminar de {collection}")
                    return False
            
            result = self.db[collection].delete_one(query)
            success = result.acknowledged
            logger.debug(f"Documento en {collection} eliminado: {success}")
            return success
        except Exception as e:
            logger.error(f"Error al eliminar documento en {collection}: {str(e)}")

            self.connect()
            return False

    def count_documents(self, collection: str, query: Dict = None) -> int:

        try:
            if not self.is_connected():
                if not self.connect():
                    logger.error(f"No se pudo reconectar a MongoDB para contar en {collection}")
                    return 0
            
            count = self.db[collection].count_documents(query or {})
            return count
        except Exception as e:
            logger.error(f"Error al contar documentos en {collection}: {str(e)}")

            self.connect()
            return 0

    def distinct(self, collection: str, field: str, query: Dict = None) -> List:

        try:
            if not self.is_connected():
                if not self.connect():
                    logger.error(f"No se pudo reconectar a MongoDB para distinct en {collection}.{field}")
                    return []
            
            values = self.db[collection].distinct(field, query or {})
            return values
        except Exception as e:
            logger.error(f"Error al obtener valores distintos en {collection}.{field}: {str(e)}")

            self.connect()
            return []

    def aggregate(self, collection: str, pipeline: List[Dict]) -> List[Dict]:

        try:
            if not self.is_connected():
                if not self.connect():
                    logger.error(f"No se pudo reconectar a MongoDB para agregación en {collection}")
                    return []
            
            result = list(self.db[collection].aggregate(pipeline))
            return result
        except Exception as e:
            logger.error(f"Error al ejecutar agregación en {collection}: {str(e)}")

            self.connect()
            return []


    def log_login_attempt(self, login_data: Dict) -> bool:

        try:
            if not self.is_connected():
                if not self.connect():
                    return False
            

            if 'timestamp' not in login_data:
                login_data['timestamp'] = datetime.now().isoformat()
                

            login_id = self.insert_one('login_attempts', login_data)
            

            username = login_data.get('username')
            if username:
                self.db.usernames.update_one(
                    {'username': username},
                    {'$inc': {'count': 1}, 
                     '$set': {'last_seen': login_data['timestamp']},
                     '$setOnInsert': {'first_seen': login_data['timestamp']}},
                    upsert=True
                )
            

            password = login_data.get('password')
            if password:
                self.db.passwords.update_one(
                    {'password': password},
                    {'$inc': {'count': 1}, 
                     '$set': {'last_seen': login_data['timestamp']},
                     '$setOnInsert': {'first_seen': login_data['timestamp']}},
                    upsert=True
                )
            

            ip = login_data.get('ip')
            if ip and ip != 'unknown':

                ip_doc = self.db.ips.find_one({'ip': ip})
                
                if ip_doc:

                    update_data = {
                        '$inc': {'count': 1},
                        '$set': {'last_seen': login_data['timestamp']}
                    }
                    

                    attacks = login_data.get('attacks', [])
                    if attacks:
                        for attack in attacks:
                            if attack not in ip_doc.get('attacks', []):
                                update_data['$push'] = {'attacks': attack}
                    
                    self.db.ips.update_one({'ip': ip}, update_data)
                else:

                    ip_data = {
                        'ip': ip,
                        'count': 1,
                        'first_seen': login_data['timestamp'],
                        'last_seen': login_data['timestamp'],
                        'country': 'Unknown',
                        'city': 'Unknown',
                        'org': 'Unknown',
                        'is_vpn': False,
                        'attacks': login_data.get('attacks', [])
                    }
                    

                    geo_info = login_data.get('geo_info', {})
                    if geo_info:
                        ip_data.update({
                            'country': geo_info.get('country', 'Unknown'),
                            'city': geo_info.get('city', 'Unknown'),
                            'org': geo_info.get('org', 'Unknown')
                        })
                    
                    self.insert_one('ips', ip_data)
            

            attacks = login_data.get('attacks', [])
            if attacks:
                for attack in attacks:
                    attack_data = {
                        'timestamp': login_data['timestamp'],
                        'ip': ip,
                        'username': username,
                        'password': password,
                        'user_agent': login_data.get('user_agent', 'Unknown'),
                        'attack_type': attack.get('type', 'Unknown'),
                        'details': attack.get('details', 'No details provided')
                    }
                    self.insert_one('attacks', attack_data)
            
            return bool(login_id)
        except Exception as e:
            logger.error(f"Error al registrar intento de login: {str(e)}")
            return False

    def log_web_request(self, request_data: Dict) -> bool:

        try:
            if not self.is_connected():
                if not self.connect():
                    return False
            

            if 'timestamp' not in request_data:
                request_data['timestamp'] = datetime.now().isoformat()
                

            request_id = self.insert_one('web_requests', request_data)
            

            ip = request_data.get('ip')
            if ip and ip != 'unknown':

                ip_doc = self.db.ips.find_one({'ip': ip})
                
                if ip_doc:

                    update_data = {
                        '$inc': {'count': 1},
                        '$set': {'last_seen': request_data['timestamp']}
                    }
                    self.db.ips.update_one({'ip': ip}, update_data)
                else:

                    ip_data = {
                        'ip': ip,
                        'count': 1,
                        'first_seen': request_data['timestamp'],
                        'last_seen': request_data['timestamp'],
                        'country': 'Unknown',
                        'city': 'Unknown',
                        'org': 'Unknown',
                        'is_vpn': False,
                        'attacks': []
                    }
                    

                    geo_info = request_data.get('geo_info', {})
                    if geo_info:
                        ip_data.update({
                            'country': geo_info.get('country', 'Unknown'),
                            'city': geo_info.get('city', 'Unknown'),
                            'org': geo_info.get('org', 'Unknown')
                        })
                    
                    self.insert_one('ips', ip_data)
            

            if request_data.get('is_attack', False):
                attack_data = {
                    'timestamp': request_data['timestamp'],
                    'ip': ip,
                    'user_agent': request_data.get('user_agent', 'Unknown'),
                    'path': request_data.get('path', '/'),
                    'attack_type': request_data.get('attack_type', 'Unknown'),
                    'details': request_data.get('details', 'No details provided')
                }
                self.insert_one('attacks', attack_data)
                

                if ip and ip != 'unknown':
                    self.db.ips.update_one(
                        {'ip': ip},
                        {'$set': {'is_malicious': True}},
                        upsert=True
                    )
            
            return bool(request_id)
        except Exception as e:
            logger.error(f"Error al registrar solicitud web: {str(e)}")
            return False

    def log_contact_form(self, contact_data: Dict) -> bool:

        try:
            if not self.is_connected():
                if not self.connect():
                    return False
                    

            if 'timestamp' not in contact_data:
                contact_data['timestamp'] = datetime.now().isoformat()
                

            contact_id = self.insert_one('contacts', contact_data)
            

            log_entry = {
                'timestamp': contact_data['timestamp'],
                'ip': contact_data.get('ip', 'unknown'),
                'user_agent': contact_data.get('user_agent', 'Unknown'),
                'type': 'contact_form',
                'details': f"Formulario de contacto - Email: {contact_data.get('email', 'No email')}"
            }
            self.insert_one('activity_logs', log_entry)
            
            return bool(contact_id)
        except Exception as e:
            logger.error(f"Error al registrar formulario de contacto: {str(e)}")
            return False

    def register_attack(self, attack_data: Dict) -> bool:

        try:
            if not self.is_connected():
                if not self.connect():
                    return False
                    

            if 'timestamp' not in attack_data:
                attack_data['timestamp'] = datetime.now().isoformat()
                

            attack_id = self.insert_one('attacks', attack_data)
            

            ip = attack_data.get('ip')
            if ip and ip != 'unknown':

                self.db.ips.update_one(
                    {'ip': ip},
                    {'$set': {'is_malicious': True}},
                    upsert=True
                )
                

                malicious_ip_data = {
                    'ip': ip,
                    'first_seen': attack_data['timestamp'],
                    'last_seen': attack_data['timestamp'],
                    'attack_count': 1,
                    'attack_types': [attack_data.get('attack_type', 'Unknown')],
                    'user_agents': [attack_data.get('user_agent', 'Unknown')],
                    'paths': [attack_data.get('path', '/')]
                }
                

                existing = self.db.malicious_ips.find_one({'ip': ip})
                
                if existing:

                    update_data = {
                        '$set': {'last_seen': attack_data['timestamp']},
                        '$inc': {'attack_count': 1}
                    }
                    

                    attack_type = attack_data.get('attack_type', 'Unknown')
                    if attack_type not in existing.get('attack_types', []):
                        update_data['$push'] = {'attack_types': attack_type}
                    

                    user_agent = attack_data.get('user_agent', 'Unknown')
                    if user_agent not in existing.get('user_agents', []):
                        if '$push' not in update_data:
                            update_data['$push'] = {}
                        update_data['$push']['user_agents'] = user_agent
                    

                    path = attack_data.get('path', '/')
                    if path not in existing.get('paths', []):
                        if '$push' not in update_data:
                            update_data['$push'] = {}
                        update_data['$push']['paths'] = path
                    
                    self.db.malicious_ips.update_one({'ip': ip}, update_data)
                else:

                    self.insert_one('malicious_ips', malicious_ip_data)
            
            return bool(attack_id)
        except Exception as e:
            logger.error(f"Error al registrar ataque: {str(e)}")
            return False

    def import_json_to_mongodb(self, json_file_path: str, collection: str, 
                               key_field: str = None, is_array: bool = False) -> bool:

        if not os.path.exists(json_file_path):
            logger.warning(f"El archivo {json_file_path} no existe")
            return False
            
        try:
            with open(json_file_path, 'r') as f:
                data = json.load(f)
                
            if is_array:

                if not data:
                    logger.info(f"El archivo {json_file_path} está vacío o no contiene un array válido")
                    return True
                    
                if len(data) > 1000:

                    chunk_size = 1000
                    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
                    
                    for i, chunk in enumerate(chunks):
                        result = self.db[collection].insert_many(chunk)
                        logger.info(f"Importados {len(result.inserted_ids)} documentos de {json_file_path} en {collection} (chunk {i+1}/{len(chunks)})")
                else:
                    result = self.db[collection].insert_many(data)
                    logger.info(f"Importados {len(result.inserted_ids)} documentos de {json_file_path} en {collection}")
            else:

                if not data:
                    logger.info(f"El archivo {json_file_path} está vacío o no contiene un diccionario válido")
                    return True
                    
                if key_field:

                    documents = []
                    for key, value in data.items():
                        if isinstance(value, dict):
                            doc = value.copy()
                            doc[key_field] = key
                            documents.append(doc)
                        else:
                            documents.append({key_field: key, "count": value})
                            
                    if documents:
                        result = self.db[collection].insert_many(documents)
                        logger.info(f"Importados {len(result.inserted_ids)} documentos de {json_file_path} en {collection}")
                else:

                    result = self.db[collection].insert_one(data)
                    logger.info(f"Importado diccionario de {json_file_path} en {collection}")
            
            return True
        except Exception as e:
            logger.error(f"Error al importar {json_file_path} a {collection}: {str(e)}")
            return False


mongodb_client = MongoDBClient()


import atexit
atexit.register(mongodb_client.close) 
