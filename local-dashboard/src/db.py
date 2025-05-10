import os
import logging
import pymongo
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
import json

# Configurar logging
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
            

            if mongo_user and mongo_password:
                self.mongo_uri = f"mongodb://{mongo_user}:{mongo_password}@{mongo_host}:{mongo_port}/{mongo_db}"
            else:
                self.mongo_uri = f"mongodb://{mongo_host}:{mongo_port}/{mongo_db}"
        

        if not self.mongo_uri:
            self.mongo_uri = 'mongodb://localhost:27017/honeypot'
            
        logger.info(f"Usando URI de MongoDB: {self.mongo_uri.replace(self.mongo_uri.split('@')[0], 'mongodb://***:***')}")
        
        self.client = None
        self.db = None
        self.connect()

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

            if not self.db:
                self.db = DummyDB()
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
                    return None
            
            result = self.db[collection].insert_one(document)
            logger.debug(f"Documento insertado en {collection}: {result.inserted_id}")
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error al insertar documento en {collection}: {str(e)}")
            return None

    def find(self, collection: str, query: Dict = None, projection: Dict = None, 
             sort: List = None, limit: int = 0, skip: int = 0) -> List[Dict]:

        try:
            if not self.is_connected():
                if not self.connect():
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
            return []

    def find_one(self, collection: str, query: Dict, projection: Dict = None) -> Optional[Dict]:

        try:
            if not self.is_connected():
                if not self.connect():
                    return None
            
            result = self.db[collection].find_one(query, projection or {})
            return result
        except Exception as e:
            logger.error(f"Error al buscar documento en {collection}: {str(e)}")
            return None

    def update_one(self, collection: str, query: Dict, update: Dict, upsert: bool = False) -> bool:

        try:
            if not self.is_connected():
                if not self.connect():
                    return False
            
            result = self.db[collection].update_one(query, update, upsert=upsert)
            success = result.acknowledged
            logger.debug(f"Documento en {collection} actualizado: {success}")
            return success
        except Exception as e:
            logger.error(f"Error al actualizar documento en {collection}: {str(e)}")
            return False

    def delete_one(self, collection: str, query: Dict) -> bool:

        try:
            if not self.is_connected():
                if not self.connect():
                    return False
            
            result = self.db[collection].delete_one(query)
            success = result.acknowledged
            logger.debug(f"Documento en {collection} eliminado: {success}")
            return success
        except Exception as e:
            logger.error(f"Error al eliminar documento en {collection}: {str(e)}")
            return False

    def count_documents(self, collection: str, query: Dict = None) -> int:

        try:
            if not self.is_connected():
                if not self.connect():
                    return 0
            
            count = self.db[collection].count_documents(query or {})
            return count
        except Exception as e:
            logger.error(f"Error al contar documentos en {collection}: {str(e)}")
            return 0

    def distinct(self, collection: str, field: str, query: Dict = None) -> List:

        try:
            if not self.is_connected():
                if not self.connect():
                    return []
            
            values = self.db[collection].distinct(field, query or {})
            return values
        except Exception as e:
            logger.error(f"Error al obtener valores distintos en {collection}.{field}: {str(e)}")
            return []

    def aggregate(self, collection: str, pipeline: List[Dict]) -> List[Dict]:

        try:
            if not self.is_connected():
                if not self.connect():
                    return []
            
            result = list(self.db[collection].aggregate(pipeline))
            return result
        except Exception as e:
            logger.error(f"Error al ejecutar agregación en {collection}: {str(e)}")
            return []


mongodb_client = MongoDBClient()


import atexit
atexit.register(mongodb_client.close) 