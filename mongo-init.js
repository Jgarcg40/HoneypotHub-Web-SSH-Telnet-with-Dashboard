print('Iniciando script de configuración de MongoDB...');

try {
  db = db.getSiblingDB('admin');
  print('Creando usuario de aplicación en la base de datos admin: ' + process.env.MONGO_APP_USER);
  db.createUser({
    user: process.env.MONGO_APP_USER,
    pwd: process.env.MONGO_APP_PASSWORD,
    roles: [
      { role: 'readWrite', db: process.env.MONGO_INITDB_DATABASE }
    ]
  });
  print('Usuario creado correctamente en admin: ' + process.env.MONGO_APP_USER);
} catch (err) {
  print('El usuario ya podría existir o hubo un error: ' + err);
}

db = db.getSiblingDB(process.env.MONGO_INITDB_DATABASE);

try {
  print('Creando colecciones iniciales...');
  try { db.createCollection('login_attempts'); } catch (err) { print('Colección login_attempts ya existe o error: ' + err); }
  try { db.createCollection('ips'); } catch (err) { print('Colección ips ya existe o error: ' + err); }
  try { db.createCollection('activity_logs'); } catch (err) { print('Colección activity_logs ya existe o error: ' + err); }
  try { db.createCollection('attacks'); } catch (err) { print('Colección attacks ya existe o error: ' + err); }
  try { db.createCollection('web_requests'); } catch (err) { print('Colección web_requests ya existe o error: ' + err); }
  try { db.createCollection('contacts'); } catch (err) { print('Colección contacts ya existe o error: ' + err); }
  try { db.createCollection('usernames'); } catch (err) { print('Colección usernames ya existe o error: ' + err); }
  try { db.createCollection('passwords'); } catch (err) { print('Colección passwords ya existe o error: ' + err); }

  print('Creando índices...');
  try { db.login_attempts.createIndex({ timestamp: -1 }); } catch (err) { print('Error creando índice en login_attempts: ' + err); }
  try { db.login_attempts.createIndex({ ip: 1 }); } catch (err) { print('Error creando índice en login_attempts.ip: ' + err); }
  try { db.login_attempts.createIndex({ username: 1 }); } catch (err) { print('Error creando índice en login_attempts.username: ' + err); }

  try { db.attacks.createIndex({ timestamp: -1 }); } catch (err) { print('Error creando índice en attacks: ' + err); }
  try { db.attacks.createIndex({ ip: 1 }); } catch (err) { print('Error creando índice en attacks.ip: ' + err); }
  try { db.attacks.createIndex({ attack_type: 1 }); } catch (err) { print('Error creando índice en attacks.attack_type: ' + err); }

  try { db.ips.createIndex({ ip: 1 }, { unique: true }); } catch (err) { print('Error creando índice en ips.ip: ' + err); }
  try { db.ips.createIndex({ is_malicious: 1 }); } catch (err) { print('Error creando índice en ips.is_malicious: ' + err); }
  try { db.ips.createIndex({ last_seen: -1 }); } catch (err) { print('Error creando índice en ips.last_seen: ' + err); }

  try { db.web_requests.createIndex({ timestamp: -1 }); } catch (err) { print('Error creando índice en web_requests: ' + err); }
  try { db.web_requests.createIndex({ ip: 1 }); } catch (err) { print('Error creando índice en web_requests.ip: ' + err); }
  try { db.web_requests.createIndex({ route: 1 }); } catch (err) { print('Error creando índice en web_requests.route: ' + err); }

  try { db.usernames.createIndex({ username: 1 }, { unique: true }); } catch (err) { print('Error creando índice en usernames: ' + err); }
  try { db.passwords.createIndex({ password: 1 }, { unique: true }); } catch (err) { print('Error creando índice en passwords: ' + err); }

  print('MongoDB inicializado con usuario, colecciones e índices');
  
} catch (error) {
  print('Error durante la inicialización de MongoDB: ' + error);
} 
