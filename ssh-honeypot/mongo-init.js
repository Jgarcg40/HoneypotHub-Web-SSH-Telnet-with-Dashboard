
db = db.getSiblingDB('honeypot');


db.createCollection('login_attempts');
db.createCollection('commands');
db.createCollection('malware');
db.createCollection('telnet_events');
db.createCollection('telnet_downloads');
db.createCollection('events');
db.createCollection('sessions');
db.createCollection('input');


db.login_attempts.createIndex({ "timestamp": -1 });
db.login_attempts.createIndex({ "src_ip": 1 });
db.login_attempts.createIndex({ "protocol": 1 });
db.login_attempts.createIndex({ "username": 1 });
db.login_attempts.createIndex({ "country": 1 });

db.commands.createIndex({ "timestamp": -1 });
db.commands.createIndex({ "src_ip": 1 });
db.commands.createIndex({ "protocol": 1 });
db.commands.createIndex({ "command": 1 });
db.commands.createIndex({ "country": 1 });

db.malware.createIndex({ "timestamp": -1 });
db.malware.createIndex({ "src_ip": 1 });
db.malware.createIndex({ "protocol": 1 });
db.malware.createIndex({ "shasum": 1 }, { unique: true, sparse: true });
db.malware.createIndex({ "filename": 1 });
db.malware.createIndex({ "country": 1 });

db.telnet_events.createIndex({ "timestamp": -1 });
db.telnet_events.createIndex({ "src_ip": 1 });
db.telnet_events.createIndex({ "command": 1 });
db.telnet_events.createIndex({ "country": 1 });

db.telnet_downloads.createIndex({ "timestamp": -1 });
db.telnet_downloads.createIndex({ "src_ip": 1 });
db.telnet_downloads.createIndex({ "shasum": 1 }, { unique: true, sparse: true });
db.telnet_downloads.createIndex({ "filename": 1 });
db.telnet_downloads.createIndex({ "country": 1 });

db.events.createIndex({ "timestamp": -1 });
db.events.createIndex({ "src_ip": 1 });
db.events.createIndex({ "country": 1 });
db.events.createIndex({ "eventid": 1 });

db.sessions.createIndex({ "timestamp": -1 });
db.sessions.createIndex({ "src_ip": 1 });
db.sessions.createIndex({ "session": 1 }, { unique: true });

db.input.createIndex({ "timestamp": -1 });
db.input.createIndex({ "src_ip": 1 });
db.input.createIndex({ "session": 1 });

db.createUser({
    user: 'dashboard_reader',
    pwd: 'HoneyReader2024',
    roles: [
        { role: 'read', db: 'honeypot' }
    ]
});

db.createUser({
    user: 'cowrie_admin',
    pwd: 'SecureHoney2024',
    roles: [
        { role: 'readWrite', db: 'honeypot' }
    ]
});

print('Inicialización de MongoDB para Honeypot completada.'); 