#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' 

log_message() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[ADVERTENCIA]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[ÉXITO]${NC} $1"
}

set_permissions() {
    local dir=$1
    local dir_perm=$2
    local file_perm=$3
    
    log_message "Estableciendo permisos en $dir (directorios: $dir_perm, archivos: $file_perm)..."
    find "$dir" -type d -exec chmod $dir_perm {} \;
    find "$dir" -type f -exec chmod $file_perm {} \;
}

set_specific_permissions() {
    local file=$1
    local perm=$2
    if [ -f "$file" ]; then
        log_message "Estableciendo permisos $perm para $file..."
        chmod $perm "$file"
    else
        log_warning "El archivo $file no existe, no se pueden establecer permisos."
    fi
}

if [ "$EUID" -ne 0 ]; then
    log_error "Este script debe ser ejecutado como root (sudo)"
    exit 1
fi

log_message "Iniciando el sistema completo de honeypot..."

log_message "Verificando dependencias del sistema..."

if ! command -v docker &> /dev/null; then
    log_error "Docker no está instalado. Por favor, instálalo antes de continuar."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    log_error "Docker Compose no está instalado. Por favor, instálalo antes de continuar."
    exit 1
fi

if [ ! -f .env ]; then
    log_error "El archivo .env no existe. Por favor, créalo antes de continuar."
    exit 1
fi

log_message "Deteniendo contenedores existentes..."
docker-compose down

log_message "Configurando directorios y permisos..."

DIRECTORIES=(
    "certs"
    "ssh-honeypot"
    "local-dashboard/logs"
    "public-web/logs"
)

for dir in "${DIRECTORIES[@]}"; do
    if [ ! -d "$dir" ]; then
        log_message "Creando directorio $dir..."
        mkdir -p "$dir"
    fi
    if [[ "$dir" == *"/logs" ]]; then
        set_permissions "$dir" "777" "666"  
    else
        set_permissions "$dir" "755" "644"
    fi
done

log_message "Configurando certificados SSL..."
mkdir -p certs
if [ ! -f "certs/server.key" ] || [ ! -f "certs/server.crt" ]; then
    log_message "Generando certificados SSL..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout certs/server.key -out certs/server.crt \
        -subj "/C=ES/ST=Madrid/L=Madrid/O=Honeypot/CN=localhost"
fi

log_message "Configurando permisos para certificados SSL..."
chmod 644 certs/server.crt  
chmod 644 certs/server.key   

log_message "Estableciendo permisos para archivos críticos..."

EXECUTABLE_FILES=(
    "local-dashboard/src/app.py"
    "public-web/src/app.py"
)

for file in "${EXECUTABLE_FILES[@]}"; do
    set_specific_permissions "$file" "755"  
done


log_message "Verificando archivos de configuración..."

REQUIRED_FILES=(
    "ssh-honeypot/cowrie.cfg"
    "ssh-honeypot/userdb.txt"
    "ssh-honeypot/cowrie-output.json"
    "ssh-honeypot/mongo-init.js"
    "ssh-honeypot/seccomp-profile.json"
    "mongo-init.js"
    ".env"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        log_error "Falta el archivo de configuración: $file"
        exit 1
    fi
    chmod 644 "$file"
done

log_message "Configurando permisos para scripts y archivos importantes..."

find . -name "*.sh" -exec chmod 755 {} \;

find . -name "*.py" -exec chmod 644 {} \; 

for file in "${EXECUTABLE_FILES[@]}"; do
    set_specific_permissions "$file" "755"  # rwxr-xr-x
done

chmod 644 .env  

log_message "Configurando permisos para directorios de logs y datos..."
find . -path "*/logs" -type d -exec chmod 777 {} \;
find . -path "*/logs/*" -type f -exec chmod 666 {} \;

log_message "Verificando configuración de red de Docker..."
if ! docker network ls | grep -q "honeypot-internal"; then
    log_message "Creando redes de Docker necesarias..."
    docker network create honeypot-internal
    docker network create public-network
    docker network create honeypot_net
fi

log_message "Reiniciando servicios de red de Docker..."
docker network prune -f

log_message "Iniciando servicios..."
docker-compose up -d

log_message "Verificando estado de los contenedores..."
sleep 10

ALL_RUNNING=true
CONTAINERS=$(docker-compose ps -q)

for CONTAINER in $CONTAINERS; do
    STATUS=$(docker inspect --format='{{.State.Status}}' $CONTAINER)
    NAME=$(docker inspect --format='{{.Name}}' $CONTAINER | cut -c2-)
    if [ "$STATUS" != "running" ]; then
        log_error "El contenedor $NAME no está ejecutándose correctamente"
        ALL_RUNNING=false
    else
        log_success "Contenedor $NAME está en ejecución"
    fi
done

if $ALL_RUNNING; then
    log_success "¡Todos los servicios están en funcionamiento!"
    echo -e "\n${GREEN}Servicios disponibles:${NC}"
    echo -e "  • Honeypot Web Público: ${YELLOW}http://localhost:80${NC}"
    echo -e "  • Dashboard Administrativo: ${YELLOW}https://localhost:8443${NC} o ${YELLOW}http://localhost:8080${NC}"
    echo -e "  • Honeypot SSH: ${YELLOW}puerto 2222${NC}"
    echo -e "  • Honeypot Telnet: ${YELLOW}puerto 23${NC}"
    echo -e "\n${YELLOW}Para ver los logs: docker-compose logs -f${NC}"
    echo -e "${YELLOW}Para detener los servicios: docker-compose down${NC}"
else
    log_error "Algunos contenedores no se iniciaron correctamente"
    log_message "Revisando logs para diagnosticar problemas..."
    docker-compose logs | grep -i "error\|denied\|permission\|cannot\|failed"
    log_warning "Revisa los logs completos con: docker-compose logs"
    exit 1
fi 