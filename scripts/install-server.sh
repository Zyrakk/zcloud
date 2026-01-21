#!/bin/bash
#===============================================================================
# ZCLOUD SERVER INSTALLER
# Instala zcloud-server en el N150
#
# USO: curl -fsSL https://api.zyrak.cloud/install-server.sh | sudo bash
#      o: sudo ./install-server.sh
#===============================================================================

set -euo pipefail

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/zcloud-server"
BINARY_URL="https://github.com/zyrak/zcloud/releases/latest/download/zcloud-server-linux-amd64"
# Para desarrollo local, usar ruta local si existe
LOCAL_BINARY="./dist/zcloud-server-linux-amd64"

log_info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root"
    fi
}

check_dependencies() {
    log_info "Verificando dependencias..."
    
    # kubectl/k3s
    if ! command -v kubectl &>/dev/null && ! command -v k3s &>/dev/null; then
        log_error "kubectl o k3s no encontrado. Instala k3s primero."
    fi
    
    # certbot (opcional pero recomendado)
    if ! command -v certbot &>/dev/null; then
        log_warn "certbot no encontrado. Instálalo para certificados TLS automáticos:"
        log_warn "  apt install certbot"
    fi
    
    log_ok "Dependencias verificadas"
}

create_directories() {
    log_info "Creando directorios..."
    
    mkdir -p ${INSTALL_DIR}/{data,certs}
    chmod 750 ${INSTALL_DIR}
    chmod 700 ${INSTALL_DIR}/data
    chmod 750 ${INSTALL_DIR}/certs
    
    log_ok "Directorios creados"
}

install_binary() {
    log_info "Instalando binario..."
    
    if [[ -f "$LOCAL_BINARY" ]]; then
        # Usar binario local (desarrollo)
        cp "$LOCAL_BINARY" ${INSTALL_DIR}/zcloud-server
        log_info "Usando binario local"
    else
        # Descargar binario
        log_info "Descargando desde ${BINARY_URL}..."
        if ! curl -fsSL -o ${INSTALL_DIR}/zcloud-server "$BINARY_URL"; then
            log_error "Error descargando binario"
        fi
    fi
    
    chmod +x ${INSTALL_DIR}/zcloud-server
    log_ok "Binario instalado"
}

create_config() {
    log_info "Creando configuración..."
    
    if [[ -f ${INSTALL_DIR}/config.yaml ]]; then
        log_warn "config.yaml ya existe, no se sobrescribe"
        return
    fi
    
    # Obtener dominio del usuario
    read -p "Dominio para la API (ej: api.zyrak.cloud): " DOMAIN
    DOMAIN=${DOMAIN:-api.zyrak.cloud}
    
    cat > ${INSTALL_DIR}/config.yaml << EOF
# ZCloud Server Configuration
# Generado: $(date)

server:
  host: 0.0.0.0
  port: 443
  domain: ${DOMAIN}

tls:
  cert: ${INSTALL_DIR}/certs/fullchain.pem
  key: ${INSTALL_DIR}/certs/privkey.pem
  auto_renew: true

auth:
  jwt_secret_file: ${INSTALL_DIR}/data/jwt.secret
  session_ttl: 12h
  totp_issuer: "ZCloud"
  require_approval: true

kubernetes:
  kubeconfig: /etc/rancher/k3s/k3s.yaml

storage:
  database: ${INSTALL_DIR}/data/zcloud.db
EOF

    chmod 600 ${INSTALL_DIR}/config.yaml
    log_ok "Configuración creada"
}

init_server() {
    log_info "Inicializando servidor..."
    
    ${INSTALL_DIR}/zcloud-server --init --config ${INSTALL_DIR}/config.yaml
    
    log_ok "Servidor inicializado"
}

install_systemd() {
    log_info "Instalando servicio systemd..."
    
    cat > /etc/systemd/system/zcloud-server.service << 'EOF'
[Unit]
Description=ZCloud Server - Remote K3s Management
After=network.target k3s.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/opt/zcloud-server/zcloud-server --config /opt/zcloud-server/config.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zcloud-server

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/zcloud-server/data
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_ok "Servicio systemd instalado"
}

setup_firewall() {
    log_info "Configurando firewall..."
    
    if command -v ufw &>/dev/null; then
        ufw allow 443/tcp comment 'ZCloud API' 2>/dev/null || true
        log_ok "Puerto 443 abierto en UFW"
    else
        log_warn "UFW no encontrado, configura el firewall manualmente"
    fi
}

setup_tls() {
    log_info "Configurando TLS..."
    
    # Leer dominio de config
    DOMAIN=$(grep "domain:" ${INSTALL_DIR}/config.yaml | awk '{print $2}')
    
    if command -v certbot &>/dev/null; then
        echo ""
        echo "Para obtener certificados TLS con Let's Encrypt:"
        echo ""
        echo "  sudo certbot certonly --standalone -d ${DOMAIN}"
        echo ""
        echo "Después crea enlaces simbólicos:"
        echo ""
        echo "  sudo ln -sf /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ${INSTALL_DIR}/certs/"
        echo "  sudo ln -sf /etc/letsencrypt/live/${DOMAIN}/privkey.pem ${INSTALL_DIR}/certs/"
        echo ""
    else
        echo ""
        echo "Instala certbot y obtén certificados TLS:"
        echo ""
        echo "  sudo apt install certbot"
        echo "  sudo certbot certonly --standalone -d ${DOMAIN}"
        echo ""
    fi
}

create_first_admin() {
    log_info "Configurando primer administrador..."
    
    echo ""
    echo "El primer dispositivo que se registre será automáticamente admin."
    echo "Para registrar tu dispositivo, instala el cliente zcloud y ejecuta:"
    echo ""
    echo "  zcloud init https://\$(tu-dominio)"
    echo ""
}

final_report() {
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✅ ZCLOUD SERVER INSTALADO${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${CYAN}Archivos instalados:${NC}"
    echo "  ${INSTALL_DIR}/zcloud-server      (binario)"
    echo "  ${INSTALL_DIR}/config.yaml        (configuración)"
    echo "  ${INSTALL_DIR}/data/              (base de datos)"
    echo "  ${INSTALL_DIR}/certs/             (certificados TLS)"
    echo ""
    
    echo -e "${CYAN}Próximos pasos:${NC}"
    echo ""
    echo "1. Configura DNS:"
    echo "   Apunta tu dominio a la IP pública de este servidor"
    echo ""
    echo "2. Obtén certificados TLS:"
    echo "   sudo certbot certonly --standalone -d api.zyrak.cloud"
    echo "   sudo ln -sf /etc/letsencrypt/live/api.zyrak.cloud/fullchain.pem ${INSTALL_DIR}/certs/"
    echo "   sudo ln -sf /etc/letsencrypt/live/api.zyrak.cloud/privkey.pem ${INSTALL_DIR}/certs/"
    echo ""
    echo "3. Inicia el servidor:"
    echo "   sudo systemctl enable --now zcloud-server"
    echo ""
    echo "4. Verifica:"
    echo "   sudo systemctl status zcloud-server"
    echo "   curl -k https://localhost/health"
    echo ""
    
    echo -e "${CYAN}Comandos útiles:${NC}"
    echo "  journalctl -u zcloud-server -f    # Ver logs"
    echo "  systemctl restart zcloud-server   # Reiniciar"
    echo ""
}

main() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║          ZCLOUD SERVER INSTALLER                           ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    check_root
    check_dependencies
    create_directories
    install_binary
    create_config
    init_server
    install_systemd
    setup_firewall
    setup_tls
    create_first_admin
    final_report
}

main "$@"
