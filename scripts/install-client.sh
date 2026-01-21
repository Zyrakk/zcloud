#!/bin/bash
#===============================================================================
# ZCLOUD CLIENT INSTALLER
# Instala el cliente zcloud en cualquier Linux
#
# USO: curl -fsSL https://api.zyrak.cloud/install.sh | bash
#===============================================================================

set -euo pipefail

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="/usr/local/bin"
BINARY_NAME="zcloud"
GITHUB_REPO="zyrak/zcloud"

# Detectar arquitectura
detect_arch() {
    local arch=$(uname -m)
    case $arch in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        arm64)   echo "arm64" ;;
        *)       echo "unsupported" ;;
    esac
}

# Detectar OS
detect_os() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    case $os in
        linux)  echo "linux" ;;
        darwin) echo "darwin" ;;
        *)      echo "unsupported" ;;
    esac
}

main() {
    echo ""
    echo -e "${BLUE}🔧 Instalando zcloud client...${NC}"
    echo ""
    
    OS=$(detect_os)
    ARCH=$(detect_arch)
    
    if [[ "$OS" == "unsupported" ]] || [[ "$ARCH" == "unsupported" ]]; then
        echo "❌ Sistema no soportado: $(uname -s) $(uname -m)"
        exit 1
    fi
    
    BINARY="zcloud-${OS}-${ARCH}"
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/${BINARY}"
    
    echo "   OS: ${OS}"
    echo "   Arch: ${ARCH}"
    echo ""
    
    # Crear directorio temporal
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT
    
    # Descargar
    echo -e "${BLUE}📥 Descargando ${BINARY}...${NC}"
    
    if command -v curl &>/dev/null; then
        curl -fsSL -o "${TMP_DIR}/${BINARY_NAME}" "${DOWNLOAD_URL}"
    elif command -v wget &>/dev/null; then
        wget -q -O "${TMP_DIR}/${BINARY_NAME}" "${DOWNLOAD_URL}"
    else
        echo "❌ Se requiere curl o wget"
        exit 1
    fi
    
    chmod +x "${TMP_DIR}/${BINARY_NAME}"
    
    # Instalar
    echo -e "${BLUE}📦 Instalando en ${INSTALL_DIR}...${NC}"
    
    if [[ -w "${INSTALL_DIR}" ]]; then
        mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        sudo mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    fi
    
    echo ""
    echo -e "${GREEN}✅ zcloud instalado correctamente${NC}"
    echo ""
    echo "   Ubicación: ${INSTALL_DIR}/${BINARY_NAME}"
    echo "   Versión:   $(zcloud version 2>/dev/null || echo 'desconocida')"
    echo ""
    echo -e "${YELLOW}Próximos pasos:${NC}"
    echo ""
    echo "   1. Inicializa el cliente:"
    echo "      zcloud init https://api.zyrak.cloud"
    echo ""
    echo "   2. Espera la aprobación del administrador"
    echo ""
    echo "   3. Completa la configuración:"
    echo "      zcloud init --complete"
    echo ""
    echo "   4. Inicia sesión:"
    echo "      zcloud login"
    echo ""
}

main "$@"
