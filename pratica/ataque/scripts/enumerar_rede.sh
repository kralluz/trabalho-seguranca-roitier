#!/bin/bash

# Script de Enumeração de Rede
# Reconhecimento completo do ambiente de laboratório

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TARGET_NET="${1:-172.20.0.0/16}"
LOG_FILE="/root/logs/enum_$(date +%Y%m%d_%H%M%S).log"

echo -e "${BLUE}"
cat <<"EOF"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║          🔍 ENUMERAÇÃO DE REDE - Reconhecimento             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo "[*] Alvo: $TARGET_NET"
echo "[*] Log: $LOG_FILE"
echo

# Fase 1: Descoberta de Hosts
echo -e "${GREEN}[FASE 1] DESCOBERTA DE HOSTS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
nmap -sn "$TARGET_NET" -oN /tmp/hosts_descobertos.txt 2>&1 | tee -a "$LOG_FILE"

# Fase 2: Scan de Portas
echo
echo -e "${GREEN}[FASE 2] SCAN DE PORTAS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
nmap -sV -p- "$TARGET_NET" -oN /tmp/portas_abertas.txt 2>&1 | tee -a "$LOG_FILE"

# Fase 3: Detecção de OS
echo
echo -e "${GREEN}[FASE 3] DETECÇÃO DE SISTEMA OPERACIONAL${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
nmap -O "$TARGET_NET" 2>&1 | tee -a "$LOG_FILE" | head -30

echo
echo -e "${GREEN}[✓] Enumeração concluída!${NC}"
echo "Resultados salvos em: $LOG_FILE"
