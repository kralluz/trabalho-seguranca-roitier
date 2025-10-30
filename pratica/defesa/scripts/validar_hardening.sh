#!/bin/bash

# Script de Validação de Hardening
# Verifica se todas as mitigações foram aplicadas corretamente
# Trabalho Final - Segurança da Informação

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

echo -e "${BLUE}"
cat <<"EOF"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     ✓ VALIDAÇÃO DE HARDENING - Teste de Mitigações         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

check_pass() {
    echo -e "${GREEN}[✓ PASS]${NC} $1"
    ((PASS_COUNT++))
}

check_fail() {
    echo -e "${RED}[✗ FAIL]${NC} $1"
    ((FAIL_COUNT++))
}

# ============================================================================
# VALIDAÇÃO #1: SSH Hardening
# ============================================================================
echo -e "${CYAN}[1/7] Validando Hardening SSH${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Verificar PermitRootLogin
if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config* 2>/dev/null; then
    check_pass "Root login via SSH desabilitado"
else
    check_fail "Root login via SSH ainda habilitado"
fi

# Verificar PasswordAuthentication
if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config* 2>/dev/null; then
    check_pass "Autenticação por senha desabilitada"
else
    check_fail "Autenticação por senha ainda habilitada"
fi

# Verificar Fail2Ban
if systemctl is-active --quiet fail2ban; then
    check_pass "Fail2Ban está ativo"
else
    check_fail "Fail2Ban não está rodando"
fi

# Verificar jail SSH do Fail2Ban
if fail2ban-client status sshd &>/dev/null; then
    check_pass "Jail SSH do Fail2Ban configurado"
else
    check_fail "Jail SSH do Fail2Ban não configurado"
fi

echo

# ============================================================================
# VALIDAÇÃO #2: Firewall
# ============================================================================
echo -e "${CYAN}[2/7] Validando Firewall e Segmentação${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Verificar UFW ativo
if ufw status | grep -q "Status: active"; then
    check_pass "Firewall UFW está ativo"
else
    check_fail "Firewall UFW não está ativo"
fi

# Verificar política padrão (deny incoming)
if ufw status verbose | grep -q "Default: deny (incoming)"; then
    check_pass "Política padrão: negar conexões de entrada"
else
    check_fail "Política padrão não restritiva"
fi

# Verificar se portas vulneráveis estão bloqueadas
BLOCKED_PORTS=(21 23 445)
for port in "${BLOCKED_PORTS[@]}"; do
    if ufw status | grep -q "DENY.*$port"; then
        check_pass "Porta $port bloqueada no firewall"
    else
        check_fail "Porta $port não está bloqueada"
    fi
done

echo

# ============================================================================
# VALIDAÇÃO #3: Serviços Desabilitados
# ============================================================================
echo -e "${CYAN}[3/7] Validando Desabilitação de Serviços${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Lista de serviços que devem estar inativos
SERVICES_DISABLED=("telnet" "vsftpd")

for service in "${SERVICES_DISABLED[@]}"; do
    if ! systemctl is-active --quiet "$service"; then
        check_pass "Serviço $service está desabilitado"
    else
        check_fail "Serviço $service ainda está ativo"
    fi
done

# Verificar MySQL bind-address
if grep -q "bind-address.*127.0.0.1" /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null; then
    check_pass "MySQL restrito ao localhost"
else
    check_fail "MySQL pode estar acessível externamente"
fi

echo

# ============================================================================
# VALIDAÇÃO #4: Política de Senhas
# ============================================================================
echo -e "${CYAN}[4/7] Validando Política de Senhas${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Verificar libpam-pwquality instalado
if dpkg -l | grep -q libpam-pwquality; then
    check_pass "libpam-pwquality instalado"
else
    check_fail "libpam-pwquality não instalado"
fi

# Verificar configuração de minlen
if grep -q "^minlen = 12" /etc/security/pwquality.conf 2>/dev/null; then
    check_pass "Comprimento mínimo de senha: 12 caracteres"
else
    check_fail "Comprimento mínimo de senha não configurado"
fi

# Verificar PASS_MAX_DAYS
if grep -q "^PASS_MAX_DAYS.*90" /etc/login.defs; then
    check_pass "Expiração de senha configurada (90 dias)"
else
    check_fail "Expiração de senha não configurada"
fi

echo

# ============================================================================
# VALIDAÇÃO #5: Monitoramento e Auditoria
# ============================================================================
echo -e "${CYAN}[5/7] Validando Monitoramento e Auditoria${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Verificar auditd ativo
if systemctl is-active --quiet auditd; then
    check_pass "Auditd está ativo"
else
    check_fail "Auditd não está rodando"
fi

# Verificar regras de auditoria
if auditctl -l | grep -q "passwd_changes"; then
    check_pass "Regras de auditoria configuradas"
else
    check_fail "Regras de auditoria não encontradas"
fi

# Verificar proteção de logs (atributo +a)
if lsattr /var/log/auth.log 2>/dev/null | grep -q "a"; then
    check_pass "Logs protegidos contra alteração (append-only)"
else
    check_fail "Logs não protegidos adequadamente"
fi

echo

# ============================================================================
# VALIDAÇÃO #6: Privilégios Sudo
# ============================================================================
echo -e "${CYAN}[6/7] Validando Restrições de Sudo${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Verificar se NOPASSWD foi removido
if ! grep -q "professor.*NOPASSWD.*ALL" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    check_pass "NOPASSWD removido do usuário professor"
else
    check_fail "NOPASSWD ainda presente para professor"
fi

# Verificar logging de sudo
if grep -q "Defaults log_output" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    check_pass "Logging de comandos sudo habilitado"
else
    check_fail "Logging de comandos sudo não configurado"
fi

echo

# ============================================================================
# VALIDAÇÃO #7: Hardening Geral
# ============================================================================
echo -e "${CYAN}[7/7] Validando Hardening Geral do Sistema${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Verificar sysctl hardening
if sysctl net.ipv4.conf.all.rp_filter 2>/dev/null | grep -q "= 1"; then
    check_pass "Proteção contra IP spoofing ativada"
else
    check_fail "Proteção contra IP spoofing não configurada"
fi

if sysctl net.ipv4.tcp_syncookies 2>/dev/null | grep -q "= 1"; then
    check_pass "Proteção contra SYN flood ativada"
else
    check_fail "Proteção contra SYN flood não configurada"
fi

if sysctl kernel.randomize_va_space 2>/dev/null | grep -q "= 2"; then
    check_pass "ASLR (Address Space Layout Randomization) ativado"
else
    check_fail "ASLR não configurado"
fi

# Verificar atualizações automáticas
if dpkg -l | grep -q unattended-upgrades; then
    check_pass "Atualizações automáticas de segurança instaladas"
else
    check_fail "Atualizações automáticas não configuradas"
fi

# Verificar AppArmor (se disponível)
if command -v aa-status > /dev/null 2>&1; then
    if systemctl is-active --quiet apparmor; then
        check_pass "AppArmor está ativo"
    else
        check_fail "AppArmor não está ativo"
    fi
fi

echo

# ============================================================================
# RELATÓRIO FINAL
# ============================================================================
TOTAL=$((PASS_COUNT + FAIL_COUNT))
PERCENTAGE=$((PASS_COUNT * 100 / TOTAL))

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}RESULTADO DA VALIDAÇÃO:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "Testes Passados: ${GREEN}$PASS_COUNT${NC}"
echo -e "Testes Falhados: ${RED}$FAIL_COUNT${NC}"
echo "Total de Testes: $TOTAL"
echo "Conformidade: $PERCENTAGE%"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

if [[ $PERCENTAGE -ge 90 ]]; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   ✅ EXCELENTE! Sistema adequadamente protegido (≥90%)      ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
elif [[ $PERCENTAGE -ge 70 ]]; then
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║   ⚠️  BOM, mas melhorias necessárias (70-89%)               ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
else
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║   ❌ ATENÇÃO! Proteção inadequada (<70%)                    ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
fi

echo
echo "Para corrigir falhas, execute novamente: sudo ./hardening_completo.sh"
echo

exit $FAIL_COUNT
