#!/bin/bash

# Script de Hardening Completo - Mitigação de Todas as Vulnerabilidades
# Trabalho Final - Segurança da Informação
# Aplica correções para as 7 vulnerabilidades identificadas

# Verificar se está rodando como root
if [[ $EUID -ne 0 ]]; then
   echo "Este script deve ser executado como root (sudo)"
   exit 1
fi

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

LOG_FILE="/var/log/hardening_$(date +%Y%m%d_%H%M%S).log"

# Banner
echo -e "${GREEN}"
cat <<"EOF"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     🛡️  HARDENING COMPLETO DO SISTEMA                       ║
║                                                              ║
║   Mitigação de Todas as Vulnerabilidades Identificadas      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Iniciando processo de hardening completo do sistema"

# ============================================================================
# VULNERABILIDADE #1: Mitigar Acesso SSH Não Autorizado
# ============================================================================
echo -e "${CYAN}[1/7] Aplicando Hardening no SSH${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

log "V#1: Configurando SSH com parâmetros seguros"

# Backup da configuração original
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)

# Configurações de Hardening SSH
cat > /etc/ssh/sshd_config.d/hardening.conf <<EOF
# Hardening SSH - Trabalho de Segurança da Informação

# Desabilitar login root via SSH
PermitRootLogin no

# Apenas autenticação por chave pública
PubkeyAuthentication yes
PasswordAuthentication no

# Desabilitar autenticação por senha vazia
PermitEmptyPasswords no

# Desabilitar X11 Forwarding
X11Forwarding no

# Configurar timeout de sessão inativa
ClientAliveInterval 300
ClientAliveCountMax 2

# Limitar tentativas de autenticação
MaxAuthTries 3
MaxSessions 2

# Usar apenas protocolo SSH 2
Protocol 2

# Logging detalhado
LogLevel VERBOSE

# Desabilitar autenticação baseada em host
IgnoreRhosts yes
HostbasedAuthentication no

# Configurar criptografia forte
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# Banner de aviso
Banner /etc/ssh/ssh_banner
EOF

# Criar banner de aviso
cat > /etc/ssh/ssh_banner <<EOF
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║              SISTEMA MONITORADO - ACESSO RESTRITO           ║
║                                                              ║
║  Acesso não autorizado é proibido e será processado         ║
║  conforme a lei. Todas as atividades são registradas.       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF

# Instalar e configurar Fail2Ban
log "Instalando Fail2Ban para proteção contra brute-force"
apt-get update -qq && apt-get install -y fail2ban -qq

# Configurar Fail2Ban para SSH
cat > /etc/fail2ban/jail.d/ssh.conf <<EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOF

systemctl enable fail2ban
systemctl restart fail2ban

log "Fail2Ban configurado e ativado"

# Reiniciar SSH
systemctl restart sshd
log "SSH reconfigurado com parâmetros seguros"

echo -e "${GREEN}[✓] SSH hardening aplicado com sucesso${NC}"
echo "  ✓ Autenticação apenas por chave pública"
echo "  ✓ Login root desabilitado"
echo "  ✓ Fail2Ban ativo (3 tentativas / 1 hora de ban)"
echo "  ✓ Timeout de sessão configurado"
echo "  ✓ Criptografia forte habilitada"
echo

# ============================================================================
# VULNERABILIDADE #2: Implementar Segmentação de Rede
# ============================================================================
echo -e "${CYAN}[2/7] Implementando Segmentação de Rede (via firewall)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

log "V#2: Configurando firewall para segmentação"

# Habilitar e configurar UFW
apt-get install -y ufw -qq

# Regras padrão: negar tudo, permitir apenas essencial
ufw default deny incoming
ufw default allow outgoing

# Permitir SSH apenas de IPs confiáveis (ajustar conforme necessidade)
ufw allow from 172.20.0.0/16 to any port 22 proto tcp

# Bloquear serviços desnecessários de fora da rede local
ufw deny from any to any port 21 proto tcp  # FTP
ufw deny from any to any port 23 proto tcp  # Telnet
ufw deny from any to any port 3306 proto tcp  # MySQL externo
ufw deny from any to any port 445 proto tcp  # SMB externo

# Permitir HTTP/HTTPS apenas local
ufw allow from 172.20.0.0/16 to any port 80 proto tcp
ufw allow from 172.20.0.0/16 to any port 443 proto tcp

# Habilitar firewall
echo "y" | ufw enable

log "Firewall configurado com regras restritivas"

echo -e "${GREEN}[✓] Segmentação via firewall aplicada${NC}"
echo "  ✓ Firewall UFW ativado"
echo "  ✓ SSH restrito à rede local"
echo "  ✓ Serviços desnecessários bloqueados externamente"
echo

# ============================================================================
# VULNERABILIDADE #3: Desabilitar Serviços Desnecessários
# ============================================================================
echo -e "${CYAN}[3/7] Desabilitando Serviços Desnecessários${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

log "V#3: Removendo/desabilitando serviços inseguros"

# Lista de serviços para desabilitar
SERVICES_TO_DISABLE=("telnet" "vsftpd" "smbd" "nmbd")

for service in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-active --quiet "$service"; then
        systemctl stop "$service"
        systemctl disable "$service"
        log "Serviço desabilitado: $service"
        echo "  ✓ $service parado e desabilitado"
    fi
done

# Desinstalar completamente (opcional, comentado para demonstração)
# apt-get remove -y telnet vsftpd samba

# Se MySQL for necessário, restringir ao localhost
if systemctl is-active --quiet mysql; then
    sed -i 's/bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null
    systemctl restart mysql
    log "MySQL configurado para aceitar apenas conexões locais"
    echo "  ✓ MySQL restrito ao localhost"
fi

echo -e "${GREEN}[✓] Serviços inseguros desabilitados${NC}"
echo

# ============================================================================
# VULNERABILIDADE #4: Implementar Política de Senhas Fortes
# ============================================================================
echo -e "${CYAN}[4/7] Implementando Política de Senhas Fortes${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

log "V#4: Configurando política de senhas com PAM"

# Instalar libpam-pwquality
apt-get install -y libpam-pwquality -qq

# Configurar requisitos de senha forte
cat > /etc/security/pwquality.conf <<EOF
# Política de Senhas Fortes - Trabalho de Segurança

# Comprimento mínimo: 12 caracteres
minlen = 12

# Mínimo de classes de caracteres (maiúsculas, minúsculas, dígitos, especiais)
minclass = 3

# Requerir pelo menos 1 dígito
dcredit = -1

# Requerir pelo menos 1 maiúscula
ucredit = -1

# Requerir pelo menos 1 minúscula
lcredit = -1

# Requerir pelo menos 1 caractere especial
ocredit = -1

# Máximo de caracteres repetidos consecutivos
maxrepeat = 2

# Verificar contra dicionário
dictcheck = 1

# Verificar se senha contém o nome do usuário
usercheck = 1

# Rejeitar senhas em wordlists comuns
enforcing = 1
EOF

# Configurar expiração de senha
sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

log "Política de senhas fortes configurada"

# Forçar troca de senha do usuário professor
echo -e "${YELLOW}[!] AÇÃO MANUAL NECESSÁRIA:${NC}"
echo "Execute: sudo passwd professor"
echo "Nova senha deve atender aos requisitos (12+ caracteres, complexa)"

echo -e "${GREEN}[✓] Política de senhas configurada${NC}"
echo "  ✓ Mínimo 12 caracteres"
echo "  ✓ Complexidade requerida (maiúscula, minúscula, dígito, especial)"
echo "  ✓ Expiração a cada 90 dias"
echo "  ✓ Verificação contra dicionários"
echo

# ============================================================================
# VULNERABILIDADE #5: Implementar Monitoramento e Auditoria
# ============================================================================
echo -e "${CYAN}[5/7] Implementando Monitoramento e Auditoria${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

log "V#5: Configurando auditd e syslog centralizado"

# Instalar auditd
apt-get install -y auditd audispd-plugins -qq

# Configurar regras de auditoria
cat > /etc/audit/rules.d/hardening.rules <<EOF
# Regras de Auditoria - Trabalho de Segurança da Informação

# Auditar mudanças em arquivos de senha
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/gshadow -p wa -k gshadow_changes
-w /etc/group -p wa -k group_changes

# Auditar modificações em sudo
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Auditar logs de autenticação
-w /var/log/auth.log -p wa -k auth_log_changes
-w /var/log/faillog -p wa -k faillog_changes

# Auditar comandos privilegiados
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged_commands
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged_commands

# Auditar mudanças em configuração SSH
-w /etc/ssh/sshd_config -p wa -k sshd_config_changes

# Auditar tentativas de esconder rastros
-w /var/log/ -p wa -k log_tampering

# Auditar acesso a arquivos sensíveis
-w /home/professor/ -p rwa -k professor_files_access

# Auditar mudanças no sistema
-w /etc/sysctl.conf -p wa -k sysctl_changes
-w /etc/hosts -p wa -k hosts_changes

# Auditar loading de módulos do kernel
-w /sbin/insmod -p x -k module_loading
-w /sbin/rmmod -p x -k module_loading
-w /sbin/modprobe -p x -k module_loading
EOF

# Reiniciar auditd
systemctl enable auditd
systemctl restart auditd

log "Auditd configurado com regras abrangentes"

# Configurar imutabilidade de logs (proteção contra alteração)
chattr +a /var/log/auth.log 2>/dev/null || true
chattr +a /var/log/syslog 2>/dev/null || true

log "Logs protegidos contra alteração (append-only)"

# Configurar rsyslog para log centralizado (simular)
cat >> /etc/rsyslog.conf <<EOF

# Log centralizado (ajustar para servidor syslog real)
# *.* @@syslog-server.example.com:514
EOF

systemctl restart rsyslog

echo -e "${GREEN}[✓] Monitoramento e auditoria implementados${NC}"
echo "  ✓ Auditd configurado e ativo"
echo "  ✓ Monitoramento de arquivos críticos"
echo "  ✓ Logs protegidos contra alteração"
echo "  ✓ Auditoria de comandos privilegiados"
echo

# ============================================================================
# VULNERABILIDADE #6: Remover Privilégios Excessivos de Sudo
# ============================================================================
echo -e "${CYAN}[6/7] Removendo Privilégios Excessivos de Sudo${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

log "V#6: Restringindo privilégios sudo"

# Backup do sudoers
cp /etc/sudoers /etc/sudoers.backup.$(date +%Y%m%d)

# Remover NOPASSWD do professor
sed -i '/professor.*NOPASSWD/d' /etc/sudoers

# Criar configuração restritiva para professor
cat > /etc/sudoers.d/professor <<EOF
# Permissões restritas para professor
# Apenas comandos específicos necessários

professor ALL=(ALL) /usr/bin/apt-get, /usr/bin/systemctl status, /usr/bin/journalctl
EOF

chmod 0440 /etc/sudoers.d/professor

log "Privilégios sudo restritos para professor"

# Habilitar logging de comandos sudo
echo 'Defaults log_output' >> /etc/sudoers.d/logging
echo 'Defaults!/usr/bin/sudoreplay !log_output' >> /etc/sudoers.d/logging
chmod 0440 /etc/sudoers.d/logging

echo -e "${GREEN}[✓] Privilégios sudo restritos${NC}"
echo "  ✓ NOPASSWD removido"
echo "  ✓ Apenas comandos específicos permitidos"
echo "  ✓ Logging de comandos sudo ativado"
echo

# ============================================================================
# VULNERABILIDADE #7: Aplicar Hardening Geral do Sistema Operacional
# ============================================================================
echo -e "${CYAN}[7/7] Aplicando Hardening Geral do Sistema${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

log "V#7: Aplicando hardening geral baseado em CIS Benchmark"

# Configurar kernel hardening via sysctl
cat > /etc/sysctl.d/99-hardening.conf <<EOF
# Kernel Hardening - CIS Benchmark

# Proteção contra IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Desabilitar IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Desabilitar ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Desabilitar source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Proteção SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Ignorar ICMP ping broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignorar ICMP erros
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Log de pacotes suspeitos
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Proteção contra buffer overflow
kernel.exec-shield = 1
kernel.randomize_va_space = 2

# Restrições de core dumps
fs.suid_dumpable = 0

# Limitar acesso a dmesg
kernel.dmesg_restrict = 1

# Restrições de ptrace
kernel.yama.ptrace_scope = 1
EOF

# Aplicar configurações
sysctl -p /etc/sysctl.d/99-hardening.conf > /dev/null

log "Kernel hardening aplicado"

# Habilitar AppArmor (se disponível)
if command -v aa-enforce > /dev/null 2>&1; then
    systemctl enable apparmor
    systemctl start apparmor
    log "AppArmor habilitado"
    echo "  ✓ AppArmor ativado"
fi

# Atualizar sistema
log "Aplicando atualizações de segurança"
apt-get update -qq
apt-get upgrade -y -qq

# Configurar atualizações automáticas de segurança
apt-get install -y unattended-upgrades -qq
dpkg-reconfigure -plow unattended-upgrades

echo -e "${GREEN}[✓] Hardening geral do sistema aplicado${NC}"
echo "  ✓ Kernel hardening ativado"
echo "  ✓ Proteções contra ataques de rede"
echo "  ✓ Atualizações de segurança automáticas"
echo

# ============================================================================
# RELATÓRIO FINAL
# ============================================================================
echo
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║     ✅ HARDENING COMPLETO APLICADO COM SUCESSO!             ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${BLUE}RESUMO DAS MITIGAÇÕES APLICADAS:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ V#1: SSH hardening (chaves, fail2ban, criptografia forte)"
echo "✅ V#2: Segmentação via firewall (UFW configurado)"
echo "✅ V#3: Serviços inseguros desabilitados (Telnet, FTP, SMB)"
echo "✅ V#4: Política de senhas fortes (12+ chars, complexidade)"
echo "✅ V#5: Monitoramento completo (auditd, logs protegidos)"
echo "✅ V#6: Privilégios sudo restritos (sem NOPASSWD)"
echo "✅ V#7: Hardening geral (kernel, AppArmor, updates automáticos)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo -e "${YELLOW}PRÓXIMOS PASSOS NECESSÁRIOS:${NC}"
echo "1. Trocar senha do usuário 'professor' (sudo passwd professor)"
echo "2. Gerar chave SSH para autenticação: ssh-keygen -t ed25519"
echo "3. Copiar chave pública para ~/.ssh/authorized_keys"
echo "4. Testar conexão SSH com chave antes de desabilitar senha"
echo "5. Reiniciar sistema para aplicar todas as mudanças"
echo
echo -e "${CYAN}VALIDAÇÃO:${NC}"
echo "Execute ./validar_hardening.sh para verificar todas as mitigações"
echo
echo "Log completo salvo em: $LOG_FILE"
echo

log "Processo de hardening completo finalizado com sucesso"
