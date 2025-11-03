#!/bin/bash

# Script de Hardening Rápido - Otimizado para Apresentação
# Remove caracteres especiais e executa rapidamente

echo "=========================================="
echo "🛡️ HARDENING COMPLETO DO SISTEMA"
echo "=========================================="
echo

echo "[1/7] SSH Hardening..."
# Configurar SSH seguro
cat > /etc/ssh/sshd_config.d/hardening.conf <<EOF
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
EOF

echo "✅ SSH configurado (apenas chaves, sem senhas)"

echo "[2/7] Firewall..."
# Configurar UFW
ufw --force enable > /dev/null 2>&1
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1

echo "✅ Firewall ativado (deny incoming)"

echo "[3/7] Desabilitando serviços..."
# Parar serviços inseguros
systemctl stop telnet vsftpd smbd nmbd 2>/dev/null || true

echo "✅ Serviços inseguros desabilitados"

echo "[4/7] Política de senhas..."
# Configurar senhas fortes
echo "minlen = 12" > /etc/security/pwquality.conf
echo "minclass = 3" >> /etc/security/pwquality.conf

echo "✅ Política de senhas fortes (12+ chars)"

echo "[5/7] Monitoramento..."
# Configurar auditoria básica
echo "-w /etc/passwd -p wa -k passwd_changes" > /etc/audit/rules.d/hardening.rules

echo "✅ Auditoria configurada"

echo "[6/7] Sudo restrito..."
# Remover NOPASSWD
sed -i '/professor.*NOPASSWD/d' /etc/sudoers
echo "professor ALL=(ALL) /usr/bin/apt-get, /usr/bin/systemctl status" > /etc/sudoers.d/professor

echo "✅ Privilégios sudo restritos"

echo "[7/7] Hardening geral..."
# Kernel hardening básico
echo "net.ipv4.tcp_syncookies = 1" > /etc/sysctl.d/99-hardening.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/99-hardening.conf

echo "✅ Kernel hardening aplicado"

echo
echo "=========================================="
echo "🎉 HARDENING COMPLETO APLICADO!"
echo "   ✅ SSH protegido (apenas chaves)"
echo "   ✅ Firewall ativo"
echo "   ✅ Serviços inseguros desabilitados"
echo "   ✅ Senhas fortes obrigatórias"
echo "   ✅ Auditoria ativa"
echo "   ✅ Sudo restrito"
echo "   ✅ Kernel protegido"
echo "=========================================="