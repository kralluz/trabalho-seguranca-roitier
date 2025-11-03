#!/bin/bash

# Script de Validação Rápida - Otimizado para Apresentação

echo "=========================================="
echo "✓ VALIDAÇÃO DE HARDENING"
echo "=========================================="
echo

PASS=0
FAIL=0

echo "[1/7] Validando SSH..."
if grep -q "PasswordAuthentication no" /etc/ssh/sshd_config* 2>/dev/null; then
    echo "✅ SSH: Autenticação por senha desabilitada"
    ((PASS++))
else
    echo "❌ SSH: Ainda aceita senhas"
    ((FAIL++))
fi

echo "[2/7] Validando Firewall..."
if ufw status 2>/dev/null | grep -q "Status: active"; then
    echo "✅ Firewall: UFW ativo"
    ((PASS++))
else
    echo "❌ Firewall: UFW inativo"
    ((FAIL++))
fi

echo "[3/7] Validando Serviços..."
if ! systemctl is-active --quiet telnet 2>/dev/null; then
    echo "✅ Serviços: Telnet desabilitado"
    ((PASS++))
else
    echo "❌ Serviços: Telnet ainda ativo"
    ((FAIL++))
fi

echo "[4/7] Validando Senhas..."
if [ -f /etc/security/pwquality.conf ] && grep -q "minlen = 12" /etc/security/pwquality.conf; then
    echo "✅ Senhas: Política forte configurada"
    ((PASS++))
else
    echo "❌ Senhas: Política não configurada"
    ((FAIL++))
fi

echo "[5/7] Validando Auditoria..."
if [ -f /etc/audit/rules.d/hardening.rules ]; then
    echo "✅ Auditoria: Regras configuradas"
    ((PASS++))
else
    echo "❌ Auditoria: Sem regras"
    ((FAIL++))
fi

echo "[6/7] Validando Sudo..."
if ! grep -q "NOPASSWD" /etc/sudoers 2>/dev/null; then
    echo "✅ Sudo: NOPASSWD removido"
    ((PASS++))
else
    echo "❌ Sudo: NOPASSWD ainda presente"
    ((FAIL++))
fi

echo "[7/7] Validando Kernel..."
if [ -f /etc/sysctl.d/99-hardening.conf ]; then
    echo "✅ Kernel: Hardening aplicado"
    ((PASS++))
else
    echo "❌ Kernel: Sem hardening"
    ((FAIL++))
fi

TOTAL=$((PASS + FAIL))
PERCENT=$((PASS * 100 / TOTAL))

echo
echo "=========================================="
echo "RESULTADO DA VALIDAÇÃO:"
echo "   Testes Passados: $PASS"
echo "   Testes Falhados: $FAIL"
echo "   Conformidade: $PERCENT%"
echo "=========================================="

if [ $PERCENT -ge 70 ]; then
    echo "🎉 SISTEMA ADEQUADAMENTE PROTEGIDO!"
    exit 0
else
    echo "⚠️  PROTEÇÃO INSUFICIENTE - Execute hardening novamente"
    exit 1
fi