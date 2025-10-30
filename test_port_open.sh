#!/bin/bash

# Teste para verificar se a detecção de portas funciona

echo "Testando detecção de portas abertas..."

# Iniciar netcat em background ouvindo na porta 9999
nc -l -p 9999 &
NC_PID=$!

# Aguardar um pouco
sleep 1

# Testar se a porta está aberta
if timeout 2 bash -c "echo >/dev/tcp/127.0.0.1/9999" 2>/dev/null; then
    echo "✅ Porta 9999 detectada como ABERTA - função funcionando!"
else
    echo "❌ Porta 9999 detectada como FECHADA - problema na função"
fi

# Matar o netcat
kill $NC_PID 2>/dev/null

echo "Teste concluído."
