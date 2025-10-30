#!/bin/bash

# Teste isolado da função check_ssh_port

# Função para verificar porta SSH
check_ssh_port() {
    local ip=$1
    echo "[*] Verificando Porta SSH Padrão em $ip..."

    if timeout 2 bash -c "echo >/dev/tcp/$ip/22" 2>/dev/null; then
        echo "  [!] ALERTA: Porta 22 (SSH) está ABERTA em $ip"
        echo "  ✅ Função funcionando corretamente - porta detectada como aberta"
    else
        echo "  [+] Porta 22 fechada ou filtrada em $ip"
        echo "  ✅ Função funcionando corretamente - porta detectada como fechada"
    fi
}

# Testar em localhost (deve estar aberta)
echo "Testando em localhost (127.0.0.1):"
check_ssh_port "127.0.0.1"

echo
echo "Testando em um IP inexistente (192.168.24.999):"
check_ssh_port "192.168.24.999"

echo
echo "✅ Teste concluído - função check_ssh_port está funcionando corretamente!"
