#!/bin/bash

# Script de entrada para o container Network Security Scanner
echo "=================================================="
echo "  🛡️  Network Security Scanner Container"
echo "=================================================="
echo "Versão: 2.0"
echo "Data: $(date)"
echo "Container ID: $(hostname)"
echo "=================================================="
echo

# Verificar se as dependências estão instaladas
echo "🔍 Verificando dependências..."
commands=("ping" "dig" "ip" "nc" "timeout")
missing=()

for cmd in "${commands[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        missing+=("$cmd")
    fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
    echo "❌ Dependências faltando: ${missing[*]}"
    echo "Verifique o Dockerfile e reconstrua a imagem."
    exit 1
else
    echo "✅ Todas as dependências estão instaladas"
fi

echo
echo "📁 Diretórios disponíveis:"
echo "   /app          - Arquivos do projeto"
echo "   /app/reports  - Relatórios gerados"
echo "   /app/logs     - Arquivos de log"
echo

echo "🚀 Comandos disponíveis:"
echo "   ./network_security_scanner.sh        - Executar scanner"
echo "   ./network_security_scanner.sh --help - Ajuda"
echo "   ./test_ssh_port.sh                   - Teste isolado"
echo

# Se nenhum argumento foi passado, mostrar menu
if [[ $# -eq 0 ]]; then
    echo "💡 Para executar o scanner:"
    echo "   docker exec -it network-security-scanner ./network_security_scanner.sh"
    echo
    echo "💡 Ou acesse o container:"
    echo "   docker exec -it network-security-scanner /bin/bash"
    echo
    echo "🕐 Mantendo container ativo..."
    tail -f /dev/null
else
    # Executar comando passado
    exec "$@"
fi