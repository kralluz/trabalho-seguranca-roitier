#!/bin/bash

# Script de Teste do Network Security Scanner
# Demonstra o uso e geração de relatórios

echo "======================================"
echo "  Teste do Network Security Scanner"
echo "======================================"
echo ""

# Verifica se Python está instalado
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 não encontrado. Instale Python 3.6+"
    exit 1
fi

echo "✅ Python3 encontrado: $(python3 --version)"
echo ""

# Torna o script executável
chmod +x network_security_scanner.py

echo "📋 Executando scan de exemplo em localhost..."
echo "   (O relatório será salvo automaticamente em arquivo .txt)"
echo ""

# Executa o scanner (com input automático para confirmar)
echo "sim" | python3 network_security_scanner.py localhost

echo ""
echo "======================================"
echo "  Arquivos gerados:"
echo "======================================"
ls -lh security_report_*.txt 2>/dev/null || echo "Nenhum relatório encontrado"

echo ""
echo "📄 Para visualizar o relatório mais recente:"
echo "   cat \$(ls -t security_report_*.txt | head -1)"
echo ""
echo "✅ Teste concluído!"
