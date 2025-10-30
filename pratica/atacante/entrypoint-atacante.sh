#!/bin/bash

# Entrypoint para Container Atacante
# Ambiente de pentest para demonstração educacional

echo "=============================================="
echo " CONTAINER ATACANTE - Estação do Aluno"
echo "=============================================="
echo "Hostname: $(hostname)"
echo "IP Address: $(hostname -I)"
echo "Target IP: ${TARGET_IP}"
echo "Data/Hora: $(date)"
echo "=============================================="
echo

echo "🎯 FERRAMENTAS DISPONÍVEIS:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " RECONHECIMENTO:"
echo "   • nmap         - Network scanner"
echo "   • ping         - Testar conectividade"
echo "   • whois        - Informações de domínio"
echo
echo " EXPLORAÇÃO:"
echo "   • hydra        - Brute-force de credenciais"
echo "   • sshpass      - Automação de SSH"
echo "   • metasploit   - Framework de exploração"
echo
echo " SCRIPTS PERSONALIZADOS:"
echo "   • ataque_ssh_bruteforce.sh"
echo "   • exploit_vulnerabilidades.sh"
echo "   • enumerar_rede.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

echo "⚠️  AVISO ÉTICO E LEGAL:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Este ambiente é para FINS EDUCACIONAIS APENAS"
echo " Use apenas no ambiente isolado do laboratório"
echo " NÃO utilize em sistemas reais sem autorização"
echo " Violações podem resultar em consequências legais"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

echo "📚 CENÁRIO DO TRABALHO:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Você (aluno) observou o professor digitando"
echo " a senha e agora tem acesso ao IP da máquina."
echo " Objetivo: Demonstrar como o ataque funciona"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

echo "🚀 COMANDOS RÁPIDOS:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " ping ${TARGET_IP}           # Testar se vítima está ativa"
echo " nmap ${TARGET_IP}           # Escanear portas abertas"
echo " ./ataque_ssh_bruteforce.sh  # Executar ataque SSH"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Verificar conectividade com vítima
echo "[*] Verificando conectividade com vítima (${TARGET_IP})..."
if ping -c 2 ${TARGET_IP} > /dev/null 2>&1; then
    echo "[✓] Vítima está ATIVA e acessível"
else
    echo "[✗] Vítima não responde. Verifique se container está rodando."
fi

echo
echo "[*] Ambiente pronto. Digite 'help' para ver comandos disponíveis."
echo

# Criar função helper
cat > /root/.bashrc <<'EOF'
export PS1='\[\e[1;31m\][ATACANTE]\[\e[0m\] \[\e[1;34m\]\w\[\e[0m\]# '

help() {
    echo "════════════════════════════════════════"
    echo " COMANDOS DISPONÍVEIS NO LABORATÓRIO"
    echo "════════════════════════════════════════"
    echo
    echo "RECONHECIMENTO:"
    echo "  ping <IP>              - Testar conectividade"
    echo "  nmap <IP>              - Escanear portas"
    echo "  nmap -sV <IP>          - Detectar versões de serviços"
    echo
    echo "ATAQUES SSH:"
    echo "  hydra -l USER -p PASS ssh://IP  - Teste de credencial"
    echo "  ssh user@IP             - Conectar via SSH"
    echo "  sshpass -p SENHA ssh user@IP    - SSH com senha"
    echo
    echo "SCRIPTS PERSONALIZADOS:"
    echo "  ./ataque_ssh_bruteforce.sh      - Brute-force SSH"
    echo "  ./exploit_vulnerabilidades.sh   - Explorar 5 vulns"
    echo "  ./enumerar_rede.sh              - Enumerar rede"
    echo
    echo "WORDLISTS:"
    echo "  /root/wordlists/senhas_comuns.txt"
    echo "  /root/wordlists/usuarios_comuns.txt"
    echo
    echo "════════════════════════════════════════"
}

export -f help
EOF

source /root/.bashrc

# Executar comando ou iniciar shell
exec "$@"
