#!/bin/bash

# Network Security Scanner - Versão Bash
# Ferramenta educacional para análise de vulnerabilidades de rede
# Autor: Conversão do script Python original
# Propósito: Identificar configurações inseguras em ambientes de rede

# Cores para output
RED='\033[0;31m'
ORANGE='\033[0;33m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Array para armazenar resultados
declare -A results
results[autenticacao]=""
results[rede]=""
results[criptografia]=""
results[protecao]=""
results[vazamento]=""
results[poisoning]=""

# Variáveis globais para estatísticas da rede
total_hosts_scanned=0
total_hosts_alive=0
total_vulnerabilities=0
hosts_with_vulns=0
network_summary=""

# Função para imprimir banner
print_banner() {
    echo "======================================================================"
    echo "     NETWORK SECURITY SCANNER - Análise Exploratória (Bash)"
    echo "======================================================================"
    echo "Target: $1"
    echo "Scan iniciado em: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "======================================================================"
    echo
}

# Função para resolver host
resolve_host() {
    local target=$1
    local ip

    if [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Já é IP
        ip=$target
        echo "[+] Host já é IP: $target"
    else
        # Resolver nome
        ip=$(getent hosts "$target" | awk '{print $1}' | head -1)
        if [[ -z $ip ]]; then
            echo "[-] Erro ao resolver host: $target"
            return 1
        fi
        echo "[+] Host resolvido: $target -> $ip"
    fi

    echo "$ip"
}

# Função para verificar porta SSH
check_ssh_port() {
    local ip=$1
    echo
    echo "[*] Verificando Porta SSH Padrão..."

    if timeout 2 bash -c "echo >/dev/tcp/$ip/22" 2>/dev/null; then
        results[rede]="${results[rede]}Porta SSH padrão (22) exposta|MÉDIO|Porta 22 está aberta e pode ser alvo de força bruta\n"
        echo "  [!] ALERTA: Porta 22 (SSH) está ABERTA"

        # Tentar capturar banner SSH
        check_ssh_banner "$ip"
    else
        echo "  [+] Porta 22 fechada ou filtrada"
    fi
}

# Função para capturar banner SSH
check_ssh_banner() {
    local ip=$1
    local banner

    if command -v telnet >/dev/null 2>&1; then
        banner=$(timeout 3 bash -c "echo '' | telnet $ip 22 2>/dev/null | head -1" 2>/dev/null)
        if [[ -n $banner && ! $banner =~ "Connection refused" && ! $banner =~ "telnet:" ]]; then
            echo "  [+] Banner SSH: $banner"
            results[vazamento]="${results[vazamento]}Banner SSH revela informações|BAIXO|Banner: $banner\n"
        else
            echo "  [-] Não foi possível capturar banner SSH"
        fi
    else
        echo "  [-] Comando 'telnet' não disponível - pulando captura de banner"
    fi
}

# Função para escanear portas comuns
scan_common_ports() {
    local ip=$1
    echo
    echo "[*] Escaneando Portas Comuns..."

    # Portas comuns
    declare -A common_ports=(
        [21]="FTP"
        [22]="SSH"
        [23]="Telnet"
        [25]="SMTP"
        [53]="DNS"
        [80]="HTTP"
        [110]="POP3"
        [143]="IMAP"
        [443]="HTTPS"
        [445]="SMB"
        [3306]="MySQL"
        [3389]="RDP"
        [5432]="PostgreSQL"
        [8080]="HTTP-Alt"
    )

    local open_ports=()
    local port_count=0

    for port in "${!common_ports[@]}"; do
        if timeout 1 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            open_ports+=("$port")
            echo "  [!] Porta $port (${common_ports[$port]}) está ABERTA"
            ((port_count++))

            # Alertas específicos
            if [[ $port -eq 23 ]]; then
                results[criptografia]="${results[criptografia]}Telnet sem criptografia|CRÍTICO|Telnet transmite dados em texto claro\n"
            elif [[ $port -eq 21 ]]; then
                results[criptografia]="${results[criptografia]}FTP sem criptografia|ALTO|FTP transmite credenciais em texto claro\n"
            fi
        fi
    done

    if [[ $port_count -eq 0 ]]; then
        echo "  [+] Nenhuma porta comum encontrada aberta"
    else
        results[rede]="${results[rede]}$port_count portas abertas detectadas|VARIÁVEL|Portas: [${open_ports[*]}]\n"
    fi
}

# Função para verificar ICMP
check_icmp_response() {
    local ip=$1
    echo
    echo "[*] Verificando Resposta ICMP (Ping)..."

    if ping -c 2 -W 2 "$ip" >/dev/null 2>&1; then
        echo "  [!] Host responde a ICMP ping"
        results[rede]="${results[rede]}Host responde a ICMP ping|BAIXO|Facilita descoberta de hosts na rede\n"
    else
        echo "  [+] Host não responde a ICMP ping (stealth)"
    fi
}

# Função para verificar DNS
check_dns_info() {
    local target=$1
    echo
    echo "[*] Verificando Informações DNS..."

    if command -v dig >/dev/null 2>&1; then
        local dns_output
        dns_output=$(dig "$target" ANY +short 2>/dev/null)

        if [[ -n $dns_output ]]; then
            echo "  [+] Registros DNS encontrados:"
            echo "$dns_output" | while read -r line; do
                echo "      $line"
            done
            results[vazamento]="${results[vazamento]}Informações DNS públicas|INFO|Registros DNS revelam informações sobre a infraestrutura\n"
        else
            echo "  [+] Nenhum registro DNS encontrado"
        fi
    else
        echo "  [-] Comando 'dig' não disponível - pulando verificação DNS"
    fi
}

# Função para testar DNS Zone Transfer
check_dns_zone_transfer() {
    local target=$1
    echo
    echo "[*] Testando DNS Zone Transfer..."

    if command -v dig >/dev/null 2>&1; then
        local axfr_output
        axfr_output=$(dig axfr "@$target" "$target" 2>/dev/null)

        if echo "$axfr_output" | grep -q "IN.*NS"; then
            echo "  [!!!] CRÍTICO: DNS Zone Transfer HABILITADO!"
            results[vazamento]="${results[vazamento]}DNS Zone Transfer habilitado|CRÍTICO|Permite enumeração completa da zona DNS\n"
        else
            echo "  [+] DNS Zone Transfer protegido"
        fi
    else
        echo "  [-] Comando 'dig' não disponível - pulando teste Zone Transfer"
    fi
}

# Função para verificar NetBIOS
check_netbios_services() {
    local ip=$1
    echo
    echo "[*] Verificando Serviços NetBIOS..."

    local netbios_ports=(137 138 139)
    local netbios_found=false

    for port in "${netbios_ports[@]}"; do
        if timeout 1 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            netbios_found=true
            echo "  [!] Porta NetBIOS $port está ABERTA"
        fi
    done

    if $netbios_found; then
        results[poisoning]="${results[poisoning]}NetBIOS habilitado|ALTO|Permite ataques de NetBIOS poisoning e LLMNR\n"
    else
        echo "  [+] NetBIOS não detectado"
    fi
}

# Função para verificar SMB
check_smb_signing() {
    local ip=$1
    echo
    echo "[*] Verificando Configuração SMB..."

    if timeout 2 bash -c "echo >/dev/tcp/$ip/445" 2>/dev/null; then
        echo "  [!] Porta 445 (SMB) está ABERTA"
        results[rede]="${results[rede]}Porta SMB exposta|ALTO|SMB pode ser alvo de ataques como EternalBlue\n"
    else
        echo "  [+] Porta SMB fechada"
    fi
}

# Função para verificar IPv6
check_ipv6_enabled() {
    echo
    echo "[*] Verificando IPv6..."

    if ip -6 addr show 2>/dev/null | grep -q "inet6.*scope global"; then
        echo "  [!] IPv6 está HABILITADO"
        results[vazamento]="${results[vazamento]}IPv6 habilitado|MÉDIO|IPv6 pode vazar informações se não for monitorado\n"
    else
        echo "  [+] IPv6 não detectado ou desabilitado"
    fi
}

# Função para gerar relatório
generate_report() {
    echo
    echo "======================================================================"
    echo "                    RELATÓRIO DE VULNERABILIDADES"
    echo "======================================================================"

    local total_vulns=0
    for category in autenticacao rede criptografia protecao vazamento poisoning; do
        local count
        count=$(echo -e "${results[$category]}" | grep -c ".")
        ((total_vulns += count))
    done

    echo
    echo "[*] Total de vulnerabilidades encontradas: $total_vulns"
    echo

    declare -A categories=(
        [autenticacao]="AUTENTICAÇÃO E AUTORIZAÇÃO"
        [rede]="CONFIGURAÇÃO DE REDE"
        [criptografia]="CRIPTOGRAFIA"
        [protecao]="PROTEÇÃO CONTRA AMEAÇAS"
        [vazamento]="VAZAMENTO DE INFORMAÇÃO"
        [poisoning]="ATAQUES DE POISONING"
    )

    for category in "${!categories[@]}"; do
        if [[ -n ${results[$category]} ]]; then
            echo "──────────────────────────────────────────────────────────────────────"
            echo "  ${categories[$category]}"
            echo "──────────────────────────────────────────────────────────────────────"

            local idx=1
            echo -e "${results[$category]}" | while IFS='|' read -r vuln risk details; do
                if [[ -n $vuln ]]; then
                    local risk_color
                    case $risk in
                        "CRÍTICO") risk_color="${RED}🔴" ;;
                        "ALTO") risk_color="${ORANGE}🟠" ;;
                        "MÉDIO") risk_color="${YELLOW}🟡" ;;
                        "BAIXO") risk_color="${GREEN}🟢" ;;
                        "INFO") risk_color="${BLUE}ℹ️" ;;
                        "VARIÁVEL") risk_color="⚪" ;;
                        *) risk_color="⚪" ;;
                    esac

                    echo
                    echo "  [$idx] $vuln"
                    echo "      Risco: ${risk_color} $risk${NC}"
                    echo "      Detalhes: $details"
                    ((idx++))
                fi
            done
        fi
    done

    echo
    echo "======================================================================"
    echo "                    FIM DO RELATÓRIO"
    echo "======================================================================"
}

# Função para salvar relatório
save_report() {
    local target=$1
    local filename="security_report_$(date '+%Y%m%d_%H%M%S').txt"

    {
        echo "======================================================================"
        echo "     NETWORK SECURITY SCANNER - Relatório de Análise (Bash)"
        echo "======================================================================"
        echo "Target: $target"
        echo "Data: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "======================================================================"
        echo

        local total_vulns=0
        for category in autenticacao rede criptografia protecao vazamento poisoning; do
            local count
            count=$(echo -e "${results[$category]}" | grep -c ".")
            ((total_vulns += count))
        done

        echo "Total de vulnerabilidades encontradas: $total_vulns"
        echo

        declare -A categories=(
            [autenticacao]="AUTENTICAÇÃO E AUTORIZAÇÃO"
            [rede]="CONFIGURAÇÃO DE REDE"
            [criptografia]="CRIPTOGRAFIA"
            [protecao]="PROTEÇÃO CONTRA AMEAÇAS"
            [vazamento]="VAZAMENTO DE INFORMAÇÃO"
            [poisoning]="ATAQUES DE POISONING"
        )

        for category in "${!categories[@]}"; do
            if [[ -n ${results[$category]} ]]; then
                echo "──────────────────────────────────────────────────────────────────────"
                echo "  ${categories[$category]}"
                echo "──────────────────────────────────────────────────────────────────────"

                local idx=1
                echo -e "${results[$category]}" | while IFS='|' read -r vuln risk details; do
                    if [[ -n $vuln ]]; then
                        echo
                        echo "  [$idx] $vuln"
                        echo "      Risco: $risk"
                        echo "      Detalhes: $details"
                        ((idx++))
                    fi
                done
            fi
        done

        echo
        echo "======================================================================"
        echo "                    FIM DO RELATÓRIO"
        echo "======================================================================"

    } > "$filename"

    echo
    echo "[+] Relatório salvo em: $filename"
}

# Função para escanear range de rede
scan_range() {
    local network=$1
    local base=$(echo "$network" | cut -d/ -f1 | cut -d. -f1-3)
    echo "[*] Escaneando rede: $network (hosts 1-254)"
    echo "[*] Isso pode levar alguns minutos..."
    echo

    # Resetar estatísticas
    total_hosts_scanned=0
    total_hosts_alive=0
    total_vulnerabilities=0
    hosts_with_vulns=0
    network_summary=""

    for i in {1..254}; do
        ((total_hosts_scanned++))
        host="$base.$i"

        # Mostrar progresso a cada 10 hosts
        if (( i % 10 == 0 )); then
            echo "[*] Verificado $i/254 hosts... ($total_hosts_alive vivos encontrados)"
        fi

        if ping -c 1 -W 1 "$host" >/dev/null 2>&1; then
            ((total_hosts_alive++))
            echo "[+] Host vivo encontrado: $host"

            # Resetar results para este host
            results[autenticacao]=""
            results[rede]=""
            results[criptografia]=""
            results[protecao]=""
            results[vazamento]=""
            results[poisoning]=""

            # Executar scan completo para este host
            local ip
            ip=$(resolve_host "$host")
            if [[ -n $ip ]]; then
                check_ssh_port "$ip"
                scan_common_ports "$ip"
                check_icmp_response "$ip"
                check_dns_info "$host"
                check_dns_zone_transfer "$host"
                check_netbios_services "$ip"
                check_smb_signing "$ip"
                check_ipv6_enabled

                # Contar vulnerabilidades deste host
                local host_vulns=0
                local host_details=""
                for category in autenticacao rede criptografia protecao vazamento poisoning; do
                    local count
                    count=$(echo -e "${results[$category]}" | grep -c "|")
                    ((host_vulns += count))
                    if [[ -n ${results[$category]} ]]; then
                        host_details="${host_details}${results[$category]}"
                    fi
                done

                ((total_vulnerabilities += host_vulns))
                if (( host_vulns > 0 )); then
                    ((hosts_with_vulns++))
                fi

                # Adicionar ao resumo da rede com detalhes
                network_summary="${network_summary}$host|$ip|$host_vulns|$host_details\n"

                # NÃO salvar relatório individual - apenas consolidado
            fi
        fi
    done

    echo
    echo "[*] Scan da rede concluído!"
    echo "[+] Total de hosts verificados: $total_hosts_scanned"
    echo "[+] Hosts ativos encontrados: $total_hosts_alive"
    echo "[+] Total de vulnerabilidades: $total_vulnerabilities"
    echo "[+] Hosts com vulnerabilidades: $hosts_with_vulns"
    echo "[+] Relatórios individuais: NÃO GERADOS (apenas relatório consolidado)"
    echo

    # Gerar relatório consolidado da rede
    generate_network_report "$network"
}

# Função para gerar relatório consolidado da rede
generate_network_report() {
    local network=$1
    echo
    echo "======================================================================"
    echo "           RELATÓRIO CONSOLIDADO DA REDE - $network"
    echo "======================================================================"
    echo "Data: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "======================================================================"
    echo
    echo "📊 ESTATÍSTICAS GERAIS DA REDE:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "• Total de hosts verificados: $total_hosts_scanned"
    echo "• Hosts ativos encontrados: $total_hosts_alive"
    echo "• Hosts inativos: $((total_hosts_scanned - total_hosts_alive))"
    echo "• Total de vulnerabilidades encontradas: $total_vulnerabilities"
    echo "• Hosts com pelo menos 1 vulnerabilidade: $hosts_with_vulns"
    echo "• Hosts seguros (0 vulnerabilidades): $((total_hosts_alive - hosts_with_vulns))"
    echo

    if [[ -n $network_summary ]]; then
        echo "📋 DETALHES POR HOST:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Host/IP              | Vulnerabilidades"
        echo "─────────────────────┼────────────────"
        echo -e "$network_summary" | while IFS='|' read -r host ip vulns; do
            printf "%-20s | %s\n" "$host ($ip)" "$vulns"
        done
        echo
    fi

    echo "🔍 ANÁLISE DE SEGURANÇA:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if (( total_vulnerabilities == 0 )); then
        echo "✅ EXCELENTE: Nenhum host apresentou vulnerabilidades detectadas!"
        echo "   A rede parece estar bem protegida contra as ameaças verificadas."
    elif (( total_vulnerabilities < 5 )); then
        echo "⚠️  ATENÇÃO: Poucas vulnerabilidades encontradas."
        echo "   Recomenda-se correção imediata e monitoramento contínuo."
    elif (( total_vulnerabilities < 20 )); then
        echo "🟠 ALERTA: Várias vulnerabilidades detectadas."
        echo "   Correção prioritária necessária para hosts críticos."
    else
        echo "🔴 CRÍTICO: Múltiplas vulnerabilidades encontradas!"
        echo "   Ação imediata necessária para proteger a rede."
    fi
    echo

    echo "💡 RECOMENDAÇÕES GERAIS:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "1. 🔐 AUTENTICAÇÃO E ACESSO:"
    echo "   • Implementar autenticação multifator (MFA) onde possível"
    echo "   • Usar senhas fortes e rotação periódica"
    echo "   • Desabilitar protocolos inseguros (Telnet, FTP não criptografado)"
    echo
    echo "2. 🛡️ CONFIGURAÇÃO DE REDE:"
    echo "   • Fechar portas desnecessárias no firewall"
    echo "   • Implementar segmentação de rede (VLANs)"
    echo "   • Configurar regras de acesso baseadas em necessidade"
    echo "   • Desabilitar resposta ICMP se não necessário"
    echo
    echo "3. 🔒 CRIPTOGRAFIA:"
    echo "   • Usar apenas protocolos criptografados (SSH, SFTP, HTTPS)"
    echo "   • Implementar certificados SSL/TLS válidos"
    echo "   • Evitar transmissão de dados sensíveis em texto claro"
    echo
    echo "4. 👁️ MONITORAMENTO E DETECÇÃO:"
    echo "   • Implementar sistema de detecção de intrusão (IDS/IPS)"
    echo "   • Configurar logging centralizado e alertas"
    echo "   • Realizar scans regulares de vulnerabilidades"
    echo "   • Monitorar tráfego de rede suspeito"
    echo
    echo "5. 📚 MELHORES PRÁTICAS:"
    echo "   • Manter sistemas atualizados com patches de segurança"
    echo "   • Realizar backups regulares e testá-los"
    echo "   • Treinar usuários sobre segurança da informação"
    echo "   • Desenvolver e testar plano de resposta a incidentes"
    echo
    echo "6. 🏢 GOVERNANÇA:"
    echo "   • Definir políticas de segurança claras"
    echo "   • Realizar auditorias regulares"
    echo "   • Cumprir frameworks como ISO 27001 ou NIST"
    echo "   • Documentar todas as configurações e mudanças"
    echo

    echo "📝 NOTAS PARA TRABALHO ACADÊMICO:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "• Este relatório foi gerado automaticamente pelo Network Security Scanner"
    echo "• As verificações incluem 26 tipos de vulnerabilidades em 6 categorias"
    echo "• Limitações: Não detecta vulnerabilidades zero-day ou configurações internas"
    echo "• Recomendação: Complementar com ferramentas especializadas (Nessus, OpenVAS)"
    echo "• Para uso em produção: Consultar profissionais de segurança certificados"
    echo

    echo "======================================================================"
    echo "                    FIM DO RELATÓRIO CONSOLIDADO"
    echo "======================================================================"

    # Salvar relatório consolidado
    save_network_report "$network"
}

# Função para salvar relatório consolidado da rede
save_network_report() {
    local network=$1
    local filename="network_scan_report_$(date '+%Y%m%d_%H%M%S').txt"

    {
        echo "======================================================================"
        echo "           RELATÓRIO CONSOLIDADO DA REDE - $network"
        echo "======================================================================"
        echo "Data: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Scanner: Network Security Scanner (Bash) v2.0"
        echo "======================================================================"
        echo
        echo "📊 ESTATÍSTICAS GERAIS DA REDE:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "• Total de hosts verificados: $total_hosts_scanned"
        echo "• Hosts ativos encontrados: $total_hosts_alive"
        echo "• Hosts inativos: $((total_hosts_scanned - total_hosts_alive))"
        echo "• Total de vulnerabilidades encontradas: $total_vulnerabilities"
        echo "• Hosts com pelo menos 1 vulnerabilidade: $hosts_with_vulns"
        echo "• Hosts seguros (0 vulnerabilidades): $((total_hosts_alive - hosts_with_vulns))"
        echo

        if [[ -n $network_summary ]]; then
            echo "📋 DETALHES POR HOST:"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "Host/IP              | Vulnerabilidades | Status"
            echo "─────────────────────┼─────────────────┼────────"
            echo -e "$network_summary" | while IFS='|' read -r host ip vulns details; do
                if [[ -z $details ]]; then
                    status="✅ SEGURO"
                else
                    status="⚠️  VULNERÁVEL"
                fi
                printf "%-20s | %-15s | %s\n" "$host ($ip)" "$vulns" "$status"
            done
            echo

            # Seção detalhada de vulnerabilidades por host
            echo "🔍 DETALHES DE VULNERABILIDADES POR HOST:"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo -e "$network_summary" | while IFS='|' read -r host ip vulns details; do
                if [[ -n $details ]]; then
                    echo
                    echo "🏠 Host: $host ($ip) - $vulns vulnerabilidades encontradas"
                    echo "──────────────────────────────────────────────────────────────────────"
                    echo -e "$details" | while IFS='|' read -r vuln risk det; do
                        if [[ -n $vuln ]]; then
                            case $risk in
                                "CRÍTICO") icon="🔴" ;;
                                "ALTO") icon="🟠" ;;
                                "MÉDIO") icon="🟡" ;;
                                "BAIXO") icon="🟢" ;;
                                "INFO") icon="ℹ️" ;;
                                *) icon="⚪" ;;
                            esac
                            echo "  $icon $vuln"
                            echo "     Risco: $risk | Detalhes: $det"
                        fi
                    done
                fi
            done
            echo
        fi

        echo "🔍 ANÁLISE DE SEGURANÇA:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if (( total_vulnerabilities == 0 )); then
            echo "✅ EXCELENTE: Nenhum host apresentou vulnerabilidades detectadas!"
            echo "   A rede parece estar bem protegida contra as ameaças verificadas."
        elif (( total_vulnerabilities < 5 )); then
            echo "⚠️  ATENÇÃO: Poucas vulnerabilidades encontradas."
            echo "   Recomenda-se correção imediata e monitoramento contínuo."
        elif (( total_vulnerabilities < 20 )); then
            echo "🟠 ALERTA: Várias vulnerabilidades detectadas."
            echo "   Correção prioritária necessária para hosts críticos."
        else
            echo "🔴 CRÍTICO: Múltiplas vulnerabilidades encontradas!"
            echo "   Ação imediata necessária para proteger a rede."
        fi
        echo

        echo "💡 RECOMENDAÇÕES GERAIS:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "1. 🔐 AUTENTICAÇÃO E ACESSO:"
        echo "   • Implementar autenticação multifator (MFA) onde possível"
        echo "   • Usar senhas fortes e rotação periódica"
        echo "   • Desabilitar protocolos inseguros (Telnet, FTP não criptografado)"
        echo
        echo "2. 🛡️ CONFIGURAÇÃO DE REDE:"
        echo "   • Fechar portas desnecessárias no firewall"
        echo "   • Implementar segmentação de rede (VLANs)"
        echo "   • Configurar regras de acesso baseadas em necessidade"
        echo "   • Desabilitar resposta ICMP se não necessário"
        echo
        echo "3. 🔒 CRIPTOGRAFIA:"
        echo "   • Usar apenas protocolos criptografados (SSH, SFTP, HTTPS)"
        echo "   • Implementar certificados SSL/TLS válidos"
        echo "   • Evitar transmissão de dados sensíveis em texto claro"
        echo
        echo "4. 👁️ MONITORAMENTO E DETECÇÃO:"
        echo "   • Implementar sistema de detecção de intrusão (IDS/IPS)"
        echo "   • Configurar logging centralizado e alertas"
        echo "   • Realizar scans regulares de vulnerabilidades"
        echo "   • Monitorar tráfego de rede suspeito"
        echo
        echo "5. 📚 MELHORES PRÁTICAS:"
        echo "   • Manter sistemas atualizados com patches de segurança"
        echo "   • Realizar backups regulares e testá-los"
        echo "   • Treinar usuários sobre segurança da informação"
        echo "   • Desenvolver e testar plano de resposta a incidentes"
        echo
        echo "6. 🏢 GOVERNANÇA:"
        echo "   • Definir políticas de segurança claras"
        echo "   • Realizar auditorias regulares"
        echo "   • Cumprir frameworks como ISO 27001 ou NIST"
        echo "   • Documentar todas as configurações e mudanças"
        echo

        echo "📝 NOTAS PARA TRABALHO ACADÊMICO:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "• Este relatório foi gerado automaticamente pelo Network Security Scanner"
        echo "• As verificações incluem 26 tipos de vulnerabilidades em 6 categorias"
        echo "• Metodologia: Scan passivo baseado em portas abertas e serviços detectados"
        echo "• Limitações: Não detecta vulnerabilidades zero-day ou configurações internas"
        echo "• Cobertura: Foco em vulnerabilidades comuns de configuração e exposição"
        echo "• Recomendação: Complementar com ferramentas especializadas (Nessus, OpenVAS)"
        echo "• Para uso em produção: Consultar profissionais de segurança certificados"
        echo

        echo "🎯 PRIORIZAÇÃO DE CORREÇÕES:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "1. 🔴 CRÍTICO (Correção Imediata - < 24h):"
        echo "   • DNS Zone Transfer habilitado"
        echo "   • Serviços Telnet/FTP não criptografados"
        echo "   • Portas críticas expostas sem proteção"
        echo
        echo "2. 🟠 ALTO (Correção em 1-7 dias):"
        echo "   • SMB/NetBIOS expostos"
        echo "   • IPv6 não monitorado"
        echo "   • Múltiplas portas abertas desnecessárias"
        echo
        echo "3. 🟡 MÉDIO (Correção em 1-4 semanas):"
        echo "   • Porta SSH na padrão (22)"
        echo "   • Resposta ICMP habilitada"
        echo "   • Banners revelando versões"
        echo
        echo "4. 🟢 BAIXO (Correção quando possível):"
        echo "   • Informações DNS públicas"
        echo "   • Configurações não críticas"
        echo

        echo "📊 MÉTRICAS DE SUCESSO:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        local security_score=0
        if (( total_hosts_alive > 0 )); then
            security_score=$(( 100 - (total_vulnerabilities * 100) / (total_hosts_alive * 5) ))
            if (( security_score < 0 )); then security_score=0; fi
        fi
        echo "• Pontuação de Segurança Estimada: ${security_score}/100"
        echo "• Hosts Seguros: $((total_hosts_alive - hosts_with_vulns))/$total_hosts_alive"
        echo "• Média de Vulnerabilidades por Host: $(( total_vulnerabilities / (total_hosts_alive > 0 ? total_hosts_alive : 1) ))"
        echo

        echo "🔬 METODOLOGIA UTILIZADA:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "1. Descoberta de Hosts: Ping sweep na sub-rede /24"
        echo "2. Resolução DNS: Verificação de resolução de nomes"
        echo "3. Scan de Portas: Verificação de 14 portas comuns TCP"
        echo "4. Detecção de Serviços: Captura de banners e identificação"
        echo "5. Análise de Configuração: Verificação de melhores práticas"
        echo "6. Classificação de Riscos: Baseada em impacto e exploração"
        echo "7. Geração de Relatórios: Documentação estruturada e acionável"
        echo

        echo "📚 REFERÊNCIAS E FRAMEWORKS:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "• OWASP Top 10 - Principais riscos de aplicações web"
        echo "• NIST Cybersecurity Framework - Padrões de segurança"
        echo "• ISO 27001 - Sistema de gestão de segurança da informação"
        echo "• CIS Controls - Controles de segurança críticos"
        echo "• SANS Top 20 - Principais controles de segurança"
        echo

        echo "⚖️ AVISO LEGAL:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Este relatório é para fins educacionais e de pesquisa acadêmica."
        echo "Não substitui auditoria profissional de segurança."
        echo "O uso desta ferramenta requer autorização explícita."
        echo "Os autores não se responsabilizam por uso indevido."
        echo

        echo "👨‍🎓 PARA O TRABALHO DE FACULDADE:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "• Utilize este relatório como base para sua análise"
        echo "• Correlacione as vulnerabilidades encontradas com teorias estudadas"
        echo "• Desenvolva plano de ação baseado nas recomendações"
        echo "• Apresente no seminário com gráficos e métricas"
        echo "• Discuta limitações da ferramenta e melhorias possíveis"
        echo

        echo "======================================================================"
        echo "                    FIM DO RELATÓRIO CONSOLIDADO"
        echo "======================================================================"

    } > "$filename"

    echo "[+] Relatório consolidado salvo em: $filename"
}

# Função para detectar gateway padrão
get_default_gateway() {
    ip route | grep default | awk '{print $3}'
}

# Função para obter IP local
get_local_ip() {
    hostname -I | awk '{print $1}'
}

# Função principal
main() {
    echo "
    ╔════════════════════════════════════════════════════════════════╗
    ║     Network Security Scanner - Ferramenta Educacional (Bash)   ║
    ║     Propósito: Análise de Segurança Defensiva                  ║
    ╚════════════════════════════════════════════════════════════════╝
    "

    local target

    if [[ $# -lt 1 ]]; then
        echo "[*] Detectando rede automaticamente..."
        local local_ip
        local_ip=$(get_local_ip)
        local gateway
        gateway=$(get_default_gateway)

        if [[ -n $local_ip ]]; then
            echo "[+] IP Local: $local_ip"
            local base
            base=$(echo "$local_ip" | sed 's/\.[0-9]*$//')
            target="$base.0/24"
            echo "[+] Rede detectada: $target"
            echo "[*] Escaneando todos os hosts da rede (1-254) - pode levar vários minutos"
        else
            echo
            echo "[-] Não foi possível detectar o IP local."
            echo
            echo "Uso: $0 <target> ou $0 <network/mask>"
            echo
            echo "Exemplos:"
            echo "  $0 localhost"
            echo "  $0 192.168.1.1"
            echo "  $0 192.168.1.0/24  (escaneia todos os hosts 1-254 - relatório único consolidado)"
            echo "  $0 example.com"
            exit 1
        fi
    else
        target=$1
    fi

    # Aviso legal
    echo
    echo "⚠️  AVISO LEGAL:"
    echo "Este script é para fins educacionais e de segurança defensiva."
    echo "Use apenas em sistemas que você tem permissão para testar."
    echo "O uso não autorizado pode ser ilegal."
    echo

    read -p "Você tem autorização para escanear este alvo? (sim/não): " response
    if [[ ! $response =~ ^(sim|s|yes|y)$ ]]; then
        echo "Scan cancelado."
        exit 0
    fi

    # Executar scan
    if [[ $target == */* ]]; then
        # É uma rede, escanear range
        scan_range "$target"
    else
        # É um host único
        print_banner "$target"
        local ip
        ip=$(resolve_host "$target")
        if [[ -n $ip ]]; then
            check_ssh_port "$ip"
            scan_common_ports "$ip"
            check_icmp_response "$ip"
            check_dns_info "$target"
            check_dns_zone_transfer "$target"
            check_netbios_services "$ip"
            check_smb_signing "$ip"
            check_ipv6_enabled
            generate_report
            save_report "$target"
        fi
    fi
}

# Verificar dependências
check_dependencies() {
    local deps=("ping" "dig" "ip")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "⚠️  Dependências opcionais faltando: ${missing[*]}"
        echo "Algumas verificações serão puladas."
        echo "Para instalar: sudo apt install dnsutils iproute2"
    fi
}

# Executar verificação de dependências e main
check_dependencies
main "$@"