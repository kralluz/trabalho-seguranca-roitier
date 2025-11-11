#!/bin/bash

# Entrypoint para Container Vítima
# Inicializa serviços vulneráveis e logging

echo "=========================================="
echo " CONTAINER VÍTIMA - Sistema do Professor"
echo "=========================================="
echo "Hostname: $(hostname)"
echo "IP Address: $(hostname -I)"
echo "Data/Hora: $(date)"
echo "=========================================="
echo

# Iniciar rsyslog para captura de logs
/usr/sbin/rsyslogd || echo "[!] Rsyslog iniciado com avisos (normal em containers)"

# Aguardar rsyslog inicializar
sleep 1

# Resetar SSH para configuração vulnerável
sed -i 's/^PasswordAuthentication no$/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
sed -i 's/^PermitRootLogin no$/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null || true

# Iniciar auditd para auditoria de sistema
service auditd start || echo "Auditd já está rodando ou não disponível"

# Configurar auditd para monitorar comandos suspeitos
auditctl -w /etc/passwd -p wa -k passwd_changes
auditctl -w /etc/shadow -p wa -k shadow_changes
auditctl -w /home/professor -p rwa -k professor_files
auditctl -w /var/log -p wa -k log_tampering

# Iniciar SSH
echo "[*] Iniciando serviço SSH..."
/usr/sbin/sshd

# Verificar se SSH está rodando
if pgrep -x sshd > /dev/null; then
    echo "[✓] SSH iniciado com sucesso na porta 22"
else
    echo "[✗] Falha ao iniciar SSH"
fi

# Iniciar Apache
echo "[*] Iniciando Apache..."
service apache2 start

# Iniciar MySQL
echo "[*] Iniciando MySQL..."
service mysql start

# Iniciar vsftpd (FTP)
echo "[*] Iniciando FTP..."
service vsftpd start 2>/dev/null || echo "[!] FTP não iniciado (opcional)"

echo
echo "=========================================="
echo " SERVIÇOS ATIVOS:"
echo "=========================================="
echo "[*] SSH:   Porta 22 (senha: senha123)"
echo "[*] HTTP:  Porta 80"
echo "[*] MySQL: Porta 3306 (admin/admin)"
echo "[*] FTP:   Porta 21"
echo "=========================================="
echo
echo "[!] SISTEMA INTENCIONALMENTE VULNERÁVEL"
echo "[!] USO EXCLUSIVAMENTE EDUCACIONAL"
echo "=========================================="
echo
echo "[*] Logs sendo salvos em /var/log/"
echo "[*] Para visualizar logs SSH: tail -f /var/log/auth.log"
echo

# Criar arquivo de histórico para o professor (simulação de uso normal)
cat > /home/professor/.bash_history <<EOF
ls -la
cd Documentos/
ls
cat notas_alunos.csv
nano prova_final.txt
pwd
whoami
exit
EOF

chown professor:professor /home/professor/.bash_history

# Manter container ativo e monitorar logs
echo "[*] Container ativo. Monitorando atividades..."
echo

# Executar comando passado ou manter rodando
exec "$@"
