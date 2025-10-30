# RELATÓRIO DE AUDITORIA E ANÁLISE FORENSE
## Incidente de Acesso Não Autorizado via SSH - Laboratório de Informática

---

**Instituição:** Universidade [Nome da Instituição]
**Curso:** Bacharelado em Sistemas de Informação
**Disciplina:** Segurança da Informação (6º Período)
**Data do Incidente:** [Data Simulada]
**Data do Relatório:** Novembro de 2025
**Equipe de Auditoria:** [Nomes da Dupla]
**Classificação:** CONFIDENCIAL

---

## SUMÁRIO EXECUTIVO

### Contexto do Incidente
Em [data], foi identificado um acesso não autorizado ao computador de um professor no laboratório de informática da universidade. A investigação preliminar revelou que um aluno, por meio de engenharia social (observação visual da digitação da senha) e subsequente acesso remoto via protocolo SSH, conseguiu manipular recursos institucionais no sistema da vítima.

### Gravidade e Impacto
- **Nível de Severidade:** CRÍTICO
- **Confidencialidade:** Comprometida
- **Integridade:** Comprometida
- **Disponibilidade:** Parcialmente Comprometida
- **Impacto Institucional:** Alto (reputação, confiança, custos)
- **Impacto Pessoal:** Alto (privacidade do professor violada)

### Principais Descobertas
1. Autenticação SSH baseada exclusivamente em senha fraca
2. Ausência de autenticação multifator (MFA)
3. Falta de políticas de segurança física adequadas
4. Ausência de monitoramento proativo de acessos SSH
5. Configurações padrão inseguras do servidor SSH
6. **+ 5 vulnerabilidades adicionais identificadas nesta auditoria**

---

## 1. ANÁLISE DE VULNERABILIDADES E VETORES DE ATAQUE

### 1.1 Vulnerabilidade Principal: Acesso SSH Não Autorizado

#### 1.1.1 Descrição Técnica
O protocolo SSH (Secure Shell) é amplamente utilizado para administração remota segura de sistemas Unix/Linux. No entanto, sua segurança depende fundamentalmente de:
- Autenticação forte (chaves criptográficas ou senhas robustas)
- Configuração adequada do servidor (hardening)
- Políticas de acesso restritivas

**No caso investigado, as seguintes falhas foram identificadas:**

| Falha | Descrição | Severidade |
|-------|-----------|------------|
| Senha fraca | Senha com menos de 8 caracteres, sem complexidade | CRÍTICA |
| Shoulder surfing | Observação visual durante digitação | ALTA |
| SSH com autenticação por senha habilitada | Configuração padrão permitindo login sem chave | ALTA |
| Ausência de fail2ban/rate limiting | Sem proteção contra tentativas repetidas | MÉDIA |
| Root login via SSH habilitado | Acesso administrativo direto possível | CRÍTICA |
| Ausência de 2FA | Apenas um fator de autenticação | ALTA |

#### 1.1.2 Vetor de Ataque Utilizado

```
┌─────────────────────────────────────────────────────────────┐
│                   CADEIA DE ATAQUE                          │
└─────────────────────────────────────────────────────────────┘

1. RECONHECIMENTO
   └─> Aluno identifica professor utilizando computador no lab

2. ENGENHARIA SOCIAL (Shoulder Surfing)
   └─> Observação visual da senha durante digitação
   └─> Memorização da credencial

3. ENUMERAÇÃO
   └─> Descoberta do endereço IP da máquina vítima
   └─> Identificação de serviço SSH aberto (porta 22)

4. ACESSO INICIAL
   └─> Login SSH com credenciais roubadas
   └─> ssh professor@192.168.24.X

5. PERSISTÊNCIA E IMPACTO
   └─> Manipulação de recursos institucionais
   └─> Possível exfiltração de dados
   └─> Comprometimento da integridade do sistema
```

#### 1.1.3 Linha do Tempo do Ataque (Estimada)

```
T+0min:  Aluno observa professor digitando senha no laboratório
T+5min:  Professor sai do laboratório (mantém sessão ativa)
T+10min: Aluno descobre IP da máquina (arp-scan, nmap, ou consulta ao DHCP)
T+12min: Aluno realiza tentativa de conexão SSH
T+13min: Acesso bem-sucedido ao sistema
T+15min: Navegação no sistema de arquivos
T+20min: Manipulação de recursos institucionais
T+25min: Logout e saída sem deixar rastros óbvios
```

---

### 1.2 Vulnerabilidades Adicionais Identificadas

Além do cenário principal de acesso SSH não autorizado, a auditoria de segurança identificou **5 vulnerabilidades críticas adicionais** no ambiente do laboratório:

---

#### **VULNERABILIDADE #2: Ausência de Segmentação de Rede**

**Descrição:**
O laboratório de informática opera em uma rede flat (plana), sem segmentação ou VLANs. Todos os computadores (alunos, professores, servidores) estão na mesma sub-rede, permitindo comunicação direta entre quaisquer máquinas.

**Impacto:**
- Movimentação lateral facilitada após comprometimento inicial
- Possibilidade de ataques ARP spoofing/poisoning
- Falta de isolamento entre ambientes críticos e não-críticos

**Severidade:** ALTA

**CVE Relacionada:** CWE-923 (Improper Restriction of Communication Channel to Intended Endpoints)

**Exploração:**
```bash
# Descoberta de todos os hosts na rede sem restrições
nmap -sn 192.168.24.0/24

# Varredura de serviços em todos os hosts
nmap -sV -p- 192.168.24.0/24
```

**Mitigação:**
- Implementar VLANs separadas (Alunos, Professores, Servidores)
- Configurar ACLs entre VLANs
- Implementar microsegmentação com firewall de próxima geração

---

#### **VULNERABILIDADE #3: Serviços Desnecessários Expostos**

**Descrição:**
Durante o scan de portas, foram identificados múltiplos serviços rodando e expostos sem necessidade:

| Serviço | Porta | Risco |
|---------|-------|-------|
| Telnet | 23 | Texto claro, sem criptografia |
| FTP | 21 | Credenciais em texto claro |
| VNC | 5900 | Controle remoto sem autenticação forte |
| MySQL | 3306 | Banco de dados acessível remotamente |
| SMB | 445 | Compartilhamento de arquivos vulnerável |

**Impacto:**
- Aumento da superfície de ataque
- Protocolos sem criptografia expõem credenciais
- Possibilidade de exploits conhecidos (EternalBlue no SMB)

**Severidade:** CRÍTICA

**CVE Relacionadas:**
- CVE-2017-0144 (EternalBlue - SMB)
- CWE-319 (Cleartext Transmission of Sensitive Information)

**Exploração:**
```bash
# Ataque de força bruta no FTP
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://192.168.24.X

# Captura de credenciais Telnet com Wireshark
tcpdump -i eth0 -A port 23
```

**Mitigação:**
- Desabilitar todos os serviços não essenciais
- Substituir Telnet por SSH, FTP por SFTP
- Implementar firewall bloqueando portas desnecessárias
- Usar VNC apenas com VPN ou tunnel SSH

---

#### **VULNERABILIDADE #4: Senhas Padrão e Contas Compartilhadas**

**Descrição:**
Múltiplas contas de usuário no laboratório utilizam senhas fracas ou padrões:
- Conta "aluno" com senha "aluno123"
- Conta "admin" com senha "admin"
- Conta "professor" com senha baseada no CPF
- Ausência de política de expiração de senhas

**Impacto:**
- Comprometimento em massa de contas
- Dificuldade de rastreabilidade (contas compartilhadas)
- Ausência de accountability

**Severidade:** CRÍTICA

**CWE Relacionada:** CWE-521 (Weak Password Requirements)

**Exploração:**
```bash
# Brute-force SSH com wordlist de senhas comuns
hydra -l professor -P senhas_comuns.txt ssh://192.168.24.X

# Password spraying (mesma senha em múltiplos usuários)
crackmapexec ssh 192.168.24.0/24 -u usuarios.txt -p 'aluno123'
```

**Evidência de Teste:**
```
[REDACTED] - Testes realizados identificaram 15 contas com senhas
em wordlists comuns (rockyou.txt) em menos de 5 minutos.
```

**Mitigação:**
- Implementar política de senhas forte (mínimo 12 caracteres, complexidade)
- Forçar troca de senha no primeiro login
- Implementar expiração periódica (90 dias)
- Banir senhas comuns (dicionário de senhas fracas)
- Implementar contas individuais (fim de contas compartilhadas)

---

#### **VULNERABILIDADE #5: Falta de Monitoramento e Auditoria**

**Descrição:**
O ambiente não possui sistema de monitoramento adequado:
- Logs de SSH não são centralizados
- Ausência de SIEM (Security Information and Event Management)
- Logs locais podem ser modificados/deletados pelo atacante
- Sem alertas em tempo real para atividades suspeitas

**Impacto:**
- Ataques não detectados em tempo real
- Impossibilidade de resposta rápida a incidentes
- Dificuldade de análise forense post-mortem
- Violação de compliance (LGPD, ISO 27001)

**Severidade:** ALTA

**CWE Relacionada:** CWE-778 (Insufficient Logging)

**Exploração pelo Atacante:**
```bash
# Atacante pode limpar rastros facilmente
history -c  # Limpa histórico de comandos
rm ~/.bash_history  # Remove arquivo de histórico

# Modificar logs locais (se tiver privilégio)
echo "" > /var/log/auth.log
```

**Mitigação:**
- Implementar syslog centralizado (rsyslog para servidor remoto)
- Configurar auditd para monitoramento de chamadas de sistema
- Implementar SIEM (Wazuh, Splunk, ELK Stack)
- Configurar alertas para:
  - Múltiplas tentativas de login falhadas
  - Logins fora do horário normal
  - Comandos suspeitos (su, sudo, ssh)

---

#### **VULNERABILIDADE #6: Privilégios Excessivos e Sudo sem Senha**

**Descrição:**
Análise da configuração de sudo revelou:
- Usuários comuns com permissão de sudo sem requisição de senha
- Configuração `/etc/sudoers` com wildcard excessivo
- Usuários no grupo `sudo` sem necessidade

**Exemplo de Configuração Vulnerável:**
```bash
# /etc/sudoers
aluno ALL=(ALL) NOPASSWD: ALL
professor ALL=(ALL) NOPASSWD: /bin/bash
```

**Impacto:**
- Escalação de privilégios trivial
- Qualquer usuário comprometido = root comprometido
- Violação do princípio do menor privilégio

**Severidade:** CRÍTICA

**CWE Relacionada:** CWE-250 (Execution with Unnecessary Privileges)

**Exploração:**
```bash
# Após comprometer conta "aluno"
sudo su -  # Obtém shell root sem senha
id  # Confirma: uid=0(root)
```

**Mitigação:**
- Remover NOPASSWD de configurações sudo
- Implementar sudo apenas para comandos específicos necessários
- Auditar regularmente membros do grupo sudo
- Implementar logging de comandos sudo
- Usar PAM para controle de autenticação adicional

---

#### **VULNERABILIDADE #7: Ausência de Hardening de Sistema Operacional**

**Descrição:**
Os sistemas do laboratório utilizam configurações padrão do Ubuntu/Debian sem aplicação de benchmarks de segurança:
- Serviços desnecessários habilitados por padrão
- Kernel sem patches de segurança atualizados
- Ausência de AppArmor/SELinux configurado
- Firewall (ufw) desabilitado

**Impacto:**
- Sistema vulnerável a exploits públicos conhecidos
- Ausência de defesa em profundidade
- Maior superfície de ataque

**Severidade:** ALTA

**CWE Relacionada:** CWE-1188 (Insecure Default Initialization of Resource)

**Verificação:**
```bash
# Verificar serviços ativos
systemctl list-units --type=service --state=running

# Verificar kernel desatualizado
uname -r
apt list --upgradable | grep linux-image

# Verificar firewall
sudo ufw status  # Output: Status: inactive
```

**Mitigação:**
- Aplicar CIS Benchmark para Ubuntu/Debian
- Habilitar e configurar AppArmor/SELinux
- Implementar firewall host-based (ufw) com regras restritivas
- Aplicar patches de segurança automaticamente
- Desabilitar serviços não essenciais
- Implementar kernel hardening (sysctl.conf)

---

### 1.3 Mapeamento Completo de Vulnerabilidades

| ID | Vulnerabilidade | Severidade | Exploração | Mitigação |
|----|----------------|------------|------------|-----------|
| V1 | Acesso SSH não autorizado (cenário) | CRÍTICA | Engenharia social + senha fraca | MFA, chaves SSH, fail2ban |
| V2 | Ausência de segmentação de rede | ALTA | Movimentação lateral | VLANs, firewall |
| V3 | Serviços desnecessários expostos | CRÍTICA | Exploits, força bruta | Desabilitar, firewall |
| V4 | Senhas padrão e contas compartilhadas | CRÍTICA | Brute-force, password spray | Política de senhas |
| V5 | Falta de monitoramento e auditoria | ALTA | Ataques silenciosos | SIEM, logs centralizados |
| V6 | Privilégios excessivos (sudo) | CRÍTICA | Escalação de privilégios | Remover NOPASSWD, auditoria |
| V7 | Ausência de hardening de SO | ALTA | Exploits conhecidos | CIS Benchmark, patches |

---

## 2. ANÁLISE FORENSE DIGITAL E RESPOSTA A INCIDENTES

### 2.1 Metodologia de Investigação Forense

A análise forense seguiu os padrões da **RFC 3227** (Guidelines for Evidence Collection and Archiving) e **NIST SP 800-86** (Guide to Integrating Forensic Techniques into Incident Response).

#### 2.1.1 Princípios Fundamentais

1. **Ordem de Volatilidade:** Coleta de evidências da mais volátil para a menos volátil
2. **Cadeia de Custódia:** Documentação rigorosa de cada etapa
3. **Integridade:** Uso de hashes criptográficos (SHA-256) para validação
4. **Não Contaminação:** Uso de ferramentas forenses que não alteram evidências

#### 2.1.2 Ordem de Coleta de Evidências

```
NÍVEL 1 - EVIDÊNCIAS VOLÁTEIS (Memória RAM)
├── Processos em execução
├── Conexões de rede ativas
├── Usuários logados
├── Conteúdo de memória
└── Cache de sistema

NÍVEL 2 - EVIDÊNCIAS SEMI-VOLÁTEIS
├── Logs de sistema (/var/log/)
├── Histórico de comandos (~/.bash_history)
├── Conexões SSH recentes
└── Processos agendados (cron)

NÍVEL 3 - EVIDÊNCIAS PERSISTENTES
├── Imagem forense do disco
├── Arquivos de configuração
├── Arquivos de usuário
└── Timestamps (atime, mtime, ctime)
```

---

### 2.2 Cadeia de Custódia

#### 2.2.1 Formulário de Cadeia de Custódia

```
┌──────────────────────────────────────────────────────────────┐
│           FORMULÁRIO DE CADEIA DE CUSTÓDIA                   │
├──────────────────────────────────────────────────────────────┤
│ Evidência ID: EVD-2025-001                                   │
│ Tipo: Imagem Forense de Disco                                │
│ Descrição: DD image do disco /dev/sda (máquina vítima)       │
│ Tamanho: 250GB                                               │
│ Hash SHA-256: a3f5b8c9d2e1f7a4b6c8d9e0f1a2b3c4d5e6f7a8b9... │
│                                                              │
│ HISTÓRICO DE CUSTÓDIA:                                       │
│ ┌────────────────────────────────────────────────────────┐  │
│ │ Data/Hora: 2025-XX-XX 14:30:00                         │  │
│ │ Coletado por: [Investigador 1]                         │  │
│ │ Método: dd if=/dev/sda of=evidence.img bs=4M           │  │
│ │ Local: Laboratório de Informática - Sala 102          │  │
│ │ Assinatura: ___________________________               │  │
│ └────────────────────────────────────────────────────────┘  │
│ ┌────────────────────────────────────────────────────────┐  │
│ │ Data/Hora: 2025-XX-XX 15:45:00                         │  │
│ │ Transferido para: [Investigador 2]                     │  │
│ │ Propósito: Análise forense                            │  │
│ │ Verificação Hash: CONFIRMADO                           │  │
│ │ Assinatura: ___________________________               │  │
│ └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

#### 2.2.2 Comandos para Preservação de Evidências

```bash
# 1. COLETA DE MEMÓRIA RAM (se possível antes de desligar)
sudo dd if=/dev/mem of=/mnt/usb/memory.dump bs=1M

# 2. COLETA DE EVIDÊNCIAS VOLÁTEIS
# Processos em execução
ps auxf > /evidence/processes.txt

# Conexões de rede
netstat -antp > /evidence/network_connections.txt
ss -tunap > /evidence/sockets.txt

# Usuários logados
w > /evidence/logged_users.txt
last -f /var/log/wtmp > /evidence/login_history.txt

# 3. CRIAÇÃO DE IMAGEM FORENSE DO DISCO
sudo dd if=/dev/sda of=/mnt/evidence/disk_image.img bs=4M status=progress conv=noerror,sync

# 4. CÁLCULO DE HASH PARA INTEGRIDADE
sha256sum /mnt/evidence/disk_image.img > /mnt/evidence/disk_image.img.sha256

# 5. COLETA DE LOGS (antes que sejam rotacionados)
tar -czf /evidence/logs_$(date +%Y%m%d_%H%M%S).tar.gz /var/log/

# 6. HISTÓRICO DE COMANDOS DE TODOS OS USUÁRIOS
for user_home in /home/*; do
    cp "$user_home/.bash_history" "/evidence/bash_history_$(basename $user_home).txt"
done
```

---

### 2.3 Análise de Logs

#### 2.3.1 Logs Críticos para Investigação

| Log | Localização | Informações Relevantes |
|-----|-------------|------------------------|
| SSH Auth | `/var/log/auth.log` | Tentativas de login, IPs de origem, horários |
| Syslog | `/var/log/syslog` | Eventos gerais do sistema |
| Histórico Bash | `~/.bash_history` | Comandos executados pelo atacante |
| wtmp | `/var/log/wtmp` | Histórico de logins (binário) |
| lastlog | `/var/log/lastlog` | Último login de cada usuário |
| Apache/Nginx | `/var/log/apache2/` ou `/var/log/nginx/` | Acessos web (se aplicável) |

#### 2.3.2 Análise do Log de Autenticação SSH

**Comando de Análise:**
```bash
# Filtrar tentativas de login SSH
sudo grep "sshd" /var/log/auth.log

# Extrair IPs de origem
sudo grep "Accepted password" /var/log/auth.log | awk '{print $1, $2, $3, $11, $9}'

# Contar tentativas falhadas por IP
sudo grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr
```

**Exemplo de Log Suspeito:**
```
Nov 15 14:12:34 lab-pc-05 sshd[2341]: Accepted password for professor from 192.168.24.87 port 52341 ssh2
Nov 15 14:12:35 lab-pc-05 sshd[2341]: pam_unix(sshd:session): session opened for user professor by (uid=0)
Nov 15 14:15:22 lab-pc-05 sshd[2341]: Received disconnect from 192.168.24.87 port 52341:11: disconnected by user
```

**Análise:**
- IP de origem: **192.168.24.87** (máquina do laboratório)
- Horário: **14:12:34** (fora do horário normal do professor)
- Duração da sessão: **~3 minutos**
- **ALERTA:** Login bem-sucedido de IP interno, mas em horário suspeito

#### 2.3.3 Análise de Comandos Executados

```bash
# Análise do histórico de comandos do usuário comprometido
cat /home/professor/.bash_history
```

**Exemplo de Histórico Suspeito:**
```bash
# [EVIDÊNCIA] Comandos suspeitos encontrados:
whoami
id
pwd
ls -la /home/professor/Documentos
cat /home/professor/Documentos/notas_alunos.xlsx
cp /home/professor/Documentos/provas/* /tmp/
ssh-keygen -t rsa -b 4096  # Tentativa de persistência?
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
history -c  # TENTATIVA DE APAGAR RASTROS
```

**Indicadores de Comprometimento (IoCs):**
1. Comandos de reconhecimento (`whoami`, `id`)
2. Acesso a arquivos sensíveis (notas, provas)
3. Cópia de arquivos para `/tmp/`
4. Tentativa de criar backdoor SSH (authorized_keys)
5. **Comando `history -c`** - clara tentativa de ocultar atividade

---

### 2.4 Linha do Tempo Forense (Timeline)

```
┌─────────────────────────────────────────────────────────────────┐
│                      LINHA DO TEMPO DO INCIDENTE                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ T-30min: 13:42:00 - Professor faz login no laboratório         │
│          Fonte: /var/log/wtmp                                   │
│          Evidência: Login físico registrado                     │
│                                                                 │
│ T-5min:  14:07:00 - Professor digita senha (aluno observa)     │
│          Fonte: Testemunha/Câmeras (se disponíveis)            │
│          Evidência: Engenharia social                           │
│                                                                 │
│ T0:      14:12:34 - Conexão SSH de 192.168.24.87               │
│          Fonte: /var/log/auth.log                               │
│          Evidência: "Accepted password for professor"           │
│          ⚠️  INÍCIO DO ACESSO NÃO AUTORIZADO                    │
│                                                                 │
│ T+1min:  14:13:15 - Comandos de reconhecimento executados      │
│          Fonte: .bash_history                                   │
│          Evidência: "whoami", "id", "pwd"                       │
│                                                                 │
│ T+2min:  14:14:22 - Acesso a arquivos sensíveis                │
│          Fonte: .bash_history, auditd logs                      │
│          Evidência: "cat notas_alunos.xlsx"                     │
│                                                                 │
│ T+3min:  14:15:10 - Tentativa de persistência                  │
│          Fonte: .bash_history                                   │
│          Evidência: Modificação de authorized_keys              │
│                                                                 │
│ T+3min:  14:15:18 - Tentativa de apagar rastros                │
│          Fonte: .bash_history (ironia: ficou registrado)        │
│          Evidência: "history -c"                                │
│                                                                 │
│ T+3min:  14:15:22 - Desconexão SSH                             │
│          Fonte: /var/log/auth.log                               │
│          Evidência: "Received disconnect from 192.168.24.87"    │
│          ⚠️  FIM DO ACESSO NÃO AUTORIZADO                       │
│                                                                 │
│ T+2h:    16:30:00 - Professor detecta alterações               │
│          Fonte: Relato da vítima                                │
│          Evidência: Arquivos modificados, timestamps alterados  │
│                                                                 │
│ T+2.5h:  17:00:00 - Incidente reportado ao TI                  │
│          Fonte: Ticket de suporte #12345                        │
│          Evidência: E-mail de notificação                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

### 2.5 Ferramentas Forenses Utilizadas

```bash
# 1. AUTOPSY (Interface gráfica para análise forense)
autopsy

# 2. SLEUTHKIT (Análise de sistemas de arquivos)
fls -r disk_image.img > file_listing.txt
icat disk_image.img 12345 > recovered_file.txt

# 3. VOLATILITY (Análise de memória)
volatility -f memory.dump --profile=LinuxUbuntu2204x64 linux_bash
volatility -f memory.dump --profile=LinuxUbuntu2204x64 linux_psaux

# 4. EXTRAÇÃO DE TIMESTAMPS (MAC times)
stat /home/professor/Documentos/notas_alunos.xlsx

# 5. ANÁLISE DE LOGS COM AUDITD
ausearch -ts today -k suspicious_commands
ausearch -ua professor
```

---

## 3. ANÁLISE DE RISCOS E IMPACTOS

### 3.1 Metodologia de Análise de Riscos

Utilizamos a metodologia **NIST SP 800-30** (Guide for Conducting Risk Assessments) combinada com a matriz de risco baseada em **probabilidade vs. impacto**.

#### Fórmula de Cálculo de Risco:
```
Risco = Probabilidade × Impacto × Vulnerabilidade × Ameaça
```

#### Matriz de Classificação:

| Probabilidade | Valor | Impacto | Valor |
|---------------|-------|---------|-------|
| Muito Baixa | 1 | Insignificante | 1 |
| Baixa | 2 | Menor | 2 |
| Média | 3 | Moderado | 3 |
| Alta | 4 | Maior | 4 |
| Muito Alta | 5 | Catastrófico | 5 |

---

### 3.2 Impacto Institucional (Universidade)

#### 3.2.1 Dimensões de Impacto

| Dimensão | Impacto | Severidade | Descrição |
|----------|---------|------------|-----------|
| **Reputacional** | ALTO | 4/5 | Dano à imagem da instituição perante alunos, professores e comunidade |
| **Financeiro** | MÉDIO | 3/5 | Custos de investigação, remediação, possíveis processos judiciais |
| **Operacional** | MÉDIO | 3/5 | Interrupção de aulas, necessidade de revisão de sistemas |
| **Legal/Regulatório** | ALTO | 4/5 | Violação da LGPD, responsabilização civil e criminal |
| **Confiança** | ALTO | 4/5 | Perda de confiança na segurança dos sistemas institucionais |
| **Acadêmico** | ALTO | 4/5 | Comprometimento da integridade acadêmica (notas, provas) |

#### 3.2.2 Custos Estimados

```
CUSTOS DIRETOS:
├── Investigação forense externa................ R$ 15.000,00
├── Atualização de infraestrutura de TI......... R$ 80.000,00
├── Consultoria em segurança.................... R$ 25.000,00
├── Treinamentos obrigatórios................... R$ 10.000,00
├── Honorários advocatícios..................... R$ 20.000,00
└── SUBTOTAL................................... R$ 150.000,00

CUSTOS INDIRETOS:
├── Perda de produtividade (horas de trabalho).. R$ 30.000,00
├── Possível redução de matrículas.............. R$ 100.000,00
├── Custos de comunicação de crise.............. R$ 15.000,00
└── SUBTOTAL................................... R$ 145.000,00

TOTAL ESTIMADO:................................. R$ 295.000,00
```

#### 3.2.3 Impacto Reputacional

**Análise SWOT Pós-Incidente:**

```
FORÇAS (Strengths):
✓ Resposta rápida à descoberta
✓ Transparência na comunicação
✓ Compromisso com melhorias

FRAQUEZAS (Weaknesses):
✗ Sistemas desatualizados expostos publicamente
✗ Falta de políticas claras de segurança
✗ Cultura de segurança deficiente

OPORTUNIDADES (Opportunities):
✓ Modernização completa da infraestrutura
✓ Implementação de programa robusto de segurança
✓ Tornar-se referência em segurança educacional

AMEAÇAS (Threats):
✗ Notícias negativas na mídia
✗ Perda de credibilidade acadêmica
✗ Processos judiciais de professores/alunos afetados
✗ Redução de captação de novos alunos
```

#### 3.2.4 Impacto Legal e Compliance

**Violações Identificadas:**

1. **Lei Geral de Proteção de Dados (LGPD - Lei 13.709/2018)**
   - Artigo 46: Falha em adotar medidas de segurança técnicas adequadas
   - Artigo 48: Obrigação de notificação de incidente à ANPD
   - Sanções Possíveis:
     - Multa de até 2% do faturamento (limitado a R$ 50 milhões)
     - Suspensão de banco de dados
     - Proibição de tratamento de dados

2. **Código Penal Brasileiro**
   - Artigo 154-A: Invasão de dispositivo informático
   - Pena: Reclusão de 3 meses a 1 ano + multa

3. **Marco Civil da Internet (Lei 12.965/2014)**
   - Artigo 10: Responsabilidade pela guarda de logs

**Ações Legais Necessárias:**
```
☐ Notificação à ANPD em até 2 dias úteis
☐ Notificação aos titulares de dados afetados
☐ Boletim de Ocorrência (polícia civil)
☐ Relatório de impacto à privacidade (RIPD)
☐ Documentação completa do incidente
```

---

### 3.3 Impacto Humano (Professor - Vítima)

#### 3.3.1 Dimensões do Impacto Pessoal

| Aspecto | Severidade | Descrição |
|---------|------------|-----------|
| **Privacidade** | CRÍTICO | Violação total da privacidade digital e profissional |
| **Psicológico** | ALTO | Sensação de vulnerabilidade, violação de confiança |
| **Profissional** | MÉDIO | Possível questionamento de competência técnica |
| **Confiança** | ALTO | Perda de confiança em sistemas e colegas |
| **Reputacional** | MÉDIO | Se informações sensíveis forem expostas publicamente |

#### 3.3.2 Consequências Psicológicas

**Sintomas Possíveis (baseados em literatura de cibersegurança):**
- Ansiedade relacionada ao uso de tecnologia
- Síndrome de vigilância constante (hipervigilância)
- Perda de confiança em ambientes compartilhados
- Estresse pós-traumático relacionado à violação de privacidade
- Receio de exposição pública de informações privadas

**Recomendações de Suporte:**
```
1. Suporte psicológico institucional imediato
2. Assistência jurídica para eventuais consequências
3. Garantia de confidencialidade do incidente
4. Revisão de procedimentos para restaurar sensação de segurança
5. Treinamento personalizado em segurança digital
```

#### 3.3.3 Impacto Profissional

**Preocupações da Vítima:**
- Exposição de notas de alunos (integridade acadêmica)
- Possível acesso a comunicações privadas (e-mails)
- Comprometimento de pesquisas acadêmicas
- Questionamento por parte da instituição
- Estigma de ter sido vítima de ataque

**Direitos da Vítima:**
```
✓ Direito à proteção de dados pessoais (LGPD)
✓ Direito à reparação por danos morais
✓ Direito à assistência institucional
✓ Direito à notificação transparente das ações tomadas
✓ Direito à segurança reforçada no ambiente de trabalho
```

---

### 3.4 Matriz de Risco Consolidada

| ID | Vulnerabilidade | Probabilidade | Impacto | Risco Total | Prioridade |
|----|----------------|---------------|---------|-------------|------------|
| V1 | Acesso SSH não autorizado | 5 (Muito Alta) | 5 (Catastrófico) | 25 | CRÍTICA |
| V2 | Ausência de segmentação | 4 (Alta) | 4 (Maior) | 16 | ALTA |
| V3 | Serviços desnecessários | 5 (Muito Alta) | 4 (Maior) | 20 | CRÍTICA |
| V4 | Senhas fracas/compartilhadas | 5 (Muito Alta) | 5 (Catastrófico) | 25 | CRÍTICA |
| V5 | Falta de monitoramento | 4 (Alta) | 4 (Maior) | 16 | ALTA |
| V6 | Privilégios excessivos | 4 (Alta) | 5 (Catastrófico) | 20 | CRÍTICA |
| V7 | Ausência de hardening | 4 (Alta) | 4 (Maior) | 16 | ALTA |

**Escala de Prioridade:**
- **CRÍTICA (20-25):** Ação imediata (< 24 horas)
- **ALTA (15-19):** Ação urgente (< 7 dias)
- **MÉDIA (10-14):** Ação necessária (< 30 dias)
- **BAIXA (5-9):** Ação recomendada (< 90 dias)

---

## 4. RECOMENDAÇÕES E PLANO DE AÇÃO

### 4.1 Estratégia de Remediação Imediata (< 24h)

```
FASE 1: CONTENÇÃO
├── [✓] Desabilitar conta comprometida temporariamente
├── [✓] Forçar troca de senha de todos os usuários do laboratório
├── [✓] Revogar todas as chaves SSH autorizadas suspeitas
├── [✓] Isolar máquinas comprometidas da rede
└── [✓] Ativar logging intensivo em todos os sistemas

FASE 2: ERRADICAÇÃO
├── [ ] Remover backdoors e mecanismos de persistência
├── [ ] Aplicar patches de segurança emergenciais
├── [ ] Reconfigurar SSH com parâmetros seguros
├── [ ] Desabilitar serviços desnecessários
└── [ ] Implementar firewall temporário restritivo

FASE 3: RECUPERAÇÃO
├── [ ] Restaurar sistemas a partir de backups limpos (se necessário)
├── [ ] Reabilitar contas com senhas fortes e MFA
├── [ ] Validar integridade de arquivos críticos
└── [ ] Monitoramento intensivo por 72 horas
```

### 4.2 Roadmap de Longo Prazo (90 dias)

```
MÊS 1 - ESTABILIZAÇÃO
├── Semana 1-2: Hardening completo de todos os sistemas
├── Semana 2-3: Implementação de MFA em todos os acessos
├── Semana 3-4: Deploy de solução SIEM centralizada
└── Semana 4: Treinamento emergencial de professores

MÊS 2 - FORTALECIMENTO
├── Semana 5-6: Segmentação de rede (VLANs)
├── Semana 6-7: Implementação de IDS/IPS
├── Semana 7-8: Auditoria externa de segurança
└── Semana 8: Desenvolvimento de políticas de segurança

MÊS 3 - MATURIDADE
├── Semana 9-10: Programa completo de treinamento
├── Semana 10-11: Testes de penetração (pentest)
├── Semana 11-12: Certificação ISO 27001 (início)
└── Semana 12: Revisão e melhoria contínua
```

---

## 5. CONCLUSÃO

### 5.1 Resumo dos Achados

O incidente de acesso não autorizado via SSH no laboratório de informática expôs **múltiplas camadas de vulnerabilidades** que, combinadas, permitiram a violação bem-sucedida de um sistema institucional. A análise forense revelou que:

1. **Falha técnica:** Configurações inseguras e ausência de controles adequados
2. **Falha humana:** Senhas fracas e falta de conscientização
3. **Falha organizacional:** Ausência de políticas, monitoramento e governança

### 5.2 Lições Aprendidas

✓ **Segurança é uma cadeia:** Um único elo fraco compromete todo o sistema
✓ **Defesa em profundidade:** Múltiplas camadas de segurança são essenciais
✓ **Monitoramento é crítico:** Detecção precoce limita danos
✓ **Treinamento é fundamental:** Tecnologia sem conscientização é inútil
✓ **Compliance não é opcional:** LGPD e regulamentações devem ser seguidas

### 5.3 Próximos Passos

```
IMEDIATO (0-7 dias):
☐ Implementar todas as mitigações críticas
☐ Notificar autoridades competentes (ANPD, polícia)
☐ Comunicar transparentemente com comunidade acadêmica
☐ Iniciar suporte à vítima

CURTO PRAZO (7-30 dias):
☐ Executar Fase 1 do roadmap (Estabilização)
☐ Realizar treinamento emergencial
☐ Contratar auditoria externa
☐ Desenvolver políticas formais

MÉDIO PRAZO (30-90 dias):
☐ Completar roadmap de 90 dias
☐ Obter certificação de segurança
☐ Implementar programa de melhoria contínua
☐ Reavaliar cultura de segurança institucional
```

---

## 6. ANEXOS

### ANEXO A - Glossário Técnico
### ANEXO B - Referências Normativas
### ANEXO C - Evidências Forenses (CONFIDENCIAL)
### ANEXO D - Scripts de Hardening
### ANEXO E - Políticas de Segurança Propostas

---

**FIM DO RELATÓRIO**

---

**Classificação:** CONFIDENCIAL
**Distribuição:** Restrita (Diretoria de TI, Jurídico, Auditoria Interna)
**Data de Validade:** Este relatório é válido até implementação completa das recomendações
**Contato:** [email da equipe de segurança]

---

*Este documento foi elaborado seguindo os padrões ISO/IEC 27035 (Incident Management) e NIST SP 800-61 (Computer Security Incident Handling Guide).*
