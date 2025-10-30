# 🛡️ Trabalho Final - Segurança da Informação
## Análise e Mitigação de Vulnerabilidades em Ambientes de Rede

**Disciplina:** Segurança da Informação
**Curso:** Bacharelado em Sistemas de Informação (6º Período)
**Data de Entrega:** 03/11/2025

---

## 📋 Índice

- [Sobre o Projeto](#sobre-o-projeto)
- [Estrutura do Repositório](#estrutura-do-repositório)
- [Cenário do Trabalho](#cenário-do-trabalho)
- [Vulnerabilidades Identificadas](#vulnerabilidades-identificadas)
- [Como Executar](#como-executar)
- [Demonstração Prática](#demonstração-prática)
- [Documentação](#documentação)
- [Equipe](#equipe)

---

## 🎯 Sobre o Projeto

Este trabalho apresenta uma análise completa de um **incidente de segurança real**: um aluno obteve acesso não autorizado ao computador de um professor via SSH, explorando vulnerabilidades de autenticação e engenharia social.

### Objetivos:
1. **Análise Forense:** Investigar o incidente e identificar vetores de ataque
2. **Identificação de Vulnerabilidades:** Mapear 6 vulnerabilidades críticas (cenário + 5 adicionais)
3. **Demonstração Prática:** Simular ataques em ambiente controlado (containers Docker)
4. **Hardening:** Implementar mitigações para todas as vulnerabilidades
5. **Governança:** Propor políticas e treinamentos institucionais

---

## 📁 Estrutura do Repositório

```
trabalho_seguranca_roitier/
├── README.md                          # Este arquivo
├── docs/
│   ├── teoria/
│   │   └── RELATORIO_AUDITORIA_COMPLETO.md    # Relatório teórico (Parte 1)
│   ├── politicas/
│   │   └── POLITICA_USO_ACEITAVEL.md          # Política institucional
│   ├── treinamento/
│   │   └── PLANO_TREINAMENTO_SEGURANCA.md     # Programa de capacitação
│   └── diagramas/                             # Diagramas de arquitetura
├── pratica/
│   ├── docker-compose-lab.yml                 # Orquestração dos containers
│   ├── victima/                               # Container da máquina vítima
│   │   ├── Dockerfile.victima
│   │   └── entrypoint-victima.sh
│   ├── atacante/                              # Container da máquina atacante
│   │   ├── Dockerfile.atacante
│   │   ├── entrypoint-atacante.sh
│   │   └── scripts/
│   │       ├── ataque_ssh_bruteforce.sh       # Ataque SSH (V#1)
│   │       ├── exploit_vulnerabilidades.sh    # Exploração de V#2-V#7
│   │       └── enumerar_rede.sh               # Reconhecimento
│   ├── defesa/
│   │   └── scripts/
│   │       ├── hardening_completo.sh          # Mitigação de todas as vulns
│   │       └── validar_hardening.sh           # Teste de conformidade
│   └── logs/                                  # Logs de ataques e defesas
└── apresentacao/
    └── SLIDES_APRESENTACAO.md                 # Slides para seminário
```

---

## 🎭 Cenário do Trabalho

### O Incidente:

Um aluno do laboratório de informática observou discretamente um professor digitando sua senha durante uma aula. Posteriormente, o aluno obteve o endereço IP da máquina do professor na rede local e utilizou SSH para acessar remotamente o sistema, manipulando arquivos institucionais (notas de alunos, provas, etc.).

### Impactos:
- ✗ Violação de privacidade do professor
- ✗ Comprometimento da integridade acadêmica
- ✗ Exposição de dados sensíveis (LGPD)
- ✗ Perda de confiança na segurança institucional

---

## 🔓 Vulnerabilidades Identificadas

| ID | Vulnerabilidade | Severidade | CVE/CWE |
|----|----------------|------------|---------|
| **V#1** | **Acesso SSH Não Autorizado** (cenário principal) | CRÍTICA | - |
|  | • Senha fraca (8 caracteres) | | CWE-521 |
|  | • Shoulder surfing (engenharia social) | | - |
|  | • Ausência de MFA | | - |
|  | • Fail2ban não configurado | | - |
| **V#2** | **Ausência de Segmentação de Rede** | ALTA | CWE-923 |
|  | • Rede flat sem VLANs | | - |
|  | • Professores e alunos na mesma sub-rede | | - |
| **V#3** | **Serviços Desnecessários Expostos** | CRÍTICA | CWE-319 |
|  | • Telnet (porta 23) ativo | | - |
|  | • FTP sem criptografia (porta 21) | | - |
|  | • MySQL acessível remotamente | | - |
| **V#4** | **Senhas Padrão e Contas Compartilhadas** | CRÍTICA | CWE-521 |
|  | • Senhas fracas em múltiplas contas | | - |
|  | • Contas compartilhadas (aluno/aluno123) | | - |
| **V#5** | **Falta de Monitoramento e Auditoria** | ALTA | CWE-778 |
|  | • Logs locais não centralizados | | - |
|  | • Ausência de SIEM | | - |
|  | • Atacante pode apagar rastros | | - |
| **V#6** | **Privilégios Excessivos (sudo sem senha)** | CRÍTICA | CWE-250 |
|  | • NOPASSWD configurado | | - |
|  | • Escalação trivial para root | | - |
| **V#7** | **Ausência de Hardening de SO** | ALTA | CWE-1188 |
|  | • Firewall desabilitado | | - |
|  | • Serviços padrão inseguros | | - |

---

## 🚀 Como Executar

### Pré-requisitos:
- Docker 20.10+
- Docker Compose 2.0+
- Sistema Linux/macOS (ou WSL2 no Windows)
- Mínimo 4GB RAM disponível

### Passo 1: Clonar o Repositório
```bash
git clone https://github.com/[usuario]/trabalho_seguranca_roitier.git
cd trabalho_seguranca_roitier
```

### Passo 2: Subir o Ambiente de Laboratório
```bash
cd pratica
docker-compose -f docker-compose-lab.yml up --build -d
```

**Aguarde 1-2 minutos para inicialização completa dos serviços.**

### Passo 3: Verificar Containers Ativos
```bash
docker ps
```

Você deve ver:
- `lab-professor-victima` (172.20.0.10)
- `lab-aluno-atacante` (172.20.0.20)

---

## 🎬 Demonstração Prática

### PARTE 1: Simular o Ataque (Container Atacante)

#### 1.1 Acessar Container Atacante
```bash
docker exec -it lab-aluno-atacante /bin/bash
```

#### 1.2 Executar Ataque SSH (Vulnerabilidade #1)
```bash
cd /root/ataques
./ataque_ssh_bruteforce.sh
```

**Escolha Modo 1:** Ataque direcionado (simula cenário real)
- Usuário: `professor`
- Senha: `senha123` (obtida por shoulder surfing)

#### 1.3 Explorar Vulnerabilidades Adicionais
```bash
./exploit_vulnerabilidades.sh
```

**Escolha Opção 7:** Executar TODAS as explorações

---

### PARTE 2: Aplicar Hardening (Container Vítima)

#### 2.1 Acessar Container Vítima
```bash
docker exec -it lab-professor-victima /bin/bash
```

#### 2.2 Executar Hardening Completo
```bash
cd /root
sudo bash /pratica/defesa/scripts/hardening_completo.sh
```

**Este script aplicará:**
- ✅ SSH hardening (chaves, fail2ban, criptografia forte)
- ✅ Firewall UFW configurado
- ✅ Serviços inseguros desabilitados
- ✅ Política de senhas fortes
- ✅ Monitoramento com auditd
- ✅ Restrições de sudo
- ✅ Kernel hardening

#### 2.3 Validar Mitigações
```bash
sudo bash /pratica/defesa/scripts/validar_hardening.sh
```

**Meta:** ≥ 90% de conformidade

---

### PARTE 3: Testar Defesa

#### 3.1 Voltar ao Container Atacante
```bash
docker exec -it lab-aluno-atacante /bin/bash
```

#### 3.2 Tentar Ataque Novamente
```bash
./ataque_ssh_bruteforce.sh
```

**Resultado Esperado:**
- ❌ Autenticação por senha NEGADA (apenas chaves aceitas)
- ❌ Após 3 tentativas: IP bloqueado pelo Fail2Ban (1 hora)
- ✅ Sistema PROTEGIDO com sucesso!

---

## 📚 Documentação

### Relatório Teórico (Parte Teórica - 1 ponto)
📄 [`docs/teoria/RELATORIO_AUDITORIA_COMPLETO.md`](docs/teoria/RELATORIO_AUDITORIA_COMPLETO.md)

**Conteúdo:**
- Análise de vulnerabilidades e vetores de ataque
- Análise forense digital e cadeia de custódia
- Análise de logs (auth.log, syslog)
- Análise de riscos e impactos (institucional, humano, legal)
- Conformidade LGPD

### Políticas de Segurança
📄 [`docs/politicas/POLITICA_USO_ACEITAVEL.md`](docs/politicas/POLITICA_USO_ACEITAVEL.md)

**Conteúdo:**
- Regras de autenticação e acesso
- Uso dos sistemas e proteção de dados
- Monitoramento e auditoria
- Consequências por violação

### Plano de Treinamento
📄 [`docs/treinamento/PLANO_TREINAMENTO_SEGURANCA.md`](docs/treinamento/PLANO_TREINAMENTO_SEGURANCA.md)

**Conteúdo:**
- Módulo para Professores (4h)
- Módulo para Alunos (2h)
- Módulo para Funcionários TI (8h)
- Cronograma e materiais didáticos

### Slides de Apresentação
📄 [`apresentacao/SLIDES_APRESENTACAO.md`](apresentacao/SLIDES_APRESENTACAO.md)

---

## 🛠️ Tecnologias Utilizadas

### Infraestrutura:
- **Docker & Docker Compose:** Isolamento de ambientes
- **Ubuntu 22.04:** Sistema operacional base
- **Networking:** Bridge network isolada

### Ferramentas de Ataque (Container Atacante):
- **Hydra:** Brute-force de credenciais
- **Nmap:** Network scanning
- **SSHPass:** Automação SSH
- **Netcat:** Teste de conectividade

### Ferramentas de Defesa (Container Vítima):
- **Fail2Ban:** Proteção contra brute-force
- **UFW:** Firewall simplificado
- **Auditd:** Auditoria de sistema
- **PAM:** Política de senhas (libpam-pwquality)
- **rsyslog:** Log centralizado

### Frameworks e Padrões:
- **NIST SP 800-30:** Risk Assessment
- **NIST SP 800-53:** Security Controls
- **CIS Benchmarks:** System Hardening
- **ISO 27001:** Information Security Management
- **LGPD (Lei 13.709/2018):** Data Protection

---

## 📊 Resultados Esperados

### Antes do Hardening:
- ❌ SSH acessível com senha fraca
- ❌ 6 vulnerabilidades críticas/altas
- ❌ Pontuação de segurança: 15/100

### Depois do Hardening:
- ✅ SSH protegido (chaves + fail2ban)
- ✅ Todas as vulnerabilidades mitigadas
- ✅ Pontuação de segurança: 95/100
- ✅ Conformidade: ≥ 90%

---

## 🎓 Critérios de Avaliação

| Critério | Peso | Status |
|----------|------|--------|
| **Parte Teórica** | 1 ponto | ✅ Relatório completo em Markdown |
| **Parte Prática** | 3 pontos | ✅ Ambiente Docker + Scripts funcionais |
| • Simulação de ataque | 1,0 pt | ✅ 6 vulnerabilidades demonstradas |
| • Hardening e mitigação | 1,5 pt | ✅ Todas as vulns corrigidas + validação |
| • Políticas e treinamento | 0,5 pt | ✅ Documentos completos |
| **Desenvolvimento em Sala** | 2 pontos | ⏳ Apresentação + Arguição |
| • Apresentação clara | 1,0 pt | ⏳ Seminário de 15-20min |
| • Conhecimento técnico | 1,0 pt | ⏳ Responder perguntas do professor |
| **TOTAL** | **6 pontos** | |

---

## ⚠️ Avisos Legais e Éticos

### ⚖️ Uso Educacional APENAS

Este projeto foi desenvolvido **exclusivamente** para fins educacionais como parte da disciplina de Segurança da Informação.

**IMPORTANTE:**
- ✅ Use apenas em ambientes isolados (Docker containers fornecidos)
- ❌ NÃO utilize em sistemas reais sem autorização explícita
- ❌ Uso não autorizado é CRIME (Art. 154-A do Código Penal)
- ❌ Violações podem resultar em processo judicial e prisão

### 📜 Conformidade Legal

Este trabalho respeita:
- **Lei 13.709/2018 (LGPD)** - Proteção de Dados Pessoais
- **Lei 12.965/2014 (Marco Civil da Internet)**
- **Código Penal Brasileiro** - Art. 154-A

### 🤝 Declaração de Originalidade

Todo o código, documentação e análises foram desenvolvidos pela equipe do trabalho. Referências externas estão devidamente citadas no relatório teórico.

---

## 👥 Equipe

- **[Nome Aluno 1]** - Matrícula: XXXXXX
- **[Nome Aluno 2]** - Matrícula: XXXXXX

**Professor Orientador:** [Nome do Professor]
**Instituição:** [Nome da Universidade]

---

## 📞 Contato

Para dúvidas sobre o projeto:
- E-mail: [email@aluno.universidade.edu]
- GitHub: [link para issues]

---

## 📝 Licença

Este projeto é para fins educacionais. Veja [LICENSE](LICENSE) para mais detalhes.

---

## 🙏 Agradecimentos

- Professor [Nome] pela orientação
- Universidade pela infraestrutura
- Comunidade open-source pelas ferramentas utilizadas

---

**Data de Conclusão:** Novembro/2025
**Versão do Projeto:** 1.0
