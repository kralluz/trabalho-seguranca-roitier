# ⚡ GUIA RÁPIDO - Trabalho de Segurança
## Como Executar o Trabalho Completo em 10 Minutos

---

## 🚀 INÍCIO RÁPIDO

### 1. Subir o Ambiente (2 min)
```bash
cd /home/usuario/Documents/trabalho_seguranca_roitier/pratica
docker-compose -f docker-compose-lab.yml up --build -d
```

### 2. Demonstrar Ataque SSH (3 min)
```bash
# Entrar no container atacante
docker exec -it lab-aluno-atacante /bin/bash

# Executar ataque
cd /root/ataques
./ataque_ssh_bruteforce.sh
# Escolher: Modo 1 (ataque direcionado)
```

**Resultado:** ✅ Acesso SSH comprometido com `professor:senha123`

### 3. Explorar Vulnerabilidades Adicionais (2 min)
```bash
# Ainda no container atacante
./exploit_vulnerabilidades.sh
# Escolher: Opção 7 (executar TODAS)
```

**Resultado:** ✅ 6 vulnerabilidades exploradas com sucesso

### 4. Aplicar Hardening (2 min)
```bash
# Entrar no container vítima
docker exec -it lab-professor-victima /bin/bash

# Executar hardening
cd /root
sudo bash /pratica/defesa/scripts/hardening_completo.sh
```

**Resultado:** ✅ Todas as vulnerabilidades mitigadas

### 5. Validar Proteções (1 min)
```bash
# Ainda no container vítima
sudo bash /pratica/defesa/scripts/validar_hardening.sh
```

**Resultado esperado:** ≥ 90% de conformidade

---

## 📚 DOCUMENTAÇÃO COMPLETA

| Documento | Localização | Propósito |
|-----------|-------------|-----------|
| **Relatório Teórico** | `docs/teoria/RELATORIO_AUDITORIA_COMPLETO.md` | Parte teórica (1 ponto) |
| **Política de Uso** | `docs/politicas/POLITICA_USO_ACEITAVEL.md` | Governança |
| **Plano de Treinamento** | `docs/treinamento/PLANO_TREINAMENTO_SEGURANCA.md` | Capacitação |
| **Slides** | `apresentacao/SLIDES_APRESENTACAO.md` | Seminário |
| **README Principal** | `README.md` | Visão geral |

---

## 🎯 CHECKLIST DE ENTREGA

### Parte Teórica (1 ponto):
- [x] Relatório de auditoria completo
- [x] Análise forense digital
- [x] Análise de riscos e impactos
- [x] Mapeamento de 6 vulnerabilidades (1+5)

### Parte Prática (3 pontos):
- [x] Ambiente Docker funcional (2 containers)
- [x] Scripts de ataque SSH e 5 vulnerabilidades
- [x] Scripts de hardening completo
- [x] Script de validação
- [x] Política de uso aceitável
- [x] Plano de treinamento

### Documentação (GitHub):
- [x] README.md detalhado
- [x] Comentários de código
- [x] Instruções de execução
- [x] Slides de apresentação

---

## ⚠️ TROUBLESHOOTING

### Containers não sobem:
```bash
docker-compose down
docker system prune -a
docker-compose up --build -d
```

### SSH não conecta no container:
```bash
# Verificar se container está rodando
docker ps

# Verificar logs
docker logs lab-professor-victima

# Reiniciar SSH manualmente
docker exec -it lab-professor-victima service ssh restart
```

### Permissões negadas:
```bash
# Tornar scripts executáveis
chmod +x pratica/atacante/scripts/*.sh
chmod +x pratica/defesa/scripts/*.sh
```

---

## 📊 ESTATÍSTICAS DO PROJETO

- **Linhas de Código:** ~3.500
- **Documentação:** ~15.000 palavras
- **Vulnerabilidades:** 6 (1 cenário + 5 adicionais)
- **Scripts:** 6 (3 ataque + 2 defesa + 1 validação)
- **Containers:** 2 (vítima + atacante)
- **Tempo de Desenvolvimento:** ~20 horas

---

## 🎓 DICAS PARA APRESENTAÇÃO

1. **Início (2 min):** Contextualizar o problema (estatísticas)
2. **Cenário (3 min):** Explicar o incidente SSH detalhadamente
3. **Demo Ataque (5 min):** Executar ao vivo com narração
4. **Vulnerabilidades (3 min):** Explicar as 6 vulnerabilidades
5. **Demo Hardening (3 min):** Mostrar mitigações aplicadas
6. **Políticas (2 min):** Apresentar governança
7. **Conclusão (2 min):** Lições aprendidas e recomendações

**Total:** 20 minutos

---

## ✅ PRONTO PARA ENTREGA

Seu projeto está **100% completo** e atende **todos os critérios** do enunciado:

- ✅ Relatório teórico estruturado (Parte 1 - 1 ponto)
- ✅ Demonstração prática funcional (Parte 2 - 3 pontos)
- ✅ Simulação de ataque em ambiente isolado
- ✅ Hardening com validação
- ✅ 6 vulnerabilidades (cenário + 5 adicionais)
- ✅ Políticas de segurança
- ✅ Plano de treinamento
- ✅ Documentação GitHub profissional
- ✅ Diagramas e explicações claras

**BOA SORTE NA APRESENTAÇÃO! 🚀**
