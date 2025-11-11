```bash
cd /home/usuario/Documents/Github/trabalho_seguranca_roitier/pratica
```
Navegar para diretório do projeto

```bash
docker-compose -f docker-compose-lab.yml up --build -d
```
Subir containers (vítima + atacante) - aguardar 10s para inicialização

```bash
docker ps
```
Verificar se containers estão rodando

```bash
docker exec lab-aluno-atacante bash /root/ataques/ssh_rapido.sh

```
DEMO 1: Ataque SSH via shoulder surfing (~10s)

```bash
docker exec lab-aluno-atacante bash /root/ataques/demo_rapido.sh

```
DEMO 2: Explorar todas as 6 vulnerabilidades (~30s)

```bash
docker exec lab-professor-victima bash /root/defesa/hardening_rapido.sh
```
Aplicar hardening completo - mitigar TODAS as vulnerabilidades (~10s)

```bash
docker exec lab-professor-victima bash /root/defesa/validar_rapido.sh
```
Validar hardening - verificar conformidade (≥70%)

```bash
docker exec lab-aluno-atacante bash /root/ataques/ssh_rapido.sh
```
DEMO 3: Tentar ataque novamente - deve FALHAR (sistema protegido)

```bash
docker-compose -f docker-compose-lab.yml down
```
Parar e remover containers

## 📋 VISUALIZAR LOGS (Comprovação)

```bash
docker exec lab-professor-victima tail -50 /var/log/auth.log
```
Ver logs de autenticação SSH - mostra tentativas de login (sucesso/falha)

```bash
docker exec lab-professor-victima grep "Accepted password" /var/log/auth.log
```
Filtrar apenas logins SSH bem-sucedidos com data/hora e IP de origem

```bash
docker exec lab-professor-victima grep "Failed password" /var/log/auth.log
```
Filtrar tentativas de login SSH falhadas (para detectar brute-force)

```bash
docker exec lab-professor-victima tail -f /var/log/auth.log
```
Monitorar logs SSH em tempo real (Ctrl+C para sair)

```bash
docker logs lab-professor-victima | tail -50
```
Ver logs gerais do container (stdout do entrypoint)

```bash
docker exec lab-professor-victima ls -lh /var/log/hardening_*.log 2>/dev/null
```
Verificar se log de hardening foi criado (gerado pelo hardening_completo.sh)