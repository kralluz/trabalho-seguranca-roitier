```bash
cd /home/usuario/Documents/Github/trabalho_seguranca_roitier/pratica
```
Navegar para diretório do projeto

```bash
docker-compose -f docker-compose-lab.yml up --build -d
```
Subir containers (vítima + atacante) - aguardar 30s para inicialização

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