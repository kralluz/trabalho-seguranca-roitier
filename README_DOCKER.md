# Network Security Scanner - Docker

Ferramenta educacional para análise de vulnerabilidades de rede, containerizada com Docker.

## 🚀 Início Rápido

### 1. Construir e subir o container
```bash
docker-compose up --build -d
```

### 2. Acessar o container
```bash
docker exec -it network-security-scanner /bin/bash
```

### 3. Executar o scanner
```bash
./network_security_scanner.sh
```

### 4. Ver relatórios gerados
```bash
ls -la reports/
cat reports/network_scan_report_*.txt
```

## 📋 Comandos Úteis

### Construir imagem
```bash
docker-compose build
```

### Subir container em background
```bash
docker-compose up -d
```

### Ver logs do container
```bash
docker-compose logs -f network-scanner
```

### Parar container
```bash
docker-compose down
```

### Executar scanner diretamente
```bash
docker exec -it network-security-scanner ./network_security_scanner.sh 192.168.1.0/24
```

### Testar funcionalidade
```bash
docker exec -it network-security-scanner ./test_ssh_port.sh
```

## 🏗️ Arquitetura

### Dockerfile
- Base: Ubuntu 22.04
- Dependências: iproute2, dnsutils, netcat, ping, telnet
- Usuário: scanner (não-root)
- Volumes: /app/reports, /app/logs

### Docker Compose
- Network mode: host (acesso completo à rede)
- Volumes persistentes para reports e logs
- Environment variables configuráveis

## 🔧 Configuração

### Variáveis de Ambiente
```yaml
environment:
  - SCANNER_VERSION=2.0
  - SCAN_TIMEOUT=300
  - NETWORK_RANGE=auto
```

### Volumes
- `./reports:/app/reports` - Relatórios gerados
- `./logs:/app/logs` - Arquivos de log

## 📊 Funcionalidades

✅ **Scan completo de rede** (1-254 hosts)  
✅ **Detecção de vulnerabilidades** em 6 categorias  
✅ **Relatório consolidado** único  
✅ **Testes isolados** de funcionalidades  
✅ **Interface educacional** com explicações  

## 🔒 Segurança

- Container roda como usuário não-root
- Network mode host para acesso à rede
- Volumes isolados para dados
- Imagem baseada em Ubuntu oficial

## 📚 Uso Educacional

Este container é ideal para:
- Estudos de segurança de redes
- Demonstrações em sala de aula
- Testes em ambientes controlados
- Aprendizado de Docker e containers

## ⚠️ Avisos

- Use apenas em redes autorizadas
- Respeite leis locais sobre scanning
- Não use em ambientes de produção
- Dados sensíveis podem ser detectados

## 🐛 Troubleshooting

### Container não sobe
```bash
docker-compose logs network-scanner
```

### Dependências faltando
```bash
docker exec -it network-security-scanner apt update && apt install -y <pacote>
```

### Rede não acessível
Verifique se `network_mode: host` está configurado

## 📝 Licença

Educacional - Network Security Scanner v2.0