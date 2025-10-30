# Dockerfile para Network Security Scanner
FROM ubuntu:22.04

# Definir maintainer
LABEL maintainer="Network Security Scanner Team"
LABEL description="Ferramenta educacional para análise de vulnerabilidades de rede"

# Evitar prompts interativos durante instalação
ENV DEBIAN_FRONTEND=noninteractive

# Atualizar sistema e instalar dependências
RUN apt-get update && apt-get install -y \
    iproute2 \
    dnsutils \
    netcat-openbsd \
    iputils-ping \
    telnet \
    curl \
    vim \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Criar diretório de trabalho
WORKDIR /app

# Copiar arquivos do projeto
COPY . /app/

# Criar diretórios para volumes
RUN mkdir -p /app/reports /app/logs

# Tornar scripts executáveis
RUN chmod +x /app/network_security_scanner.sh \
    && chmod +x /app/entrypoint.sh \
    && chmod +x /app/test_ssh_port.sh

# Definir usuário não-root para segurança
RUN useradd -m -s /bin/bash scanner && \
    chown -R scanner:scanner /app
USER scanner

# Expor porta (opcional, para futura web UI)
# EXPOSE 8080

# Definir entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Labels para metadados
LABEL version="2.0"
LABEL project="Network Security Scanner"
LABEL purpose="Educational Network Vulnerability Assessment"