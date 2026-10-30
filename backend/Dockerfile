# One image serves both roles: uvicorn for web-api, `python -m app.worker` for scanner-worker.
FROM python:3.13-slim

ARG NUCLEI_VERSION=3.11.1
ARG KATANA_VERSION=1.8.0
ARG TARGETARCH

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Nuclei and katana (crawler for DAST discovery): pinned releases, installed for the build platform.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip ca-certificates \
 && curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" \
 && unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin \
 && chmod 0755 /usr/local/bin/nuclei \
 && curl -fsSL -o /tmp/katana.zip \
      "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${TARGETARCH}.zip" \
 && unzip -q /tmp/katana.zip katana -d /usr/local/bin \
 && chmod 0755 /usr/local/bin/katana \
 && rm -f /tmp/nuclei.zip /tmp/katana.zip \
 && apt-get purge -y curl unzip && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app ./app
COPY scripts ./scripts
# Payload DAST templates, pinned (see payload-templates/PIN.txt). Read-only for the scanner user.
COPY payload-templates /opt/vmdr/payload-templates

# Non-root user. HOME matters: nuclei keeps templates in $HOME/nuclei-templates.
# Ownership set here is copied into the named volumes on first use.
RUN useradd --create-home --home-dir /home/vmdr --shell /usr/sbin/nologin vmdr \
 && mkdir -p /data/scans /home/vmdr/nuclei-templates \
 && chown -R vmdr:vmdr /data /home/vmdr

USER vmdr
ENV HOME=/home/vmdr

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
