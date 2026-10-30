# One image serves both roles: uvicorn for web-api, `python -m app.worker` for scanner-worker.
FROM python:3.13-slim

ARG NUCLEI_VERSION=3.11.1
ARG TARGETARCH

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Nuclei: pinned release, installed for the build platform (amd64 or arm64).
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip ca-certificates \
 && curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" \
 && unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin \
 && chmod 0755 /usr/local/bin/nuclei \
 && rm -f /tmp/nuclei.zip \
 && apt-get purge -y curl unzip && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app ./app
COPY scripts ./scripts

# Non-root user. HOME matters: nuclei keeps templates in $HOME/nuclei-templates.
# Ownership set here is copied into the named volumes on first use.
RUN useradd --create-home --home-dir /home/vmdr --shell /usr/sbin/nologin vmdr \
 && mkdir -p /data/scans /home/vmdr/nuclei-templates \
 && chown -R vmdr:vmdr /data /home/vmdr

USER vmdr
ENV HOME=/home/vmdr

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
