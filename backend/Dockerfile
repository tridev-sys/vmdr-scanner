# One image serves both roles: `uvicorn` for web-api, `python -m app.worker` for scanner-worker.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app

# Non-root user. HOME matters: nuclei stores templates in $HOME/nuclei-templates.
RUN useradd --create-home --home-dir /home/vmdr --shell /usr/sbin/nologin vmdr \
 && mkdir -p /data/scans \
 && chown -R vmdr:vmdr /data

USER vmdr
ENV HOME=/home/vmdr \
    VMDR_DATABASE_URL=sqlite:////data/vmdr.db \
    VMDR_SCAN_WORKDIR=/data/scans

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
