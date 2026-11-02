# Benchmark target app: standard library only, no network access needed to run.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /bench
COPY app.py manifest.py ./

RUN useradd --create-home --home-dir /home/bench --shell /usr/sbin/nologin bench
USER bench

EXPOSE 9090
CMD ["python", "app.py", "9090"]
