FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    aiohttp \
    redis \
    structlog \
    prometheus_client

COPY lattice_keeper.py app.py

EXPOSE 8765

CMD ["python", "app.py"]
