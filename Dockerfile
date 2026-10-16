FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir .

RUN mkdir -p /data /evidence

CMD ["uvicorn", "avchain.ledger.service:app", "--host", "0.0.0.0", "--port", "8000"]
