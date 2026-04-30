FROM python:3.12-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY fraud_detection.py download_payments.py build_blocked_list.py \
     webhook_server.py db.py female_names.csv ./

CMD exec python webhook_server.py --port ${PORT:-8080} --host 0.0.0.0
