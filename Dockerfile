FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates build-essential && \
    rm -rf /var/lib/apt/lists/*

RUN curl -sL https://github.com/XTLS/Xray-core/releases/download/v1.8.21/Xray-linux-64.zip -o /tmp/xray.zip && \
    unzip /tmp/xray.zip -d /usr/local/bin/ && \
    rm /tmp/xray.zip && \
    chmod +x /usr/local/bin/xray

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# کپی همه فایل‌ها از جمله static و templates
COPY main.py .
COPY templates/ ./templates/
COPY static/ ./static/

RUN mkdir -p /app/configs /app/data

EXPOSE 8000

CMD ["python", "main.py"]
