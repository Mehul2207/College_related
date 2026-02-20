FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    openjdk-21-jre-headless \
    wget \
    curl \
    tar \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Use latest version here
RUN wget -q https://github.com/zaproxy/zaproxy/releases/latest/download/ZAP_Linux.tar.gz \
    && tar -xzf ZAP_Linux.tar.gz -C /opt \
    && rm ZAP_Linux.tar.gz

ENV ZAP_PATH=/opt/ZAP/zap.sh

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8080

CMD ["python", "app.py"]
