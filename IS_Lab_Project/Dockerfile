FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    openjdk-21-jre-headless \
    wget \
    curl \
    tar \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q --show-progress --progress=dot:giga \
    https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz \
    && tar -xzf ZAP_2.14.0_Linux.tar.gz -C /opt \
    && rm ZAP_2.14.0_Linux.tar.gz

ENV ZAP_PATH=/opt/ZAP_2.14.0/zap.sh

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8080

CMD ["python", "app.py"]
