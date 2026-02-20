FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    openjdk-21-jre-headless \
    wget \
    curl \
    && apt-get clean

RUN wget -qO- https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz | tar zx -C /opt
ENV ZAP_PATH=/opt/ZAP_2.14.0/zap.sh

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p uploads reports

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
