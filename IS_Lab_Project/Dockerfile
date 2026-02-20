# Stage 1 — get ZAP from official image
FROM ghcr.io/zaproxy/zaproxy:stable AS zap

# Stage 2 — your Python app
FROM python:3.10-slim

# Install Java (ZAP needs it)
RUN apt-get update && apt-get install -y \
    openjdk-21-jre-headless \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy ZAP from official image
COPY --from=zap /zap /opt/zap

ENV ZAP_PATH=/opt/zap/zap.sh
ENV PATH="/opt/zap:${PATH}"

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8080

CMD ["python", "app.py"]
