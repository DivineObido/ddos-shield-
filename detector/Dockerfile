FROM python:3.11-alpine

WORKDIR /app


RUN apk add --no-cache \
    iptables \
    procps \
    curl

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /var/log/detector

CMD ["python", "main.py"]