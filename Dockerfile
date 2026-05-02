FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    libpcap0.8 \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p logs

EXPOSE 5000

CMD ["python", "main.py"]