FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils bind9-dnsutils \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY dnssec_tool.py /app/dnssec_tool.py
COPY app.py /app/app.py
COPY requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
