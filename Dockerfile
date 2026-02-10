FROM python:3.12-slim

ENV MPLBACKEND=Agg

RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils bind9-dnsutils \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY cli.py /app/cli.py
COPY dnssec_analytics.py /app/dnssec_analytics.py
COPY dnssec_reporting.py /app/dnssec_reporting.py
COPY dnssec_runner.py /app/dnssec_runner.py
COPY dnssec_scanner.py /app/dnssec_scanner.py
COPY dnssec_tool.py /app/dnssec_tool.py

COPY app.py /app/app.py
COPY requirements.txt /app/requirements.txt
COPY static /app/static

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
