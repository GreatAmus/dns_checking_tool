FROM python:3.12-slim

ENV MPLBACKEND=Agg

RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils bind9-dnsutils \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

RUN pip install .

EXPOSE 8080
CMD ["uvicorn", "dns_checking_tool.app:app", "--host", "0.0.0.0", "--port", "8080"]
