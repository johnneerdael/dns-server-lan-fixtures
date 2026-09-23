FROM python:3.12-alpine

LABEL org.opencontainers.image.source="https://github.com/johnneerdael/dns-server-lan-fixtures"
LABEL org.opencontainers.image.description="Fresh DNS answers and bounded transport fixtures for example.test"
RUN addgroup -g 10001 dnsfault \
    && adduser -D -H -u 10001 -G dnsfault dnsfault
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY --chown=10001:10001 dns_fault_proxy.py /app/dns_fault_proxy.py
COPY --chown=10001:10001 fresh_fixtures.py fresh_transport.py security_records.py /app/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 5301/tcp 5301/udp
ENTRYPOINT ["python3", "/app/dns_fault_proxy.py"]
