FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir mcp

COPY server.py /app/server.py

ENV PORT=8200
# AUDIT_ENDPOINT must be set at runtime: docker run -e AUDIT_ENDPOINT=https://your-api-host ...

EXPOSE 8200

CMD ["python", "server.py", "--transport", "streamable-http"]
