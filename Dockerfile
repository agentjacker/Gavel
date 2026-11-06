FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY setup.py README.md ./
COPY gavel ./gavel
RUN pip install --no-cache-dir . && useradd --uid 10001 --create-home gavel \
    && mkdir -p /app/data && chown gavel:gavel /app/data
COPY examples ./examples
USER gavel
EXPOSE 8080
CMD ["gavel-server", "--config", "/app/gavel.config.json", "--host", "0.0.0.0"]
