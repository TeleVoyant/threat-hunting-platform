# Dockerfile for Federated Learning Server / Client
FROM python:3.11-slim

WORKDIR /app

# Install only FL-relevant dependencies
RUN pip install --no-cache-dir \
    flwr[simulation]>=1.7.0 \
    xgboost>=1.7.0 \
    numpy>=1.24.0 \
    pyyaml>=6.0 \
    pydantic>=2.0

# Copy FL code + shared modules
COPY shared/ shared/
COPY federated/ federated/
COPY config/ config/

RUN useradd -m -u 1000 fluser
USER fluser

# Default: run FL server. Override in docker-compose for clients.
CMD ["python", "-m", "federated.server"]
