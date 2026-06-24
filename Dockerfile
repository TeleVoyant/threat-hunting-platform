# Base Dockerfile for the AI Platform (API + Detection Loop)
FROM python:3.11-slim

WORKDIR /app

# Regenerate stdlib bytecode from source.
# The base image's precompiled stdlib can ship a corrupt .pyc on some hosts
# (seen here: configparser.cpython-311.pyc -> "ValueError: bad marshal data"),
# which crashes uvicorn at import before the app ever starts. The .py sources
# are intact, so force-recompile the top-level stdlib (-l = no recursion, skips
# lib2to3 py2 test fixtures) into our own image layer, then fail the build fast
# if it still won't import. Cheap (~15s) and keeps the image reproducible.
# RUN python -m compileall -fql /usr/local/lib/python3.11 \
#  && python -c "import configparser"

# Install dependencies
COPY requirements.lock.txt .
RUN pip install --no-cache-dir -r requirements.lock.txt

# Copy platform code
COPY shared/ shared/
COPY ingestion/ ingestion/
COPY features/ features/
COPY detection/ detection/
COPY federated/ federated/
COPY threat_intel/ threat_intel/
COPY alert_manager/ alert_manager/
COPY visualization/ visualization/
COPY observability/ observability/
COPY api/ api/
# training/ is required at runtime by the Models page:
#   - in-process imports for retrain (training.synthetic, training.trainer, ...)
#   - subprocess `python -m training.evaluate_models` and `python -m training.tuning`
# .dockerignore excludes training/data/ so the FL CSV partitions don't bloat the image.
COPY training/ training/
# scripts/ is used by /admin/hardening (runs scripts/audit_compose_hardening.py).
COPY scripts/ scripts/
COPY run_server.py .

# Config is mounted as volume, not baked into image
# Models are mounted as volume

# Non-root user
RUN useradd -m -u 1000 platform
RUN mkdir -p /app/data/{dead_letter,audit,alerts,graphs,allowlist,fl_local,fleet,drift} \
       && chown -R platform:platform /app/data
USER platform

EXPOSE 8000

CMD ["python", "run_server.py", "--mode", "full"]
