FROM python:3.11.16-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
WORKDIR /app
# Build-time packaging network only to retrieve pinned third-party dependencies.
# Runtime always --network=none, nonroot, cap-drop ALL, read-only root.
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
    "pydantic==2.11.10" "cryptography==50.0.0" "pytest==9.0.3" \
    "jsonschema==4.23.0" "PyYAML==6.0.3"
COPY _pins/veritas/veritas_os/ /app/veritas_os/
COPY scripts/task4_372_real_laba_docker_proof_v1.py /app/task4_372.py
ENV PYTHONDONTWRITEBYTECODE=1
