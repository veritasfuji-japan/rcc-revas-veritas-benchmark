FROM python:3.11.16-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
RUN python -m pip install --no-cache-dir --disable-pip-version-check "cryptography==50.0.0" "cffi==2.0.0" "pycparser==2.23"
WORKDIR /app
COPY task15_mock_broker_authorization_boundary_v1.py /app/
COPY scripts/task15_unix_ipc_mock_broker_server_v1.py /app/scripts/
ENV PYTHONDONTWRITEBYTECODE=1
# Actual broker UID/GID, read-only root, network namespace and mounts are
# enforced at docker create and independently checked against docker inspect.
# No API keys, network sender, privileged Docker socket or bank tools included.
