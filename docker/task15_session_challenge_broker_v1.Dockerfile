FROM python:3.11.16-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
RUN python -m pip install --no-cache-dir --disable-pip-version-check "cryptography==50.0.0" "cffi==2.0.0" "pycparser==2.23"
WORKDIR /app
COPY task15_mock_broker_authorization_boundary_v1.py /app/
COPY scripts/task15_unix_ipc_mock_broker_server_v1.py /app/scripts/
COPY scripts/task15_session_challenge_broker_server_v1.py /app/scripts/
ENV PYTHONDONTWRITEBYTECODE=1
# Docker create enforces non-root, read-only root, no network/caps and
# broker-only synthetic-secret and session-verifier key mounts.
