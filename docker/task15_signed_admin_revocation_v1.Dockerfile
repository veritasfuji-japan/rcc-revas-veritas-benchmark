FROM python:3.11.16-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
RUN python -m pip install --no-cache-dir --disable-pip-version-check "cryptography==50.0.0" "cffi==2.0.0" "pycparser==2.23"
WORKDIR /app
COPY task15_mock_broker_authorization_boundary_v1.py /app/
COPY task15_stolen_session_revocation_fence_v1.py /app/
COPY task15_signed_admin_revocation_v1.py /app/
COPY scripts/task15_unix_ipc_mock_broker_server_v1.py /app/scripts/
COPY scripts/task15_session_challenge_broker_server_v1.py /app/scripts/
COPY scripts/task15_signed_admin_docker_broker_v1.py /app/scripts/
ENV PYTHONDONTWRITEBYTECODE=1
# No production Provider secrets, HTTP client or banking tools.
# Runtime docker create: --network=none, read-only root, nonroot, caps dropped.
