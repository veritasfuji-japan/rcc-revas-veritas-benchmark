FROM python:3.11.16-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
WORKDIR /app
COPY scripts/task4_370_docker_network_service_v1.py /app/service.py
COPY scripts/task4_370_docker_network_agent_v1.py /app/agent.py
COPY scripts/task4_371_veritas_bind_gateway_v1.py /app/veritas_gateway.py
COPY scripts/task4_371_veritas_bind_agent_v1.py /app/veritas_agent.py
# Actual upstream VERITAS OS source from exact pinned Git checkout;
# no surrogate or locally reimplemented admission algorithm.
COPY _pins/veritas/veritas_os/core/continuation_runtime/bind_admissibility.py /app/veritas_bind_admissibility.py
ENV PYTHONDONTWRITEBYTECODE=1
# No real Provider SDK, account secrets, bank client, or live network entrypoint.
