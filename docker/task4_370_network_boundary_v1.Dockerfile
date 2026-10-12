FROM python:3.11.16-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
WORKDIR /app
COPY scripts/task4_370_docker_network_service_v1.py /app/service.py
COPY scripts/task4_370_docker_network_agent_v1.py /app/agent.py
ENV PYTHONDONTWRITEBYTECODE=1
# No extra packages, real credentials, shell entrypoint or real cloud SDK.
