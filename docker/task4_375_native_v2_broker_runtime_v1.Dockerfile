FROM python:3.11.16-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONNOUSERSITE=1
WORKDIR /source/veritas_os_source
# Packages installed only at image-build time on trusted CI, never at runtime.
# Runtime networks are explicitly Docker --internal with no external egress.
COPY external-eval/v0.3.9 /build/ben_eval/
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
      "fastapi==0.137.2" "uvicorn==0.30.3" "h11==0.16.0" \
      "pydantic==2.11.10" "python-dotenv==1.2.2" "orjson==3.11.6" \
      "PyYAML==6.0.3" "jinja2==3.1.6" "jsonschema==4.23.0" \
      "openai==1.53.0" "httpx==0.28.1" "requests==2.34.2" \
      "idna==3.15" "numpy==1.26.4" "cryptography==50.0.0" \
      "psycopg[binary]==3.2.9" "psycopg-pool==3.2.6" \
      "alembic==1.18.4" "pytest==9.0.3" "pytest-asyncio==1.3.0" \
      "psutil==7.2.0" \
  && python -m pip install --no-cache-dir --disable-pip-version-check --no-deps /build/ben_eval
ENV PYTHONPATH=/source/veritas_os_source:/source/benchmark
# Exact code/fixtures mounted read-only by trusted CI from SHA-pinned checkouts.
# Never embed host/API secrets or authorize a Provider invocation.
