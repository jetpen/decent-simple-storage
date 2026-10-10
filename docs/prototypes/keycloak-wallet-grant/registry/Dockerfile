ARG PYTHON_BASE
FROM ${PYTHON_BASE} AS build-deps
RUN apt-get update && apt-get install -y --no-install-recommends build-essential python3-dev libgmp-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY decent-simple-storage/docs/prototypes/keycloak-wallet-grant/build/python-requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.lock
COPY decent-registry/pyproject.toml decent-registry/README.md /app/
COPY decent-registry/src /app/src
RUN pip install --no-cache-dir --no-deps --no-build-isolation . && pip check
ENV PYTHONPATH=/app/src
ENTRYPOINT ["decent-registry"]
