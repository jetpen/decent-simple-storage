ARG PYTHON_BASE
FROM ${PYTHON_BASE} AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential python3-dev libgmp-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY decent-simple-storage/docs/prototypes/keycloak-wallet-grant/build/python-requirements.lock /src/requirements.lock
RUN pip install --no-cache-dir --require-hashes -r /src/requirements.lock
COPY decent-registry/pyproject.toml decent-registry/README.md /src/decent-registry/
COPY decent-registry/src /src/decent-registry/src
COPY decent-identity/pyproject.toml decent-identity/README.md /src/decent-identity/
COPY decent-identity/src /src/decent-identity/src
RUN pip install --no-cache-dir --no-deps --no-build-isolation /src/decent-registry /src/decent-identity && pip check

FROM ${PYTHON_BASE}
COPY --from=build /usr/local /usr/local
WORKDIR /app
COPY decent-simple-storage/docs/prototypes/keycloak-wallet-grant/verifier/app.py /app/app.py
COPY decent-simple-storage/docs/prototypes/keycloak-wallet-grant/verifier/start_verifier.py /app/start_verifier.py
ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/start_verifier.py"]
