# Multi-stage throwaway image for the current local decent-identity checkout.
FROM python:3.12-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential python3-dev libgmp-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY decent-registry/pyproject.toml decent-registry/README.md /src/decent-registry/
COPY decent-registry/src /src/decent-registry/src
COPY decent-identity/pyproject.toml decent-identity/README.md /src/decent-identity/
COPY decent-identity/src /src/decent-identity/src
COPY decent-simple-storage/docs/prototypes/keycloak-wallet-grant/verifier/requirements.txt /src/verifier/requirements.txt
RUN pip install --no-cache-dir /src/decent-registry /src/decent-identity -r /src/verifier/requirements.txt

FROM python:3.12-slim
COPY --from=build /usr/local /usr/local
WORKDIR /app
COPY decent-simple-storage/docs/prototypes/keycloak-wallet-grant/verifier/app.py /app/app.py
COPY decent-simple-storage/docs/prototypes/keycloak-wallet-grant/verifier/start_verifier.py /app/start_verifier.py
ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/start_verifier.py"]
