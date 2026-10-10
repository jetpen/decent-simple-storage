FROM python:3.12-slim AS build-deps
RUN apt-get update && apt-get install -y --no-install-recommends build-essential python3-dev libgmp-dev && rm -rf /var/lib/apt/lists/*

FROM build-deps
WORKDIR /app
COPY pyproject.toml README.md /app/
COPY src /app/src
RUN pip install --no-cache-dir .
ENV PYTHONPATH=/app/src
ENTRYPOINT ["decent-registry"]
