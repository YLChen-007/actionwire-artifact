FROM python:3.12-slim@sha256:a39549e211a16149edf74e5fdc9ef03a6767e46cd987c5048b6659b6c9904c94

ENV PYTHONPATH=/opt/clawgap PYTHONDONTWRITEBYTECODE=1
WORKDIR /opt/clawgap
COPY src /opt/clawgap/src
COPY benchmark/python/AstrBot /opt/clawgap/benchmark/python/AstrBot
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && python -m pip install --no-cache-dir --disable-pip-version-check \
      jsonschema==4.25.1 \
 && python -m pip install --no-cache-dir --disable-pip-version-check \
      -r /opt/clawgap/benchmark/python/AstrBot/requirements.txt \
 && apt-get purge -y build-essential \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*
USER 65532:65532
