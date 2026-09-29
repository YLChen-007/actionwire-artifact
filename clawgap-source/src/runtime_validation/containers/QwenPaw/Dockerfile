FROM python:3.12-slim@sha256:a39549e211a16149edf74e5fdc9ef03a6767e46cd987c5048b6659b6c9904c94

ENV PYTHONPATH=/opt/clawgap PYTHONDONTWRITEBYTECODE=1
WORKDIR /opt/clawgap
COPY src /opt/clawgap/src
COPY benchmark/python/QwenPaw /opt/clawgap/benchmark/python/QwenPaw
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
      jsonschema==4.25.1 agentscope==2.0.0 agentscope-runtime==1.1.6 \
      mcp==1.27.2 python-dotenv PyYAML
USER 65532:65532
