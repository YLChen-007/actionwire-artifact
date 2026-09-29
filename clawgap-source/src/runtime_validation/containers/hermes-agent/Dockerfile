FROM node:22-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 AS node-runtime
FROM python:3.12-slim@sha256:a39549e211a16149edf74e5fdc9ef03a6767e46cd987c5048b6659b6c9904c94

ENV PYTHONPATH=/opt/clawgap PYTHONDONTWRITEBYTECODE=1
WORKDIR /opt/clawgap
COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=node-runtime /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

COPY src /opt/clawgap/src
COPY benchmark/python/hermes-agent /opt/clawgap/benchmark/python/hermes-agent
WORKDIR /opt/clawgap/benchmark/python/hermes-agent
RUN npm ci --ignore-scripts --no-audit --no-fund
WORKDIR /opt/clawgap
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
      jsonschema==4.25.1 \
      aiohttp \
 && python -m pip install --no-cache-dir --disable-pip-version-check \
      /opt/clawgap/benchmark/python/hermes-agent

USER 65532:65532
