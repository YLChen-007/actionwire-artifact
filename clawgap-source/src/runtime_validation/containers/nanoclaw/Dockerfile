FROM node:22-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 AS node-runtime
FROM oven/bun:1.3.14-slim@sha256:d56a2534ffd262e92c12fd3249d3924d296d97086da773f821d7d0477435ea04 AS bun-runtime
FROM python:3.12-slim@sha256:a39549e211a16149edf74e5fdc9ef03a6767e46cd987c5048b6659b6c9904c94

ENV PYTHONPATH=/opt/clawgap PYTHONDONTWRITEBYTECODE=1 PATH=/usr/local/bin:/usr/bin:/bin
WORKDIR /opt/clawgap
COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=node-runtime /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
COPY --from=bun-runtime /usr/local/bin/bun /usr/local/bin/bun
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm  && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx  && python -m pip install --no-cache-dir --disable-pip-version-check jsonschema==4.25.1
COPY src /opt/clawgap/src
COPY benchmark/typescript/nanoclaw /opt/clawgap/benchmark/typescript/nanoclaw
WORKDIR /opt/clawgap/benchmark/typescript/nanoclaw
RUN npm exec --yes --package=pnpm@10.33.0 -- pnpm install --frozen-lockfile --ignore-scripts
WORKDIR /opt/clawgap
USER 65532:65532
