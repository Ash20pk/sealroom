# Hosted web demo: the Sealroom orchestrator, near-cli-rs for signing, and the static web app.
FROM python:3.12-slim

ARG NEAR_CLI_VERSION=0.22.2
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && arch="$(uname -m)" \
 && curl -fsSL "https://github.com/near/near-cli-rs/releases/download/v${NEAR_CLI_VERSION}/near-cli-rs-${arch}-unknown-linux-gnu.tar.gz" \
    | tar -xz -C /tmp \
 && install -m 755 "$(find /tmp -type f -name near | head -1)" /usr/local/bin/near \
 && rm -rf /tmp/* /var/lib/apt/lists/* \
 && near --version

COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv
WORKDIR /srv
COPY app/pyproject.toml app/uv.lock app/
RUN cd app && uv sync --frozen --no-dev --no-install-project
COPY app app
COPY web web
COPY demo demo
RUN cd app && uv sync --frozen --no-dev
COPY deploy/near-config.toml /root/.config/near-cli/config.toml
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh

ENV HOST=0.0.0.0 PORT=10000 SEALROOM_STATE=/srv/.state PYTHONUNBUFFERED=1
EXPOSE 10000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
