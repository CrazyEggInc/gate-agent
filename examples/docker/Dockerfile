ARG RUNNER_IMAGE="alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6"

FROM ${RUNNER_IMAGE}
ARG VERSION=0.0.8

WORKDIR /app
RUN chown nobody /app
RUN mkdir /.aws && chown nobody /.aws

# install
RUN apk add --no-cache --update \
  ca-certificates=20261020-r0 aws-cli=2.34.63-r0 jq=1.8.2-r0 curl=8.22.0-r0 coreutils=9.11-r0 bash=5.3.9-r1

# install
RUN curl -fsSL "https://raw.githubusercontent.com/CrazyEggInc/gate-agent/refs/tags/v${VERSION#v}/install.sh" -o /tmp/gate-agent-install.sh \
  && VERSION="${VERSION}" GATE_AGENT_INSTALL_DIR=/app sh /tmp/gate-agent-install.sh \
  && rm /tmp/gate-agent-install.sh

USER nobody
EXPOSE 8787

COPY start.sh .

CMD ["/app/start.sh"]
