ARG ALPINE_VERSION=3.23.4
ARG RUNNER_IMAGE="alpine:${ALPINE_VERSION}"
ARG VERSION=x.y.z

FROM ${RUNNER_IMAGE}

WORKDIR /app
RUN chown nobody /app
RUN mkdir /.aws && chown nobody /.aws

# install
RUN apk add --no-cache --update \
  aws-cli jq curl coreutils bash \
  && rm -rf /var/cache/apk/*

# install
RUN curl -fsSL https://raw.githubusercontent.com/CrazyEggInc/gate-agent/refs/heads/master/install.sh | VERSION=${VERSION} GATE_AGENT_INSTALL_DIR=/app sh

USER nobody
EXPOSE 8787

COPY start.sh .

CMD ["/app/start.sh"]
