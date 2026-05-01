#!/usr/bin/env bash

set -euo pipefail

# implement your configuration setup below
# e.g. my-secrets-command > .secrets

# start server
/app/gate-agent start --config .secrets
