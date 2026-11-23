#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TN="${REPO_ROOT}/.fabric/fabric-samples/test-network"
if [ -d "${TN}" ]; then ( cd "${TN}" && ./network.sh down ); fi
echo "network down."
