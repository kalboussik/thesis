#!/usr/bin/env bash
# =====================================================================
# setup.sh — brings up Fabric 2.5 test-network, deploys the idsledger
# chaincode, and wires the Caliper network config to the generated
# crypto material. Run from the repo root.
#
# Prereqs (install once):
#   - Docker + Docker Compose
#   - Node.js 18.x  (Caliper 0.6 requires Node 18; NOT 20+)
#   - jq, curl, git
# =====================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${REPO_ROOT}/.fabric"
FABRIC_VERSION="2.5.9"
CA_VERSION="1.5.12"

echo ">>> [1/5] Fetching fabric-samples + binaries (v${FABRIC_VERSION})"
mkdir -p "${WORK}"
cd "${WORK}"
if [ ! -d fabric-samples ]; then
  curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh
  chmod +x install-fabric.sh
  ./install-fabric.sh --fabric-version "${FABRIC_VERSION}" --ca-version "${CA_VERSION}" binary samples
fi

TN="${WORK}/fabric-samples/test-network"
export PATH="${WORK}/fabric-samples/bin:${PATH}"
export FABRIC_CFG_PATH="${WORK}/fabric-samples/config"

echo ">>> [2/5] Starting test-network with CA + creating channel 'mychannel'"
cd "${TN}"
./network.sh down || true
./network.sh up createChannel -ca -c mychannel -s couchdb

echo ">>> [3/5] Deploying idsledger chaincode"
./network.sh deployCC \
  -ccn idsledger \
  -ccp "${REPO_ROOT}/chaincode/idsledger" \
  -ccl javascript \
  -c mychannel

echo ">>> [4/5] Copying Org1 connection profile for Caliper"
CCP_SRC="${TN}/organizations/peerOrganizations/org1.example.com/connection-org1.yaml"
cp "${CCP_SRC}" "${REPO_ROOT}/caliper/networks/org1ccp.yaml"

echo ">>> [5/5] Resolving User1 identity paths and rendering networkConfig.yaml"
USERMSP="${TN}/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp"
KEY_FILE="$(ls "${USERMSP}/keystore/"*_sk 2>/dev/null | head -n1 || ls "${USERMSP}/keystore/" | head -n1)"
KEY_PATH="${USERMSP}/keystore/$(basename "${KEY_FILE}")"
CERT_PATH="${USERMSP}/signcerts/$(ls "${USERMSP}/signcerts/" | head -n1)"

sed -e "s#__ORG1_KEY__#${KEY_PATH}#" \
    -e "s#__ORG1_CERT__#${CERT_PATH}#" \
    "${REPO_ROOT}/caliper/networks/networkConfig.template.yaml" \
    > "${REPO_ROOT}/caliper/networks/networkConfig.yaml"

echo ""
echo "================================================================"
echo " Setup complete."
echo "   Channel:    mychannel"
echo "   Chaincode:  idsledger (javascript)"
echo "   State DB:   CouchDB (so you can measure ledger growth)"
echo "   Net config: caliper/networks/networkConfig.yaml"
echo ""
echo " Next:  ./scripts/run-benchmark.sh"
echo "================================================================"
