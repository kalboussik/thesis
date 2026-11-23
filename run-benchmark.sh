#!/usr/bin/env bash
# =====================================================================
# run-benchmark.sh — runs the Caliper benchmark N times (for variance /
# confidence intervals) and snapshots ledger size before/after so you
# can report ledger growth. Produces one HTML + one CSV-friendly log
# per repetition under results/.
# =====================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPS="${1:-10}"                      # number of repetitions (default 10)
RESULTS="${REPO_ROOT}/results"
mkdir -p "${RESULTS}"

cd "${REPO_ROOT}/caliper"
if [ ! -d node_modules ]; then
  echo ">>> Installing Caliper 0.6 + Fabric 2.5 bindings"
  npm install
  npx caliper bind --caliper-bind-sut fabric:2.5
fi

ledger_size_bytes () {
  # sum the on-disk ledger block files inside the peer container
  docker exec peer0.org1.example.com \
    sh -c "du -sb /var/hyperledger/production/ledgersData/chains 2>/dev/null | cut -f1" 2>/dev/null || echo "NA"
}

echo "rep,ledger_before_bytes,ledger_after_bytes,ledger_delta_bytes" > "${RESULTS}/ledger_growth.csv"

for r in $(seq 1 "${REPS}"); do
  echo ">>> ===== Repetition ${r}/${REPS} ====="
  BEFORE="$(ledger_size_bytes)"

  npx caliper launch manager \
    --caliper-workspace . \
    --caliper-networkconfig networks/networkConfig.yaml \
    --caliper-benchconfig benchmarks/idsBenchmark.yaml \
    --caliper-report-path "${RESULTS}/report_rep${r}.html" \
    --caliper-flow-only-test

  AFTER="$(ledger_size_bytes)"
  if [ "${BEFORE}" != "NA" ] && [ "${AFTER}" != "NA" ]; then
    DELTA=$(( AFTER - BEFORE ))
  else
    DELTA="NA"
  fi
  echo "${r},${BEFORE},${AFTER},${DELTA}" >> "${RESULTS}/ledger_growth.csv"
  echo ">>> rep ${r}: ledger delta = ${DELTA} bytes"
done

echo ""
echo "================================================================"
echo " Done. ${REPS} repetitions."
echo "   HTML reports : results/report_rep*.html"
echo "   Ledger growth: results/ledger_growth.csv"
echo ""
echo " Each HTML report contains, per round (per function & TPS):"
echo "   - Throughput (TPS)        - Send rate"
echo "   - Avg / Min / Max latency - p95 latency (in the detail table)"
echo "   - Success / Fail counts   - Resource use (CPU/mem) from docker monitor"
echo ""
echo " Bring me results/ (HTML + CSV) and I'll build the French chapter."
echo "================================================================"
