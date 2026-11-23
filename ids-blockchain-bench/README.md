# IDS Coordination Ledger — Hyperledger Fabric 2.5 + Caliper 0.6 benchmark

Turnkey scaffold to **implement and measure** the permissioned blockchain
coordination layer for the distributed multi-agent IoT IDS (thesis Chapter 6).
Run it, then hand the `results/` folder back and the French chapter gets
written from your **real** numbers.

This replaces the previously *estimated* figures (tx/day, validation latency,
ledger growth, CPU) with measured ones — the methodological standard set by
Marwa's Ganache/Web3 benchmark, transposed to your permissioned Fabric design.

---

## 0. Attack taxonomy used here

Four classes (router-level capture; Wi-Fi deauth and ARP-MITM removed because
they are layer-2 and not visible in your PCAPs):

`dos`, `ddos`, `portscan`, `bruteforce`

---

## 1. Prerequisites (install once)

- Docker + Docker Compose (running daemon)
- **Node.js 18.x** — Caliper 0.6 requires Node 18; do **not** use 20+
- `git`, `curl`, `jq`
- ~8 GB free RAM, Linux or macOS (your i7-12700K box is ideal)

Check:
```bash
node -v      # v18.x
docker info  # daemon up
```

## 2. Bring up Fabric + deploy the chaincode

```bash
cd ids-blockchain-bench
chmod +x scripts/*.sh
./scripts/setup.sh
```
This fetches fabric-samples v2.5.9, starts a 2-org network with a Raft orderer
and **CouchDB** state DB, creates `mychannel`, deploys the `idsledger`
chaincode (JavaScript), and renders `caliper/networks/networkConfig.yaml` with
the correct identity paths automatically.

## 3. Run the benchmark (with repetitions for variance)

```bash
./scripts/run-benchmark.sh 10      # 10 repetitions -> mean ± std / 95% CI
```
First run auto-installs Caliper and binds the Fabric 2.5 SUT. Each repetition
sweeps every smart-contract function across multiple offered-load points.

## 4. What you get (and bring back to me)

Under `results/`:
- `report_rep1.html … report_rep10.html` — per round (function × TPS):
  **throughput, avg/min/max latency, p95 latency, success/fail counts**, and
  **CPU/memory** per container (from the docker resource monitor).
- `ledger_growth.csv` — on-disk ledger bytes before/after each repetition →
  your **ledger growth rate** (KB/day once scaled by the load model).

Send me the whole `results/` folder (HTML + CSV). That is everything I need to
write the measurement tables and analysis in French.

## 5. Tear down

```bash
./scripts/teardown.sh
```

---

## How the load maps to your IoT IDS (state this in the chapter)

See `caliper/workload/loadModel.js`. Offered alert load is derived from an
explicit model: window `W = 30 s`, peak attack fraction `p_attack = 0.20`, so a
network of `N` nodes generates `N·p_attack/W` confirmed-alert tx/s at the
nominal operating point (e.g. ~0.67 tx/s for N=100). The benchmark deliberately
sweeps **well above** that (10→100 TPS) to produce a full latency-vs-load curve
and locate the saturation point — exactly the kind of curve in Marwa's
Tables 4.2/4.3.

To produce a **scalability table by network size** (matching your 10/25/50/75/100
simulation points), map each `N` to its nominal TPS via `alertTpsForNetwork(N)`
and add those as extra `submitAlert` rounds, or run the suite once per `N`.

## Notes / knobs

- `caliper/benchmarks/idsBenchmark.yaml` — edit `workers.number`, `txDuration`,
  and the `tps` points to taste. The `updateReputation` round currently reuses
  the validateAlert seeding module for convenience; if you want a dedicated
  reputation workload, copy `validateAlert.js` to `updateReputation.js` and
  change the `contractFunction` to `updateReputation` with args
  `[agentID, 'true']`.
- CouchDB is used so ledger growth is realistic and queryable; LevelDB would be
  smaller/faster but less representative.
- Determinism: the chaincode uses the transaction timestamp (not `Date.now()`),
  so endorsements never diverge.

## Files

```
chaincode/idsledger/
  index.js
  package.json
  lib/idsContract.js        # the 5 functions
caliper/
  package.json
  networks/networkConfig.template.yaml
  benchmarks/idsBenchmark.yaml
  workload/loadModel.js      # load assumptions (document these)
  workload/registerAgent.js
  workload/submitAlert.js
  workload/validateAlert.js
  workload/queryHistory.js
scripts/
  setup.sh                   # bring up + deploy + wire config
  run-benchmark.sh           # run N reps + capture ledger growth
  teardown.sh
```
