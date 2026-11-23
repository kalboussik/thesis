# Federated two-stage IDS on ToN-IoT — experiment kit (Chapter 6, detection track)

Measured federated-learning detection results to replace the *estimated* numbers
in Chapter 6, and to establish the FL ↔ blockchain link: each FL round's
model-update hash is the on-chain coordination transaction whose **cost** you
already measured with Caliper. Run it, bring back `results/`, and the French
detection section gets written from your real numbers.

## Design (as agreed)

- **Dataset:** ToN-IoT `Train_Test_Network.csv` (per-flow tabular).
- **Labels:** collapsed to 5 classes — `benign, bruteforce, ddos, dos, portscan`
  (ToN-IoT `password`→bruteforce, `scanning`→portscan; `injection, xss,
  ransomware, backdoor, mitm` are **dropped**, documented in `processed/meta.json`).
- **Model:** the Chapter-5 LSTM-1DCNN, reused unchanged, with the lightweight
  **stage-1 benign profiler** in front (two-stage detection).
- **Federation:** FedAvg, **simulated on one machine**.
- **Client sweep:** 5 → 10 → 20 clients.
- **Partitioning:** **non-IID** (Dirichlet, α = 0.5, fixed across the sweep) plus
  an **IID baseline** for comparison.
- **Implementations:** a transparent **manual FedAvg** loop *and* **Flower**, on
  identical deterministic partitions — an implementation-agreement check.
- **Repetitions:** 3 seeds → mean ± std.

## Requirements

- **Python 3.10 or 3.11** (TensorFlow 2.15 does not support 3.12+).
- A virtual environment is strongly recommended:

```bash
python3.11 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Get the data

Download ToN-IoT's processed network CSV (`Train_Test_Network.csv`) from the
official UNSW ToN-IoT distribution and place it at `data/Train_Test_Network.csv`,
or point the kit at it:

```bash
export TONIOT_CSV=/path/to/Train_Test_Network.csv
```

## Run everything

```bash
chmod +x run_all.sh
./run_all.sh
```

This runs: data prep → partitioning → manual sweep → Flower sweep → aggregation.
On a CPU machine the full sweep (2 implementations × 2 partitions × 3 client
counts × 3 seeds = 36 runs × up to 50 rounds) takes a while; see "Time" below.

### Run a single configuration

```bash
cd src
python data_prep.py            # once
python partition.py            # once
python manual_fedavg.py --partition noniid --clients 10 --seed 0
python flower_sim.py   --partition noniid --clients 10 --seed 0
python aggregate.py
```

## What you get (bring this back to me)

Under `results/`:
- `summary_table.csv` — accuracy / macro-F1 / profiler-offload, **mean ± std**
  over seeds, for every (implementation, partition, client-count).
- `manual_vs_flower.csv` — the implementation-agreement check (|Δ macro-F1|).
- `*_full.json` — per run: per-class precision/recall/F1, confusion matrix,
  convergence history, rounds-to-early-stop.
- `*_update_hashes.jsonl` — per round, per client: the SHA-256 model-update hash
  = the on-chain coordination workload (links to the Caliper-measured cost).

Zip `results/` and upload it.

## Time / resource notes

- Each run early-stops (patience 8 on global-val macro-F1), so most runs finish
  well before 50 rounds.
- If the full 36-run sweep is too long, run the **manual** loop only first
  (`run_all.sh` step 2) — it alone produces every detection number needed. Flower
  is the secondary cross-check; if its simulation engine gives version trouble
  (it depends on `ray`), the manual results stand on their own and we note the
  cross-check as future work.
- CPU is fine. A GPU (set `client_resources` num_gpus) speeds Flower up.

## How this connects to the blockchain chapter

The federation emits one model update per client per round. Its integrity hash
(`results/*_update_hashes.jsonl`) is exactly what an agent anchors on-chain via
the `submitAlert`/coordination chaincode. So the **detection quality** comes from
this experiment and the **coordination cost** from the Caliper benchmark — two
measured halves of one system. State this explicitly in §6 so the FL and
blockchain layers read as integrated, not bolted together.

## Files

```
src/
  config.py          # all knobs (sweep, alpha, rounds, seeds, label map)
  data_prep.py       # ToN-IoT load, collapse, encode, scale, split
  partition.py       # deterministic Dirichlet non-IID + IID partitions
  model.py           # LSTM-CNN (Ch5) + BenignProfiler (stage 1)
  manual_fedavg.py   # transparent reference FedAvg
  flower_sim.py      # Flower simulation (same partitions/model)
  metrics.py         # two-stage eval, confusion matrix, update hashing
  aggregate.py       # builds the summary/comparison CSVs
requirements.txt
run_all.sh
```
