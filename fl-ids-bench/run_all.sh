#!/usr/bin/env bash
# Orchestrates the full FL-IDS experiment: data prep -> partition ->
# sweep over {manual, flower} x {noniid, iid} x {5,10,20 clients} x seeds.
set -euo pipefail
cd "$(dirname "$0")/src"

echo ">>> [0] data preparation (run once)"
python data_prep.py
echo ">>> [1] partitioning"
python partition.py

CLIENTS=(5 10 20)
PARTS=(noniid iid)
SEEDS=(0 1 2)

echo ">>> [2] manual FedAvg sweep"
for p in "${PARTS[@]}"; do for n in "${CLIENTS[@]}"; do for s in "${SEEDS[@]}"; do
  echo "    manual  part=$p clients=$n seed=$s"
  python manual_fedavg.py --partition "$p" --clients "$n" --seed "$s"
done; done; done

echo ">>> [3] Flower sweep"
for p in "${PARTS[@]}"; do for n in "${CLIENTS[@]}"; do for s in "${SEEDS[@]}"; do
  echo "    flower  part=$p clients=$n seed=$s"
  python flower_sim.py --partition "$p" --clients "$n" --seed "$s"
done; done; done

echo ">>> [4] aggregate"
python aggregate.py
echo ">>> DONE — see results/ (summary_table.csv, manual_vs_flower.csv, *_full.json, *_update_hashes.jsonl)"
