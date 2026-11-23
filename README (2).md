# Distributed IoT Intrusion Detection — Experimental Code

Experimental code accompanying the PhD thesis *"A new approach to intelligent
intrusion detection in an IoT context based on mobile agents and blockchain"*
(UPHF / LAMIH). The repository groups the two experimental kits used in the
evaluation chapters.

## Repository layout

| Directory | What it is | Thesis chapter |
|-----------|-----------|----------------|
| `fl-ids-bench/` | Federated-learning IDS benchmark: data preparation, non-IID/IID partitioning, LSTM-1DCNN classifier, behavioural profiler, manual FedAvg + Flower cross-check, k-sweep, cross-dataset (Bot-IoT/ADASYN) | Detection evaluation (Ch. 6) |
| `ids-blockchain-bench/` | Hyperledger Fabric chaincode (agent registry, alert anchoring, reputation) + Hyperledger Caliper benchmark workloads | Coordination/blockchain evaluation (Ch. 6) |

Each kit has its own `README.md` with detailed run instructions.

## Datasets

The experiments use **public** datasets, which are **not** redistributed here:

- **ToN-IoT** (`Train_Test_Network.csv`) — reduced to 5 classes: benign,
  bruteforce, ddos, dos, portscan.
- **Bot-IoT** (5% version) — used binary (benign vs attack) as a cross-dataset check.

Download them from their official sources and set the paths as described in
`fl-ids-bench/README.md`.

## Quick start

```bash
# Federated-learning IDS benchmark (Python)
cd fl-ids-bench
pip install -r requirements.txt
bash run_all.sh

# Blockchain benchmark (Node.js + Hyperledger Fabric + Caliper)
cd ids-blockchain-bench
bash scripts/setup.sh
bash scripts/run-benchmark.sh
```

## Reproducibility notes

- Federated runs use fixed random seeds; non-IID partitioning uses a Dirichlet
  law (concentration alpha = 0.5). Results are reported as mean +/- std over seeds.
- The blockchain benchmark reports latency/throughput over 10 repetitions.

## License

Released under the MIT License — see `LICENSE`.
