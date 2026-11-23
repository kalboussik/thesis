"""Stage 1 — partition the training set across federated clients.

Produces DETERMINISTIC partitions (seeded) so the manual FedAvg loop and Flower
operate on identical splits — essential for a valid implementation comparison.

- non-IID: Dirichlet(alpha) over classes per client (fixed alpha across the
  5/10/20 sweep for fairness). Low alpha => more skew.
- iid: uniform random shard of equal size.

Saves one index file per (partition, n_clients, seed) under partitions/.
"""
import numpy as np
import os, json
import config as C


def dirichlet_partition(y, n_clients, alpha, rng):
    """Return list of index arrays, one per client, with class proportions
    drawn from a Dirichlet distribution (classic non-IID FL setup)."""
    n_classes = len(C.CLASSES)
    idx_by_class = [np.where(y == k)[0] for k in range(n_classes)]
    for a in idx_by_class:
        rng.shuffle(a)
    client_idx = [[] for _ in range(n_clients)]
    for k in range(n_classes):
        if len(idx_by_class[k]) == 0:
            continue
        props = rng.dirichlet([alpha] * n_clients)
        # cut points along this class's samples according to proportions
        cuts = (np.cumsum(props) * len(idx_by_class[k])).astype(int)[:-1]
        splits = np.split(idx_by_class[k], cuts)
        for c in range(n_clients):
            client_idx[c].extend(splits[c].tolist())
    return [np.array(sorted(ci), dtype=np.int64) for ci in client_idx]


def iid_partition(y, n_clients, rng):
    idx = np.arange(len(y))
    rng.shuffle(idx)
    return [np.array(sorted(s), dtype=np.int64) for s in np.array_split(idx, n_clients)]


def main():
    d = np.load(os.path.join(C.PROC_DIR, "toniot_5class.npz"))
    y = d["y_train"]

    summary = {}
    for part in C.PARTITIONS:
        for n in C.CLIENT_COUNTS:
            for seed in C.SEEDS:
                rng = np.random.default_rng(seed)
                if part == "noniid":
                    parts = dirichlet_partition(y, n, C.DIRICHLET_ALPHA, rng)
                else:
                    parts = iid_partition(y, n, rng)

                fn = os.path.join(C.PART_DIR, f"{part}_n{n}_s{seed}.npz")
                np.savez_compressed(fn, **{f"client_{i}": parts[i] for i in range(n)})

                # record per-client class composition for the chapter (skew evidence)
                comp = []
                for i in range(n):
                    yi = y[parts[i]]
                    comp.append({C.CLASSES[k]: int((yi == k).sum()) for k in range(len(C.CLASSES))})
                summary[f"{part}_n{n}_s{seed}"] = {
                    "client_sizes": [int(len(p)) for p in parts],
                    "class_composition": comp,
                }
    json.dump(summary, open(os.path.join(C.PART_DIR, "partition_summary.json"), "w"), indent=2)
    print(">>> partitions written to", C.PART_DIR)
    print(">>> alpha =", C.DIRICHLET_ALPHA, "| clients =", C.CLIENT_COUNTS, "| seeds =", C.SEEDS)


if __name__ == "__main__":
    main()
