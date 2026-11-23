"""Manual FedAvg — a transparent, framework-free reference implementation.

For one (partition, n_clients, seed): builds a global LSTM-CNN, runs NUM_ROUNDS
of {distribute -> local train 1 epoch -> sample-weighted average}, early-stops on
global-val macro-F1, fits the stage-1 profiler on the global benign training
data, then evaluates the two-stage system on the held-out test set.

Each round, every client's local update is hashed and recorded (the on-chain
coordination workload measured separately with Caliper).
"""
import numpy as np
import os, json, argparse, time
import tensorflow as tf
import config as C
from model import build_lstm_cnn, reshape_seq, BenignProfiler
from metrics import evaluate, record_update_hash, hash_weights
from sklearn.metrics import f1_score


def fedavg(weight_list, sample_counts):
    total = float(sum(sample_counts))
    avg = [np.zeros_like(w) for w in weight_list[0]]
    for w, n in zip(weight_list, sample_counts):
        for i in range(len(avg)):
            avg[i] += (n / total) * w[i]
    return avg


def run(partition, n_clients, seed):
    tf.keras.utils.set_random_seed(seed)
    d = np.load(os.path.join(C.PROC_DIR, "toniot_5class.npz"))
    X_train, y_train = d["X_train"], d["y_train"]
    X_val, y_val = d["X_val"], d["y_val"]
    X_test, y_test = d["X_test"], d["y_test"]
    n_features, n_classes = X_train.shape[1], len(C.CLASSES)

    parts = np.load(os.path.join(C.PART_DIR, f"{partition}_n{n_clients}_s{seed}.npz"))
    client_idx = [parts[f"client_{i}"] for i in range(n_clients)]

    tag = f"manual_{partition}_n{n_clients}_s{seed}"
    hash_path = os.path.join(C.RESULTS, f"{tag}_update_hashes.jsonl")
    open(hash_path, "w").close()

    global_model = build_lstm_cnn(n_features, n_classes)
    global_w = global_model.get_weights()

    best_f1, best_w, patience = -1.0, None, 0
    history = []
    Xv = reshape_seq(X_val)

    for rnd in range(1, C.NUM_ROUNDS + 1):
        local_w, counts = [], []
        for cid, idx in enumerate(client_idx):
            if len(idx) == 0:
                continue
            cm = build_lstm_cnn(n_features, n_classes)
            cm.set_weights(global_w)
            steps = getattr(C, "LOCAL_STEPS", None)
            cm.fit(reshape_seq(X_train[idx]), y_train[idx],
                   epochs=C.LOCAL_EPOCHS, steps_per_epoch=steps,
                   batch_size=C.BATCH_SIZE, verbose=0)
            w = cm.get_weights()
            local_w.append(w); counts.append(len(idx))
            record_update_hash(hash_path, rnd, f"client_{cid}", w, len(idx))
            tf.keras.backend.clear_session()

        global_w = fedavg(local_w, counts)
        global_model.set_weights(global_w)

        val_pred = global_model.predict(Xv, verbose=0).argmax(1)
        vf1 = f1_score(y_val, val_pred, average="macro", zero_division=0)
        history.append({"round": rnd, "val_macro_f1": float(vf1)})
        print(f"[{tag}] round {rnd:02d}/{C.NUM_ROUNDS}  val_macroF1={vf1:.4f}")

        if vf1 > best_f1:
            best_f1, best_w, patience = vf1, [w.copy() for w in global_w], 0
        else:
            patience += 1
            if patience >= C.EARLY_STOP_PATIENCE:
                print(f"[{tag}] early stop at round {rnd}")
                break

    global_model.set_weights(best_w)
    profiler = BenignProfiler(k=2.0, alpha=0.05, window=64).fit(
        X_train, y_train, benign_label=C.CLASSES.index("benign"),
        X_val=X_val, y_val=y_val)

    res = evaluate(profiler, global_model, X_test, y_test, tag, C.RESULTS)
    res["rounds_run"] = len(history)
    res["best_val_macro_f1"] = best_f1
    json.dump({"result": res, "history": history},
              open(os.path.join(C.RESULTS, f"{tag}_full.json"), "w"), indent=2)
    print(f"[{tag}] DONE  acc={res['accuracy']:.4f}  macroF1={res['macro_f1']:.4f}  "
          f"offload={res['profiler_offload_rate']:.3f}")
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--partition", required=True, choices=C.PARTITIONS)
    ap.add_argument("--clients", type=int, required=True)
    ap.add_argument("--seed", type=int, required=True)
    a = ap.parse_args()
    run(a.partition, a.clients, a.seed)
