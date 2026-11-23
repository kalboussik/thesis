"""k-sweep tuning study for the stage-1 behavioral profiler (manuscript Eq. 4).

Trains ONE federated model for a chosen config, then re-evaluates the two-stage
pipeline across a range of sensitivity values k. Calibration note: the operating
point should be chosen on VALIDATION, not test — this script reports both so the
choice is honest. Produces results/ksweep_<config>.csv and prints the table.

Usage:
  python k_sweep.py --partition noniid --clients 10 --seed 0
"""
import numpy as np
import os, json, argparse
import tensorflow as tf
import config as C
from model import build_lstm_cnn, reshape_seq, BenignProfiler
from metrics import two_stage_predict
from manual_fedavg import run as train_run   # reuse training
from sklearn.metrics import f1_score, accuracy_score

K_GRID = [0.5, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0]


def eval_profiler_at_k(profiler, clf, X, y, benign_label):
    y_pred, offload = two_stage_predict(profiler, clf, X, benign_label)
    passed = profiler.passes_as_benign(X)
    attacks = y != benign_label
    leak = float((passed & attacks).sum() / max(1, attacks.sum()))
    bgr = float((passed & ~attacks).sum() / max(1, (~attacks).sum()))
    return {
        "offload": float(offload),
        "attack_leakage": leak,
        "benign_gate_recall": bgr,
        "two_stage_macro_f1": float(f1_score(y, y_pred, average="macro", zero_division=0)),
        "two_stage_accuracy": float(accuracy_score(y, y_pred)),
    }


def main(partition, clients, seed, alpha=0.05, window=64):
    # train once (writes the model results); we re-load data + rebuild model
    print(">>> training base model (reuses manual_fedavg) ...")
    # Easiest robust path: retrain and keep the in-memory model via a light hook.
    # Here we re-run training and then reconstruct from saved best weights is not
    # exposed, so we retrain a fresh model deterministically for the sweep.
    d = np.load(os.path.join(C.PROC_DIR, "toniot_5class.npz"))
    benign_label = C.CLASSES.index("benign")

    # train via the same routine, then reload its saved full json to get metrics;
    # for the sweep we need the model object, so retrain inline (deterministic).
    from manual_fedavg import fedavg
    tf.keras.utils.set_random_seed(seed)
    X_train, y_train = d["X_train"], d["y_train"]
    X_val, y_val = d["X_val"], d["y_val"]
    X_test, y_test = d["X_test"], d["y_test"]
    n_features, n_classes = X_train.shape[1], len(C.CLASSES)
    parts = np.load(os.path.join(C.PART_DIR, f"{partition}_n{clients}_s{seed}.npz"))
    client_idx = [parts[f"client_{i}"] for i in range(clients)]

    gm = build_lstm_cnn(n_features, n_classes); gw = gm.get_weights()
    best_f1, best_w, patience = -1, None, 0
    Xv = reshape_seq(X_val)
    for rnd in range(1, C.NUM_ROUNDS + 1):
        lw, cnt = [], []
        for idx in client_idx:
            if len(idx) == 0: continue
            cm = build_lstm_cnn(n_features, n_classes); cm.set_weights(gw)
            cm.fit(reshape_seq(X_train[idx]), y_train[idx],
                   epochs=C.LOCAL_EPOCHS, batch_size=C.BATCH_SIZE, verbose=0)
            lw.append(cm.get_weights()); cnt.append(len(idx))
            tf.keras.backend.clear_session()
        gw = fedavg(lw, cnt); gm.set_weights(gw)
        vf1 = f1_score(y_val, gm.predict(Xv, verbose=0).argmax(1),
                       average="macro", zero_division=0)
        if vf1 > best_f1: best_f1, best_w, patience = vf1, [w.copy() for w in gw], 0
        else:
            patience += 1
            if patience >= C.EARLY_STOP_PATIENCE: break
    gm.set_weights(best_w)
    print(f">>> base model ready (val macroF1={best_f1:.3f}); sweeping k ...")

    rows = []
    for k in K_GRID:
        prof = BenignProfiler(k=k, alpha=alpha, window=window).fit(
            X_train, y_train, benign_label=benign_label)
        val = eval_profiler_at_k(prof, gm, X_val, y_val, benign_label)
        tst = eval_profiler_at_k(prof, gm, X_test, y_test, benign_label)
        rows.append({"k": k, "val": val, "test": tst})
        print(f"k={k:<4} | VAL off={val['offload']:.3f} leak={val['attack_leakage']:.3f} "
              f"2sF1={val['two_stage_macro_f1']:.3f} | TEST off={tst['offload']:.3f} "
              f"leak={tst['attack_leakage']:.3f} 2sF1={tst['two_stage_macro_f1']:.3f}")

    out = os.path.join(C.RESULTS, f"ksweep_{partition}_n{clients}_s{seed}.json")
    json.dump({"config": f"{partition}_n{clients}_s{seed}",
               "classifier_only_macro_f1": best_f1, "rows": rows},
              open(out, "w"), indent=2)
    print(">>> saved", out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--partition", default="noniid", choices=C.PARTITIONS)
    ap.add_argument("--clients", type=int, default=10)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    main(a.partition, a.clients, a.seed)
