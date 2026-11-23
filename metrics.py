"""Evaluation utilities: two-stage (profiler -> classifier) metrics, confusion
matrix, and the model-update hashing that bridges FL to the blockchain layer.
"""
import numpy as np
import hashlib, json, os, time
from sklearn.metrics import (classification_report, confusion_matrix,
                             f1_score, accuracy_score)
import config as C
from model import reshape_seq


def two_stage_predict(profiler, clf, X, benign_label=0):
    """Stage 1: profiler passes obvious-benign flows. Stage 2: LSTM-CNN labels
    the rest. Returns predictions + the fraction offloaded by the profiler."""
    y_pred = np.full(X.shape[0], benign_label, dtype=np.int64)
    benign_mask = profiler.passes_as_benign(X)
    forward = ~benign_mask
    if forward.any():
        probs = clf.predict(reshape_seq(X[forward]), verbose=0)
        y_pred[forward] = probs.argmax(axis=1)
    offload_rate = float(benign_mask.mean())
    return y_pred, offload_rate


def evaluate(profiler, clf, X_test, y_test, tag, out_dir):
    # --- two-stage (profiler + classifier) ---
    y_pred, offload = two_stage_predict(profiler, clf, X_test)
    rep = classification_report(y_test, y_pred, target_names=C.CLASSES,
                                output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=list(range(len(C.CLASSES))))

    # --- classifier-only (true detection performance on the full test set) ---
    co_pred = clf.predict(reshape_seq(X_test), verbose=0).argmax(axis=1)
    co_rep = classification_report(y_test, co_pred, target_names=C.CLASSES,
                                   output_dict=True, zero_division=0)
    co_cm = confusion_matrix(y_test, co_pred, labels=list(range(len(C.CLASSES))))

    # --- profiler safety: attack leakage (attacks wrongly finalized benign) ---
    benign = C.CLASSES.index("benign")
    passed = profiler.passes_as_benign(X_test)
    attacks = y_test != benign
    attack_leakage = float((passed & attacks).sum() / max(1, attacks.sum()))
    benign_recall_gate = float((passed & ~attacks).sum() / max(1, (~attacks).sum()))

    res = {
        "tag": tag,
        # headline = classifier-only detection performance
        "accuracy": float(accuracy_score(y_test, co_pred)),
        "macro_f1": float(f1_score(y_test, co_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_test, co_pred, average="weighted", zero_division=0)),
        "per_class": {c: {"precision": co_rep[c]["precision"],
                          "recall": co_rep[c]["recall"],
                          "f1": co_rep[c]["f1-score"],
                          "support": co_rep[c]["support"]} for c in C.CLASSES},
        "confusion_matrix": co_cm.tolist(),
        # two-stage pipeline (efficiency view) + profiler safety metrics
        "two_stage": {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "macro_f1": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
            "profiler_offload_rate": offload,
            "attack_leakage_rate": attack_leakage,     # want LOW
            "benign_gate_recall": benign_recall_gate,  # ~ target (0.95)
            "confusion_matrix": cm.tolist(),
        },
        "profiler_offload_rate": offload,
    }
    os.makedirs(out_dir, exist_ok=True)
    json.dump(res, open(os.path.join(out_dir, f"{tag}.json"), "w"), indent=2)
    return res


# ---- FL <-> blockchain bridge -------------------------------------------

def hash_weights(weights):
    """SHA-256 over the concatenated, rounded weight arrays — the integrity
    marker an agent would anchor on-chain via submitAlert/coordination."""
    h = hashlib.sha256()
    for w in weights:
        h.update(np.asarray(w, dtype=np.float32).tobytes())
    return h.hexdigest()


def record_update_hash(jsonl_path, rnd, client_id, weights, n_samples):
    """Append one model-update integrity record. The stream of these records IS
    the on-chain coordination workload whose cost was measured with Caliper:
    each entry corresponds to one submitAlert-class transaction."""
    rec = {
        "round": int(rnd),
        "client": client_id,
        "n_samples": int(n_samples),
        "update_hash": hash_weights(weights),
        "ts": time.time(),
    }
    with open(jsonl_path, "a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec
