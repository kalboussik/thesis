#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_adasyn_ram.py
====================

Two checks on the Chapter 5 results of the thesis
("A new approach to intelligent intrusion detection in an IoT context ...").

  1. LEAKAGE  - Is the ADASYN protocol inflating the test scores?
                Trains the same CNN-LSTM under 4 protocols and evaluates each
                on its own test set:
                  P0  no oversampling                     (random split)
                  P1  ADASYN on the WHOLE dataset, then split   <- thesis §5.3.2 / §5.4.4
                  P2  split, then ADASYN on TRAIN only    (correct, random split)
                  P3  temporal split, then ADASYN on TRAIN only (correct, time-ordered)
                For P1, the test set is also scored separately on its REAL rows
                and its SYNTHETIC rows, and the distance of each test row to the
                nearest training row is reported (synthetic rows are interpolations
                of training rows -> they sit much closer to the training set).
                Also checks whether FPR == 1 - accuracy (the pattern seen in Table 5.4).

  2. RAM      - Where does the RAM gap of Table 5.5 come from?
                Each configuration runs in a FRESH subprocess with the same model
                and the same data loaded, and the peak RSS during inference is sampled:
                  batch_full          whole test set in one predict() call   (thesis "static")
                  batch_full_adasyn   same, test set enlarged by ADASYN       (thesis "static + ADASYN")
                  stream_no_profiler  one 20 s window per node at a time, ALL windows classified
                  stream_profiler     same, but only out-of-profile windows classified (thesis "real-time")
                If stream_no_profiler ~= stream_profiler, the gap is caused by
                batch-vs-streaming, not by the profiler (what §5.3.5 says).
                The streaming runs also give window-level shedding / leakage / TPR / FPR,
                and compare the MEASURED two-stage FPR/TPR with the value obtained by
                simply multiplying profiler rates x classifier rates (Table 5.2 check).

Usage
-----
  pip install "tensorflow==2.8.*" imbalanced-learn psutil pandas scikit-learn
  (optional, for GPU utilisation:  pip install pynvml)

  # quick smoke test on synthetic data (no dataset needed)
  python verify_adasyn_ram.py demo

  # real data (ToN-IoT network CSVs). Start small, then increase --max-rows.
  python verify_adasyn_ram.py all --data "/path/ToN-IoT/Network_dataset_*.csv" --max-rows 2000000
  python verify_adasyn_ram.py leakage --data "..." --max-rows 1000000 --epochs 10
  python verify_adasyn_ram.py ram     --data "..." --max-rows 2000000

  # use YOUR exact architecture: a .py file defining build_model(n_features, n_classes)
  python verify_adasyn_ram.py all --data "..." --model-module my_model.py

Outputs: printed tables + results_<mode>.json in --out (default ./verify_out).

Notes
-----
* --max-rows reads the FIRST rows of the files in timestamp order (keeps time order,
  needed for P3 and for the streaming/profiler runs). --frac draws a random sample
  instead (like the "5% of ToN-IoT" of Table 5.1) - fine for P0-P2, NOT for P3/RAM.
* The profiler here re-implements Eqs. 5.1-5.2 as described in the manuscript and on
  slide 34 (V = (dst, src, proto, Np), PI = sum V_i.V_{i+1}, Delta = |nPI-oPI|/|oPI|*100).
  If your implementation differs, replace the function `profile_index_for_window`.
* TensorFlow grabs all GPU memory by default; memory growth is enabled here so that
  GPU memory numbers mean something.
"""

import argparse
import glob
import importlib.util
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

import numpy as np
import pandas as pd

SEED = 42
WINDOW_S = 20.0
THRESH_PCT = 10.0

# Fields removed in the thesis preprocessing (§5.3.2) + label columns
DROP_COLS = ["dns_query", "ssl_subject", "ssl_issuer", "http_uri", "http_user_agent",
             "http_orig_mime_types", "http_resp_mime_types", "weird_name", "weird_addl",
             "weird_notice", "type"]
IP_COLS = ["src_ip", "dst_ip"]


# --------------------------------------------------------------------------- utils
def log(msg):
    print(msg, flush=True)


def set_seeds(seed=SEED):
    import random
    random.seed(seed)
    np.random.seed(seed)
    try:
        import tensorflow as tf
        tf.random.set_seed(seed)
    except Exception:
        pass


def tf_quiet():
    os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
    import tensorflow as tf
    for g in tf.config.list_physical_devices("GPU"):
        try:
            tf.config.experimental.set_memory_growth(g, True)
        except Exception:
            pass
    return tf


def ip_to_int(series):
    """'192.168.1.33' -> 3232235809 (same coding as the thesis, netaddr-like)."""
    uniq = pd.unique(series.astype(str))
    mapping = {}
    for u in uniq:
        try:
            mapping[u] = int(ipaddress.ip_address(u.strip())) % (2 ** 53)  # keep float-exact
        except ValueError:
            mapping[u] = 0
    return series.astype(str).map(mapping).astype("float64")


# --------------------------------------------------------------------------- data
def make_demo_df(n_nodes=12, hours=10, seed=SEED):
    """Synthetic ToN-IoT-like flow table: periodic benign traffic per node + attack bursts."""
    rng = np.random.default_rng(seed)
    rows = []
    t_end = hours * 3600
    protos = ["tcp", "udp", "icmp"]
    services = ["-", "http", "dns", "mqtt"]
    for n in range(n_nodes):
        dst = "192.168.1.%d" % (10 + n)
        period = rng.uniform(5, 30)
        t = rng.uniform(0, period)
        while t < t_end:
            pk = max(1, int(rng.normal(8 + n, 2)))
            rows.append((t, "192.168.1.%d" % (100 + n % 3), int(rng.integers(1024, 65535)), dst,
                         [1883, 80, 53][n % 3], protos[n % 2], services[n % 4],
                         abs(rng.normal(0.5, 0.2)), pk * 60, pk * 40, pk, pk, 0))
            t += period * rng.uniform(0.8, 1.2)
    # attack bursts (DoS / scanning) on random nodes
    for _ in range(40):
        n = int(rng.integers(0, n_nodes))
        start = rng.uniform(0, t_end - 300)
        dur = rng.uniform(60, 240)
        k = int(rng.integers(150, 600))
        for t in np.sort(rng.uniform(start, start + dur, k)):
            pk = int(rng.integers(1, 4))
            rows.append((t, "10.0.0.%d" % rng.integers(2, 6), int(rng.integers(1024, 65535)),
                         "192.168.1.%d" % (10 + n), int(rng.integers(1, 1024)), "tcp", "-",
                         abs(rng.normal(0.01, 0.01)), pk * 40, 0, pk, 0, 1))
    df = pd.DataFrame(rows, columns=["ts", "src_ip", "src_port", "dst_ip", "dst_port", "proto",
                                     "service", "duration", "src_bytes", "dst_bytes",
                                     "src_pkts", "dst_pkts", "label"])
    return df.sort_values("ts").reset_index(drop=True)


def load_df(pattern, max_rows=None, frac=None, label_col="label", seed=SEED):
    files = sorted(glob.glob(pattern))
    if not files:
        sys.exit("No file matches --data %r" % pattern)
    log("Reading %d file(s) ..." % len(files))
    parts, n = [], 0
    for f in files:
        d = pd.read_csv(f, low_memory=False)
        parts.append(d)
        n += len(d)
        log("  %s : %d rows" % (os.path.basename(f), len(d)))
    df = pd.concat(parts, ignore_index=True)
    if label_col not in df.columns:
        sys.exit("Label column %r not found. Columns: %s" % (label_col, list(df.columns)))
    if "ts" in df.columns:
        df = df.sort_values("ts", kind="mergesort").reset_index(drop=True)
    if frac:
        df = df.sample(frac=frac, random_state=seed).reset_index(drop=True)
        log("Random sample frac=%.3f -> %d rows (TIME ORDER DESTROYED)" % (frac, len(df)))
    elif max_rows and len(df) > max_rows:
        df = df.iloc[:max_rows].reset_index(drop=True)
        log("First %d rows in timestamp order kept" % len(df))
    return df


def preprocess(df, label_col="label", drop_ids=False):
    """Thesis preprocessing (§5.3.2): IP -> int, categorical -> codes, drop fields.
    Returns X (DataFrame, unscaled), y, and side info for windows/profiler."""
    df = df.copy()
    y = pd.to_numeric(df[label_col], errors="coerce").fillna(0).astype(int).values
    y = (y > 0).astype(int)  # 1 = attack, 0 = benign
    side = pd.DataFrame({
        "ts": pd.to_numeric(df["ts"], errors="coerce").fillna(0).values if "ts" in df else np.arange(len(df), dtype=float),
        "node": df["dst_ip"].astype(str).values if "dst_ip" in df else np.zeros(len(df), dtype=str),
        "src": df["src_ip"].astype(str).values if "src_ip" in df else np.zeros(len(df), dtype=str),
        "proto": df["proto"].astype(str).values if "proto" in df else np.zeros(len(df), dtype=str),
    })
    pk = np.zeros(len(df))
    for c in ("src_pkts", "dst_pkts"):
        if c in df:
            pk += pd.to_numeric(df[c], errors="coerce").fillna(0).values
    side["npkts"] = np.where(pk > 0, pk, 1.0)

    df = df.drop(columns=[c for c in DROP_COLS + [label_col] if c in df.columns])
    for c in IP_COLS:
        if c in df:
            df[c] = ip_to_int(df[c])
    if drop_ids:  # optional: shortcut-free variant (no ts, IPs, ports)
        df = df.drop(columns=[c for c in ["ts", "src_ip", "dst_ip", "src_port", "dst_port"] if c in df])
    for c in df.columns:
        if not pd.api.types.is_numeric_dtype(df[c]):
            num = pd.to_numeric(df[c], errors="coerce")
            if num.notna().mean() > 0.99:
                df[c] = num
            else:
                df[c] = df[c].astype("category").cat.codes
    X = df.fillna(0).astype("float64")
    log("Features: %d  | rows: %d  | attack share: %.2f%%  | benign share: %.2f%%"
        % (X.shape[1], len(X), 100 * y.mean(), 100 * (1 - y.mean())))
    return X, y, side


# --------------------------------------------------------------------------- model
def default_build_model(n_features, n_classes=2):
    """CNN-LSTM close to Fig. 5.3 / slide 41. NB: the input is (n_features, 1), so the
    LSTM 'time steps' are FEATURE positions, not time - see jury question 4."""
    from tensorflow.keras import layers, models, optimizers
    m = models.Sequential([
        layers.Input(shape=(n_features, 1)),
        layers.Conv1D(64, 3, padding="same", activation="relu"),
        layers.MaxPooling1D(2, padding="same"),
        layers.Conv1D(64, 3, padding="same", activation="relu"),
        layers.MaxPooling1D(2, padding="same"),
        layers.LSTM(64, return_sequences=True),
        layers.LSTM(32),
        layers.Dense(64, activation="relu"),
        layers.Dropout(0.5),
        layers.Dense(n_classes, activation="softmax"),
    ])
    m.compile(optimizer=optimizers.Adam(1e-3), loss="sparse_categorical_crossentropy",
              metrics=["accuracy"])
    return m


def get_builder(model_module):
    if not model_module:
        return default_build_model
    spec = importlib.util.spec_from_file_location("user_model", model_module)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not hasattr(mod, "build_model"):
        sys.exit("%s must define build_model(n_features, n_classes)" % model_module)
    return mod.build_model


def fit(builder, Xtr, ytr, Xva, yva, epochs, batch=64, patience=10):
    tf = tf_quiet()
    set_seeds()
    m = builder(Xtr.shape[1], 2)
    cb = [tf.keras.callbacks.EarlyStopping(monitor="val_loss", patience=patience,
                                           restore_best_weights=True)]
    m.fit(Xtr[..., None], ytr, validation_data=(Xva[..., None], yva), epochs=epochs,
          batch_size=batch, callbacks=cb, verbose=2)
    return m


def predict(m, X, batch=4096):
    p = m.predict(X[..., None], batch_size=batch, verbose=0)
    return p.argmax(1) if p.shape[1] > 1 else (p[:, 0] > 0.5).astype(int)


# --------------------------------------------------------------------------- metrics
def metrics(y, yp):
    from sklearn.metrics import f1_score, matthews_corrcoef
    y, yp = np.asarray(y), np.asarray(yp)
    tp = int(((yp == 1) & (y == 1)).sum()); tn = int(((yp == 0) & (y == 0)).sum())
    fp = int(((yp == 1) & (y == 0)).sum()); fn = int(((yp == 0) & (y == 1)).sum())
    n = max(1, len(y))
    acc = (tp + tn) / n
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {
        "n": int(n), "attack_share": float(y.mean()) if len(y) else 0.0,
        "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "accuracy": acc, "precision": prec, "recall_TPR": rec, "FPR": fpr,
        "F1_attack": f1,
        "macro_F1": float(f1_score(y, yp, average="macro", zero_division=0)) if len(y) else 0.0,
        "balanced_acc": (rec + (1 - fpr)) / 2,
        "MCC": float(matthews_corrcoef(y, yp)) if len(np.unique(y)) > 1 else 0.0,
        "error_rate": 1 - acc,
    }


def fmt_row(name, r):
    return ("%-34s n=%-8d att=%5.1f%%  acc=%6.2f%%  prec=%6.2f%%  TPR=%6.2f%%  FPR=%6.2f%%  "
            "F1=%6.2f%%  mF1=%.3f  MCC=%.3f"
            % (name, r["n"], 100 * r["attack_share"], 100 * r["accuracy"], 100 * r["precision"],
               100 * r["recall_TPR"], 100 * r["FPR"], 100 * r["F1_attack"], r["macro_F1"], r["MCC"]))


# --------------------------------------------------------------------------- ADASYN
def adasyn(X, y, seed=SEED):
    """Returns resampled X, y and a boolean mask of synthetic rows.
    imblearn appends synthetic rows AFTER the original ones - verified below."""
    from imblearn.over_sampling import ADASYN, SMOTE
    n0 = len(X)
    try:
        Xr, yr = ADASYN(random_state=seed, n_neighbors=5).fit_resample(X, y)
    except RuntimeError as e:  # classes perfectly separable around minority points
        log("ADASYN refused (%s) -> falling back to SMOTE (same leakage mechanism)" % str(e)[:80])
        Xr, yr = SMOTE(random_state=seed, k_neighbors=5).fit_resample(X, y)
    Xr, yr = np.asarray(Xr), np.asarray(yr)
    if not np.allclose(Xr[:n0], X):
        raise RuntimeError("Unexpected ADASYN output order - cannot tag synthetic rows")
    syn = np.zeros(len(Xr), bool)
    syn[n0:] = True
    log("Oversampling: %d -> %d rows (+%d synthetic, class counts %s)"
        % (n0, len(Xr), syn.sum(), np.bincount(yr).tolist()))
    return Xr, yr, syn


def split_idx(n, y=None, stratify=True, temporal=False, seed=SEED, fr=(0.6, 0.2, 0.2)):
    from sklearn.model_selection import train_test_split
    idx = np.arange(n)
    if temporal:
        a, b = int(fr[0] * n), int((fr[0] + fr[1]) * n)
        return idx[:a], idx[a:b], idx[b:]
    st = y if stratify else None
    tr, rest = train_test_split(idx, train_size=fr[0], random_state=seed, stratify=st)
    st2 = y[rest] if stratify else None
    va, te = train_test_split(rest, test_size=fr[2] / (fr[1] + fr[2]), random_state=seed, stratify=st2)
    return tr, va, te


def nn_distance(Xref, Xq, max_ref=50000, max_q=5000, seed=SEED):
    from sklearn.neighbors import NearestNeighbors
    rng = np.random.default_rng(seed)
    if len(Xq) == 0:
        return float("nan")
    R = Xref[rng.choice(len(Xref), min(max_ref, len(Xref)), replace=False)]
    Q = Xq[rng.choice(len(Xq), min(max_q, len(Xq)), replace=False)]
    d, _ = NearestNeighbors(n_neighbors=1).fit(R).kneighbors(Q)
    return float(np.median(d[:, 0]))


# --------------------------------------------------------------------------- experiment 1
def run_leakage(X, y, side, builder, epochs, out):
    from sklearn.preprocessing import StandardScaler
    Xv = X.values
    res = {}

    # P0 - no oversampling
    log("\n=== P0: no oversampling (random stratified 60/20/20) ===")
    tr, va, te = split_idx(len(Xv), y)
    sc = StandardScaler().fit(Xv[tr])
    m = fit(builder, sc.transform(Xv[tr]), y[tr], sc.transform(Xv[va]), y[va], epochs)
    res["P0_no_oversampling"] = metrics(y[te], predict(m, sc.transform(Xv[te])))

    # P1 - thesis protocol: scale + ADASYN on everything, then split
    log("\n=== P1: ADASYN on the WHOLE dataset, then split (thesis protocol) ===")
    Xs = StandardScaler().fit_transform(Xv)
    Xr, yr, syn = adasyn(Xs, y)
    tr, va, te = split_idx(len(Xr), yr)
    m1 = fit(builder, Xr[tr], yr[tr], Xr[va], yr[va], epochs)
    yp = predict(m1, Xr[te])
    res["P1_leaky_full_test"] = metrics(yr[te], yp)
    real, synth = te[~syn[te]], te[syn[te]]
    res["P1_leaky_real_rows_only"] = metrics(yr[real], predict(m1, Xr[real]))
    res["P1_leaky_synthetic_rows_only"] = metrics(yr[synth], predict(m1, Xr[synth]))
    res["P1_share_of_test_that_is_synthetic"] = float(syn[te].mean())
    res["P1_median_NN_dist_to_train_real_test_rows"] = nn_distance(Xr[tr], Xr[real])
    res["P1_median_NN_dist_to_train_synthetic_test_rows"] = nn_distance(Xr[tr], Xr[synth])

    # P2 - correct, random split
    log("\n=== P2: split first, ADASYN on TRAIN only (random stratified) ===")
    tr, va, te = split_idx(len(Xv), y)
    sc = StandardScaler().fit(Xv[tr])
    Xtr, ytr, _ = adasyn(sc.transform(Xv[tr]), y[tr])
    m2 = fit(builder, Xtr, ytr, sc.transform(Xv[va]), y[va], epochs)
    res["P2_correct_random_split"] = metrics(y[te], predict(m2, sc.transform(Xv[te])))

    # P3 - correct, temporal split
    log("\n=== P3: temporal split 60/20/20, ADASYN on TRAIN only ===")
    order = np.argsort(side["ts"].values, kind="mergesort")
    tr, va, te = split_idx(len(Xv), temporal=True)
    tr, va, te = order[tr], order[va], order[te]
    for name, ix in (("train", tr), ("val", va), ("test", te)):
        log("  %s: %d rows, attack share %.2f%%" % (name, len(ix), 100 * y[ix].mean()))
    if len(np.unique(y[tr])) < 2 or len(np.unique(y[te])) < 2:
        log("  !! one split contains a single class -> P3 skipped (use more rows)")
    else:
        sc = StandardScaler().fit(Xv[tr])
        Xtr, ytr, _ = adasyn(sc.transform(Xv[tr]), y[tr])
        m3 = fit(builder, Xtr, ytr, sc.transform(Xv[va]), y[va], epochs)
        res["P3_correct_temporal_split"] = metrics(y[te], predict(m3, sc.transform(Xv[te])))

    # report
    log("\n" + "=" * 140 + "\nLEAKAGE RESULTS (test sets)\n" + "=" * 140)
    for k, v in res.items():
        if isinstance(v, dict):
            log(fmt_row(k, v))
    log("\nShare of P1 test set that is synthetic: %.1f%%" % (100 * res["P1_share_of_test_that_is_synthetic"]))
    log("Median distance to nearest TRAIN row: real test rows = %.4f | synthetic test rows = %.4f"
        % (res["P1_median_NN_dist_to_train_real_test_rows"],
           res["P1_median_NN_dist_to_train_synthetic_test_rows"]))
    log("\nFPR vs 1-accuracy check (Table 5.4 pattern):")
    for k, v in res.items():
        if isinstance(v, dict):
            log("  %-34s FPR=%.4f  1-acc=%.4f  %s" % (k, v["FPR"], v["error_rate"],
                "<- identical (suspicious)" if v["FPR"] > 0 and abs(v["FPR"] - v["error_rate"]) < 1e-4 else ""))
    log("""
How to read it
  * Leakage is confirmed if P1_leaky_full_test is clearly better than P2/P3, and/or
    P1 synthetic rows score better than P1 real rows, and/or synthetic test rows sit much
    closer to the training set than real test rows.
  * P2/P3 are the numbers that can be defended. P3 (temporal) is the most realistic.
  * FPR must be FP/(FP+TN). It only equals 1-accuracy by coincidence.""")
    save(res, out, "leakage")
    return res


# --------------------------------------------------------------------------- profiler
def profile_index_for_window(sub):
    """Eq. 5.1: V_n = (z_dst, z_src, z_proto, Np) per channel (src, proto) of one node in
    one window; PI = sum_{n=1}^{N-1} V_n . V_{n+1}.  sub: DataFrame of the window's flows."""
    g = sub.groupby(["src", "proto"], sort=True).agg(zd=("z_dst", "first"), zs=("z_src", "first"),
                                                     zp=("z_proto", "first"), Np=("npkts", "sum"))
    V = g[["zd", "zs", "zp", "Np"]].values
    if len(V) < 2:
        return float(V[0] @ V[0]) if len(V) else 0.0  # degenerate case (N=1): self product
    return float(np.sum(V[:-1] * V[1:]))


def build_windows(side_te):
    w = side_te.copy()
    w["win"] = np.floor((w["ts"] - w["ts"].min()) / WINDOW_S).astype(np.int64)
    # z-scores used in the profile vector (slide 30 notes)
    for col, src in (("z_dst", "node"), ("z_src", "src")):
        v = ip_to_int(w[src])
        w[col] = (v - v.mean()) / (v.std() + 1e-12)
    pc = w["proto"].astype("category").cat.codes.astype(float)
    w["z_proto"] = (pc - pc.mean()) / (pc.std() + 1e-12)
    groups = list(w.groupby(["win", "node"], sort=True).indices.items())
    return w, groups


# --------------------------------------------------------------------------- experiment 2
def prepare_ram(X, y, side, builder, epochs, out):
    """Train a model correctly (temporal split, ADASYN on train only), save model + test data,
    then measure each configuration in a separate process."""
    from sklearn.preprocessing import StandardScaler
    Xv = X.values
    order = np.argsort(side["ts"].values, kind="mergesort")
    tr, va, te = split_idx(len(Xv), temporal=True)
    tr, va, te = order[tr], order[va], order[te]
    sc = StandardScaler().fit(Xv[tr])
    if len(np.unique(y[tr])) < 2:
        sys.exit("Training part has a single class; increase --max-rows")
    Xtr, ytr, _ = adasyn(sc.transform(Xv[tr]), y[tr])
    m = fit(builder, Xtr, ytr, sc.transform(Xv[va]), y[va], epochs)
    Xte = sc.transform(Xv[te]).astype("float32")
    # test set enlarged by ADASYN, to reproduce the thesis "CNN-LSTM with oversampling" memory
    try:
        Xte_ad, _, _ = adasyn(Xte.astype("float64"), y[te])
        Xte_ad = Xte_ad.astype("float32")
    except Exception as e:  # e.g. single class in test
        log("ADASYN on test failed (%s); batch_full_adasyn will reuse the plain test set" % e)
        Xte_ad = Xte
    tmp = tempfile.mkdtemp(prefix="ram_")
    mpath = os.path.join(tmp, "model.h5")
    m.save(mpath)
    side_te = side.iloc[te].reset_index(drop=True)
    side_te.to_pickle(os.path.join(tmp, "side.pkl"))
    np.savez(os.path.join(tmp, "data.npz"), X=Xte, y=y[te], X_ad=Xte_ad)
    return tmp, mpath


class PeakSampler:
    """Samples RSS of this process (and GPU via pynvml if available) every `dt` s."""

    def __init__(self, dt=0.01):
        import psutil
        self.p = psutil.Process(os.getpid())
        self.dt, self.peak, self.stop_flag = dt, 0, False
        self.gpu_util_peak, self.gpu_mem_peak = None, None
        try:
            import pynvml
            pynvml.nvmlInit()
            self.nv = pynvml
            self.h = pynvml.nvmlDeviceGetHandleByIndex(0)
            self.gpu_util_peak, self.gpu_mem_peak = 0, 0
        except Exception:
            self.nv = None

    def _run(self):
        while not self.stop_flag:
            self.peak = max(self.peak, self.p.memory_info().rss)
            if self.nv:
                u = self.nv.nvmlDeviceGetUtilizationRates(self.h).gpu
                mm = self.nv.nvmlDeviceGetMemoryInfo(self.h).used
                self.gpu_util_peak = max(self.gpu_util_peak, u)
                self.gpu_mem_peak = max(self.gpu_mem_peak, mm)
            time.sleep(self.dt)

    def __enter__(self):
        self.peak = self.p.memory_info().rss
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()
        return self

    def __exit__(self, *a):
        self.stop_flag = True
        self.t.join()


def measure_worker(tmp, config, batch_size, max_windows):
    """Runs inside a fresh process. Prints one JSON line with the measurements."""
    import psutil
    tf = tf_quiet()
    m = tf.keras.models.load_model(os.path.join(tmp, "model.h5"))
    d = np.load(os.path.join(tmp, "data.npz"))
    X, y = d["X"], d["y"]
    side = pd.read_pickle(os.path.join(tmp, "side.pkl"))
    w, groups = build_windows(side) if config.startswith("stream") else (None, None)
    if groups is not None and max_windows:
        groups = groups[:max_windows]
    m(X[:2, :, None], training=False)  # warm-up: graph build not counted
    gpus = tf.config.list_physical_devices("GPU")
    if gpus:
        try:
            tf.config.experimental.reset_memory_stats("GPU:0")
        except Exception:
            pass
    proc = psutil.Process(os.getpid())
    base = proc.memory_info().rss
    out = {"config": config}
    t0 = time.perf_counter()
    with PeakSampler() as s:
        if config == "batch_full":
            bs = batch_size or len(X)
            m.predict(X[..., None], batch_size=bs, verbose=0)
            out["rows"] = int(len(X))
        elif config == "batch_full_adasyn":
            Xa = d["X_ad"]
            bs = batch_size or len(Xa)
            m.predict(Xa[..., None], batch_size=bs, verbose=0)
            out["rows"] = int(len(Xa))
        else:
            use_prof = config == "stream_profiler"
            oPI = {}
            win_true, win_pred, win_sent, win_clf = [], [], [], []
            t_prof = t_clf = 0.0
            for (win, node), idx in groups:
                send = True
                if use_prof:
                    tp0 = time.perf_counter()
                    nPI = profile_index_for_window(w.iloc[idx])
                    prev = oPI.get(node)
                    if prev is not None and abs(prev) > 1e-12:
                        delta = abs(nPI - prev) / abs(prev) * 100.0
                        send = delta > THRESH_PCT
                    # first window of a node (prev None) -> sent to classifier
                    oPI[node] = nPI
                    t_prof += time.perf_counter() - tp0
                yt = int(y[idx].max())
                if send:
                    tc0 = time.perf_counter()
                    p = m(X[idx][..., None], training=False).numpy()
                    t_clf += time.perf_counter() - tc0
                    yhat = int((p.argmax(1) == 1).any())
                    win_clf.append(yhat)
                else:
                    yhat = 0
                    win_clf.append(-1)
                win_true.append(yt); win_pred.append(yhat); win_sent.append(send)
            out["profiler_seconds"] = t_prof
            out["classifier_seconds"] = t_clf
            out["windows"] = len(win_true)
            out["windows_sent"] = int(np.sum(win_sent))
            out["window_metrics"] = metrics(np.array(win_true), np.array(win_pred))
            yt_a, sent_a = np.array(win_true), np.array(win_sent)
            if use_prof:
                ben, att = yt_a == 0, yt_a == 1
                out["load_shedding_benign"] = float((~sent_a[ben]).mean()) if ben.any() else None
                out["attack_leakage"] = float((~sent_a[att]).mean()) if att.any() else None
    out["seconds"] = time.perf_counter() - t0
    tot = psutil.virtual_memory().total
    out["rss_baseline_MB"] = base / 2 ** 20
    out["rss_peak_MB"] = s.peak / 2 ** 20
    out["rss_delta_MB"] = (s.peak - base) / 2 ** 20
    out["rss_peak_pct_of_total_RAM"] = 100 * s.peak / tot
    out["rss_delta_pct_of_total_RAM"] = 100 * (s.peak - base) / tot
    if gpus:
        try:
            out["tf_gpu_peak_MB"] = tf.config.experimental.get_memory_info("GPU:0")["peak"] / 2 ** 20
        except Exception:
            pass
    if s.gpu_util_peak is not None:
        out["nvml_gpu_util_peak_pct"] = s.gpu_util_peak
        out["nvml_gpu_mem_peak_MB"] = s.gpu_mem_peak / 2 ** 20
    if "windows" in out and out["windows"]:
        out["ms_per_window"] = 1000 * out["seconds"] / out["windows"]
    print("RESULT_JSON " + json.dumps(out), flush=True)


def run_ram(X, y, side, builder, epochs, out, batch_size=None, max_windows=None):
    tmp, _ = prepare_ram(X, y, side, builder, epochs, out)
    res = {}
    for cfg in ("batch_full", "batch_full_adasyn", "stream_no_profiler", "stream_profiler"):
        log("\n--- measuring %s in a fresh process ---" % cfg)
        cmd = [sys.executable, os.path.abspath(__file__), "_worker", "--tmp", tmp, "--config", cfg]
        if batch_size:
            cmd += ["--batch-size", str(batch_size)]
        if max_windows:
            cmd += ["--max-windows", str(max_windows)]
        p = subprocess.run(cmd, capture_output=True, text=True)
        line = [l for l in p.stdout.splitlines() if l.startswith("RESULT_JSON ")]
        if not line:
            log("  FAILED:\n" + p.stdout[-2000:] + p.stderr[-3000:])
            continue
        res[cfg] = json.loads(line[0][len("RESULT_JSON "):])

    log("\n" + "=" * 120 + "\nRAM RESULTS (each config in its own process; delta = peak - RSS after loading model+data)\n" + "=" * 120)
    log("%-20s %10s %12s %12s %11s %11s %10s %s" % ("config", "rows/win", "base MB", "peak MB",
                                                    "delta MB", "peak %RAM", "time s", "GPU"))
    for k, r in res.items():
        gpu = ""
        if "tf_gpu_peak_MB" in r:
            gpu += "tf_peak=%.0fMB " % r["tf_gpu_peak_MB"]
        if "nvml_gpu_util_peak_pct" in r:
            gpu += "util_peak=%d%%" % r["nvml_gpu_util_peak_pct"]
        log("%-20s %10s %12.1f %12.1f %11.1f %10.3f%% %10.2f %s" % (
            k, r.get("rows", r.get("windows")), r["rss_baseline_MB"], r["rss_peak_MB"],
            r["rss_delta_MB"], r["rss_peak_pct_of_total_RAM"], r["seconds"], gpu))

    if "stream_no_profiler" in res and "stream_profiler" in res:
        a, b = res["stream_no_profiler"], res["stream_profiler"]
        log("\nClassifier time: %.2f s without profiler vs %.2f s with profiler (+ %.2f s spent in the profiler)"
            % (a["classifier_seconds"], b["classifier_seconds"], b["profiler_seconds"]))
        log("Streaming without profiler: %d windows classified, %.1f ms/window, window F1=%.3f, FPR=%.2f%%, TPR=%.2f%%"
            % (a["windows_sent"], a.get("ms_per_window", 0), a["window_metrics"]["macro_F1"],
               100 * a["window_metrics"]["FPR"], 100 * a["window_metrics"]["recall_TPR"]))
        log("Streaming with profiler   : %d/%d windows classified (%.1f%%), %.1f ms/window, window F1=%.3f, FPR=%.2f%%, TPR=%.2f%%"
            % (b["windows_sent"], b["windows"], 100 * b["windows_sent"] / max(1, b["windows"]),
               b.get("ms_per_window", 0), b["window_metrics"]["macro_F1"],
               100 * b["window_metrics"]["FPR"], 100 * b["window_metrics"]["recall_TPR"]))
        if b.get("load_shedding_benign") is not None and b.get("attack_leakage") is not None:
            sh, lk = b["load_shedding_benign"], b["attack_leakage"]
            fpr0, tpr0 = a["window_metrics"]["FPR"], a["window_metrics"]["recall_TPR"]
            log("Profiler: benign shedding = %.1f%%, attack leakage = %.1f%%" % (100 * sh, 100 * lk))
            log("Table 5.2 check - composed (shedding x classifier) vs MEASURED two-stage:")
            log("   FPR composed = (1-shed)*FPR_clf = %.2f%%   measured = %.2f%%"
                % (100 * (1 - sh) * fpr0, 100 * b["window_metrics"]["FPR"]))
            log("   TPR composed = (1-leak)*TPR_clf = %.2f%%   measured = %.2f%%"
                % (100 * (1 - lk) * tpr0, 100 * b["window_metrics"]["recall_TPR"]))
    log("""
How to read it
  * Compare stream_no_profiler with stream_profiler: that difference is the profiler's
    real memory/time effect. Compare batch_full with stream_no_profiler: that difference
    is batch-vs-streaming. Table 5.5 compared batch_full with stream_profiler, which
    mixes the two effects.
  * batch_full_adasyn vs batch_full shows that the higher RAM 'with ADASYN' comes only
    from the larger (partly synthetic) test set.
  * Report MB (delta) rather than % of total RAM: % depends on the machine.
  * If GPU is used, 'GPU usage %' in the thesis must be defined: utilisation (nvml util)
    or memory (tf_peak / nvml mem). Without memory growth TF reserves almost all VRAM.""")
    save(res, out, "ram")
    return res


# --------------------------------------------------------------------------- main
def save(res, out, name):
    os.makedirs(out, exist_ok=True)
    p = os.path.join(out, "results_%s.json" % name)
    with open(p, "w") as f:
        json.dump(res, f, indent=2, default=float)
    log("Saved %s" % p)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["leakage", "ram", "all", "demo", "_worker"])
    ap.add_argument("--data", help="glob of ToN-IoT network CSV files")
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--max-rows", type=int, default=None, help="first N rows in time order")
    ap.add_argument("--frac", type=float, default=None, help="random sample fraction (destroys time order)")
    ap.add_argument("--epochs", type=int, default=10)
    ap.add_argument("--model-module", default=None, help=".py file with build_model(n_features, n_classes)")
    ap.add_argument("--drop-ids", action="store_true", help="drop ts, IPs, ports from the features")
    ap.add_argument("--batch-size", type=int, default=None, help="batch size for batch_* configs (default: whole set)")
    ap.add_argument("--max-windows", type=int, default=None, help="limit streamed windows (speed)")
    ap.add_argument("--out", default="verify_out")
    ap.add_argument("--tmp", help=argparse.SUPPRESS)
    ap.add_argument("--config", help=argparse.SUPPRESS)
    a = ap.parse_args()

    if a.mode == "_worker":
        measure_worker(a.tmp, a.config, a.batch_size, a.max_windows)
        return

    set_seeds()
    if a.mode == "demo":
        df = make_demo_df()
        log("Demo data: %d synthetic flows" % len(df))
        epochs = min(a.epochs, 3)
    else:
        if not a.data:
            sys.exit("--data is required (or use the 'demo' mode)")
        df = load_df(a.data, a.max_rows, a.frac, a.label_col)
        epochs = a.epochs
    X, y, side = preprocess(df, a.label_col, a.drop_ids)
    builder = get_builder(a.model_module)

    if a.mode in ("leakage", "all", "demo"):
        run_leakage(X, y, side, builder, epochs, a.out)
    if a.mode in ("ram", "all", "demo"):
        if a.frac:
            log("WARNING: --frac destroys time order; RAM/profiler results are not meaningful")
        run_ram(X, y, side, builder, epochs, a.out, a.batch_size, a.max_windows)


if __name__ == "__main__":
    main()
