"""Stage 0 (Bot-IoT) — data preparation for the Bot-IoT 5% full-feature CSVs.

Loads the UNSW_2018_IoT_Botnet_Full5pc_*.csv files, maps `category` to the
4-class scheme (benign/dos/ddos/portscan; Theft dropped), removes identifier/
leaky columns (critical for Bot-IoT: pkSeqID/seq leak the label), encodes
categoricals, scales numerics, and writes the same processed .npz format the
rest of the kit consumes. Run once.

Usage:
  export BOTIOT_DIR=/path/to/botiot_5pc      # folder containing the CSV(s)
  python data_prep_botiot.py
"""
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib, os, glob, json
import config as C

BOTIOT_DIR = os.environ.get("BOTIOT_DIR", os.path.join(C.ROOT, "data_botiot"))

# Canonical Argus column names for Bot-IoT (used if the CSVs have no header row).
BOTIOT_COLS = [
    "pkSeqID", "stime", "flgs", "proto", "saddr", "sport", "daddr", "dport",
    "pkts", "bytes", "state", "ltime", "seq", "dur", "mean", "stddev", "smac",
    "dmac", "sum", "min", "max", "soui", "doui", "sco", "dco", "spkts", "dpkts",
    "sbytes", "dbytes", "rate", "srate", "drate", "attack", "category", "subcategory",
]

# Bot-IoT category -> our 4-class scheme. Theft dropped.
# Bot-IoT BINARY mapping: benign vs attack. Theft folded into attack (still
# malicious); only Normal maps to benign.
LABEL_MAP_BOTIOT = {
    "normal": "benign",
    "dos": "attack",
    "ddos": "attack",
    "reconnaissance": "attack",
    "theft": "attack",
}
CLASSES_BOTIOT = ["attack", "benign"]  # must match config.CLASSES (alphabetical)
DROPPED_CATEGORIES = []  # binary: all attack families collapse to 'attack'

# identifier / leaky columns (pkSeqID & seq notoriously leak the Bot-IoT label)
DROP_COLS_BOTIOT = ["pkSeqID", "stime", "ltime", "saddr", "daddr", "sport",
                    "dport", "seq", "smac", "dmac", "soui", "doui", "sco", "dco",
                    "attack", "subcategory"]


def load_and_clean():
    files = sorted(glob.glob(os.path.join(BOTIOT_DIR, "*.csv")))
    if not files:
        raise FileNotFoundError(f"no CSVs in {BOTIOT_DIR} (set BOTIOT_DIR)")
    print(f">>> loading {len(files)} Bot-IoT CSV(s) from {BOTIOT_DIR}")

    frames = []
    for f in files:
        # detect header: read first line, check if it contains 'category' or 'pkSeqID'
        head = pd.read_csv(f, nrows=0)
        has_header = any(c.lower() in ("category", "pkseqid", "attack")
                         for c in head.columns)
        if has_header:
            df = pd.read_csv(f, low_memory=False)
            df.columns = [c.strip().lower() for c in df.columns]
        else:
            df = pd.read_csv(f, header=None, names=BOTIOT_COLS, low_memory=False)
            df.columns = [c.strip().lower() for c in df.columns]
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df = df.replace("-", np.nan)

    if "category" not in df.columns:
        raise ValueError("expected a 'category' label column in Bot-IoT CSV")
    df["category"] = df["category"].astype(str).str.strip().str.lower()

    df = df[~df["category"].isin(DROPPED_CATEGORIES)]
    df = df[df["category"].isin(LABEL_MAP_BOTIOT.keys())].copy()
    df["y"] = df["category"].map(LABEL_MAP_BOTIOT)

    drop = [c for c in DROP_COLS_BOTIOT if c in df.columns] + ["category"]
    df = df.drop(columns=drop, errors="ignore")

    print(">>> class distribution after collapsing:")
    print(df["y"].value_counts())
    return df


def encode_and_scale(df):
    y = df["y"].values
    X = df.drop(columns=["y"])
    cat_cols, num_cols = [], []
    for c in X.columns:
        coerced = pd.to_numeric(X[c], errors="coerce")
        if coerced.notna().mean() > 0.95:
            X[c] = coerced; num_cols.append(c)
        else:
            cat_cols.append(c)
    X[num_cols] = X[num_cols].fillna(0.0)
    for c in cat_cols:
        X[c] = X[c].fillna("none").astype(str)
        X[c] = LabelEncoder().fit_transform(X[c])

    feat_names = list(X.columns)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X.values.astype(np.float32))
    le = LabelEncoder().fit(CLASSES_BOTIOT)
    y_enc = le.transform(y)
    return Xs.astype(np.float32), y_enc.astype(np.int64), feat_names, scaler, le, num_cols, cat_cols


def main():
    df = load_and_clean()
    X, y, feat_names, scaler, le, num_cols, cat_cols = encode_and_scale(df)

    X_tmp, X_test, y_tmp, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42)
    X_train, X_val, y_train, y_val = train_test_split(
        X_tmp, y_tmp, test_size=0.15, stratify=y_tmp, random_state=42)

    # ---- ADASYN on the TRAINING SET ONLY (val/test stay real & imbalanced) ----
    # Consistent with the TWEB methodology. Benign has very few real seeds, so we
    # cap k_neighbors accordingly and report the augmentation explicitly.
    pre_counts = {list(le.classes_)[i]: int((y_train == i).sum())
                  for i in range(len(le.classes_))}
    try:
        from imblearn.over_sampling import ADASYN
        benign_n = int((y_train == le.transform(["benign"])[0]).sum())
        k = max(1, min(5, benign_n - 1))      # can't use more neighbours than seeds
        # oversample every minority class up toward the majority count
        ada = ADASYN(random_state=42, n_neighbors=k, sampling_strategy="not majority")
        X_train, y_train = ada.fit_resample(X_train, y_train)
        adasyn_ok = True
    except Exception as e:
        print(f"!! ADASYN failed ({e}); falling back to class weighting at train time")
        adasyn_ok = False
    post_counts = {list(le.classes_)[i]: int((y_train == i).sum())
                   for i in range(len(le.classes_))}

    out = os.path.join(C.PROC_DIR, "toniot_5class.npz")   # same path the kit reads
    np.savez_compressed(out, X_train=X_train, y_train=y_train,
                        X_val=X_val, y_val=y_val, X_test=X_test, y_test=y_test)
    joblib.dump({"scaler": scaler, "label_encoder": le, "features": feat_names,
                 "num_cols": num_cols, "cat_cols": cat_cols, "profiler_idx": []},
                os.path.join(C.PROC_DIR, "preproc.joblib"))
    meta = {
        "dataset": "bot-iot-5pc", "n_features": X.shape[1],
        "classes": list(le.classes_),
        "adasyn_applied": adasyn_ok,
        "train_class_counts_before_adasyn": pre_counts,
        "train_class_counts_after_adasyn": post_counts,
        "n_train": int(len(y_train)), "n_val": int(len(y_val)), "n_test": int(len(y_test)),
        "val_class_counts": {list(le.classes_)[i]: int((y_val == i).sum())
                             for i in range(len(le.classes_))},
        "test_class_counts": {list(le.classes_)[i]: int((y_test == i).sum())
                              for i in range(len(le.classes_))},
    }
    json.dump(meta, open(os.path.join(C.PROC_DIR, "meta.json"), "w"), indent=2)
    print(">>> saved", out); print(json.dumps(meta, indent=2))
    print("\nNOTE: ADASYN applied to TRAINING ONLY; val/test remain real and imbalanced.")
    print("NOTE: benign has very few real seeds — report benign metrics with caution.")


if __name__ == "__main__":
    main()
