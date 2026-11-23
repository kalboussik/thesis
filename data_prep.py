"""Stage 0 — data preparation for ToN-IoT (Train_Test_Network.csv).

Loads the per-flow tabular dataset, collapses labels to the 5-class scheme,
drops identifier/leaky columns and unmapped attack types, encodes categoricals,
scales numerics, and writes a single processed .npz used by every downstream
script. Run once.
"""
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib, os, json
import config as C


def load_and_clean():
    print(f">>> loading {C.DATA_CSV}")
    df = pd.read_csv(C.DATA_CSV, low_memory=False)
    df.columns = [c.strip().lower() for c in df.columns]

    # ToN-IoT marks missing values with '-'
    df = df.replace("-", np.nan)

    # label column is 'type' (normal, dos, ddos, scanning, password, ...)
    if "type" not in df.columns:
        raise ValueError("expected a 'type' label column in ToN-IoT CSV")
    df["type"] = df["type"].astype(str).str.strip().str.lower()

    # drop unmapped attack types
    df = df[~df["type"].isin(C.DROPPED_TYPES)]
    # keep only rows whose type is in our map
    df = df[df["type"].isin(C.LABEL_MAP.keys())].copy()
    df["y"] = df["type"].map(C.LABEL_MAP)

    # drop identifier / leaky columns + raw label columns
    drop = [c for c in C.DROP_COLS if c in df.columns] + ["type"]
    df = df.drop(columns=drop, errors="ignore")

    print(">>> class distribution after collapsing:")
    print(df["y"].value_counts())
    return df


def encode_and_scale(df):
    y = df["y"].values
    X = df.drop(columns=["y"])

    # split columns into numeric vs categorical
    cat_cols, num_cols = [], []
    for c in X.columns:
        coerced = pd.to_numeric(X[c], errors="coerce")
        if coerced.notna().mean() > 0.95:      # mostly numeric
            X[c] = coerced
            num_cols.append(c)
        else:
            cat_cols.append(c)

    # numerics: fill NaN with 0, scale
    X[num_cols] = X[num_cols].fillna(0.0)
    # categoricals: fill, label-encode
    for c in cat_cols:
        X[c] = X[c].fillna("none").astype(str)
        X[c] = LabelEncoder().fit_transform(X[c])

    feat_names = list(X.columns)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X.values.astype(np.float32))

    le = LabelEncoder().fit(C.CLASSES)
    y_enc = le.transform(y)

    return Xs.astype(np.float32), y_enc.astype(np.int64), feat_names, scaler, le, num_cols, cat_cols


def main():
    df = load_and_clean()
    X, y, feat_names, scaler, le, num_cols, cat_cols = encode_and_scale(df)

    # global train / val / test (stratified) — test is the held-out evaluation set
    X_tmp, X_test, y_tmp, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42)
    X_train, X_val, y_train, y_val = train_test_split(
        X_tmp, y_tmp, test_size=0.15, stratify=y_tmp, random_state=42)

    out = os.path.join(C.PROC_DIR, "toniot_5class.npz")
    np.savez_compressed(
        out, X_train=X_train, y_train=y_train,
        X_val=X_val, y_val=y_val, X_test=X_test, y_test=y_test)
    joblib.dump({"scaler": scaler, "label_encoder": le,
                 "features": feat_names, "num_cols": num_cols,
                 "cat_cols": cat_cols, "profiler_idx":
                 [feat_names.index(f) for f in C.PROFILER_FEATURES if f in feat_names]},
                os.path.join(C.PROC_DIR, "preproc.joblib"))

    meta = {
        "n_features": X.shape[1],
        "classes": list(le.classes_),
        "n_train": int(len(y_train)), "n_val": int(len(y_val)), "n_test": int(len(y_test)),
        "train_class_counts": {C.CLASSES[i]: int((y_train == i).sum()) for i in range(len(C.CLASSES))},
    }
    json.dump(meta, open(os.path.join(C.PROC_DIR, "meta.json"), "w"), indent=2)
    print(">>> saved", out)
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
