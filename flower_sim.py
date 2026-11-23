"""Flower implementation of the same FedAvg experiment, on the SAME partitions
and model as manual_fedavg.py — an independent implementation for validity
comparison (not a contest).

Uses Flower's simulation engine (flwr==1.7.x). A custom FedAvg strategy captures
the aggregated global weights every round so we can early-stop on global-val
macro-F1 and run the full two-stage (profiler + LSTM-CNN) evaluation on the
held-out test set, exactly like the manual loop.
"""
import numpy as np
import os, json, argparse
import tensorflow as tf
import flwr as fl
from flwr.common import parameters_to_ndarrays
import config as C
from model import build_lstm_cnn, reshape_seq, BenignProfiler
from metrics import evaluate
from sklearn.metrics import f1_score
import joblib

_D = None
def data():
    global _D
    if _D is None:
        _D = np.load(os.path.join(C.PROC_DIR, "toniot_5class.npz"))
    return _D


class FlowerClient(fl.client.NumPyClient):
    def __init__(self, idx, n_features, n_classes):
        d = data()
        self.X = reshape_seq(d["X_train"][idx]); self.y = d["y_train"][idx]
        self.model = build_lstm_cnn(n_features, n_classes)
    def get_parameters(self, config): return self.model.get_weights()
    def fit(self, parameters, config):
        self.model.set_weights(parameters)
        steps = getattr(C, "LOCAL_STEPS", None)
        self.model.fit(self.X, self.y, epochs=C.LOCAL_EPOCHS,
                       steps_per_epoch=steps,
                       batch_size=C.BATCH_SIZE, verbose=0)
        return self.model.get_weights(), len(self.y), {}
    def evaluate(self, parameters, config):
        self.model.set_weights(parameters)
        loss, acc = self.model.evaluate(self.X, self.y, verbose=0)
        return float(loss), len(self.y), {"accuracy": float(acc)}


class SavingFedAvg(fl.server.strategy.FedAvg):
    """FedAvg that tracks the best global weights by global-val macro-F1."""
    def __init__(self, n_features, n_classes, **kw):
        super().__init__(**kw)
        self.n_features, self.n_classes = n_features, n_classes
        self.eval_model = build_lstm_cnn(n_features, n_classes)
        d = data(); self.Xv = reshape_seq(d["X_val"]); self.yv = d["y_val"]
        self.best_f1, self.best_w, self.history = -1.0, None, []

    def aggregate_fit(self, server_round, results, failures):
        params, metrics = super().aggregate_fit(server_round, results, failures)
        if params is not None:
            w = parameters_to_ndarrays(params)
            self.eval_model.set_weights(w)
            vpred = self.eval_model.predict(self.Xv, verbose=0).argmax(1)
            vf1 = f1_score(self.yv, vpred, average="macro", zero_division=0)
            self.history.append({"round": server_round, "val_macro_f1": float(vf1)})
            print(f"  [flower] round {server_round:02d} val_macroF1={vf1:.4f}")
            if vf1 > self.best_f1:
                self.best_f1 = vf1; self.best_w = [a.copy() for a in w]
        return params, metrics


def run(partition, n_clients, seed):
    tf.keras.utils.set_random_seed(seed)
    d = data()
    n_features, n_classes = d["X_train"].shape[1], len(C.CLASSES)
    parts = np.load(os.path.join(C.PART_DIR, f"{partition}_n{n_clients}_s{seed}.npz"))
    client_idx = [parts[f"client_{i}"] for i in range(n_clients)]

    def client_fn(cid):
        return FlowerClient(client_idx[int(cid)], n_features, n_classes).to_client()

    strategy = SavingFedAvg(
        n_features, n_classes,
        fraction_fit=1.0, fraction_evaluate=0.0,
        min_fit_clients=n_clients, min_available_clients=n_clients,
    )
    fl.simulation.start_simulation(
        client_fn=client_fn, num_clients=n_clients,
        config=fl.server.ServerConfig(num_rounds=C.NUM_ROUNDS),
        strategy=strategy,
        client_resources={"num_cpus": 1, "num_gpus": 0},
    )

    tag = f"flower_{partition}_n{n_clients}_s{seed}"
    model = build_lstm_cnn(n_features, n_classes)
    model.set_weights(strategy.best_w)
    pidx = joblib.load(os.path.join(C.PROC_DIR, "preproc.joblib"))["profiler_idx"]
    profiler = BenignProfiler(k=2.0, alpha=0.05, window=64).fit(
        d["X_train"], d["y_train"], benign_label=C.CLASSES.index("benign"),
        X_val=d["X_val"], y_val=d["y_val"])
    res = evaluate(profiler, model, d["X_test"], d["y_test"], tag, C.RESULTS)
    res["best_val_macro_f1"] = strategy.best_f1
    json.dump({"result": res, "history": strategy.history},
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
