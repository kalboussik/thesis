"""Model definitions.

- build_lstm_cnn: the Chapter-5 LSTM-1DCNN classifier, reused unchanged so the
  chapters stay consistent. The per-flow feature vector is treated as a 1-D
  pseudo-sequence (n_features, 1) fed to Conv1D + LSTM.
- BenignProfiler: the lightweight stage-1 gate. It learns per-feature benign
  bounds (Tukey fences) on benign training flows; at inference a flow whose
  profiled features all fall inside the benign envelope is passed straight
  through as benign (offloaded from the heavy classifier). Everything else is
  forwarded to the LSTM-CNN. This reproduces the two-stage design of Chapter 5.
"""
import numpy as np
import tensorflow as tf
from tensorflow.keras import layers, models
import config as C


def build_lstm_cnn(n_features, n_classes, lr=C.LEARNING_RATE):
    inp = layers.Input(shape=(n_features, 1))
    x = layers.Conv1D(64, 3, padding="same", activation="relu")(inp)
    x = layers.BatchNormalization()(x)
    x = layers.MaxPooling1D(2)(x)
    x = layers.Conv1D(128, 3, padding="same", activation="relu")(x)
    x = layers.BatchNormalization()(x)
    x = layers.MaxPooling1D(2)(x)
    x = layers.LSTM(64, return_sequences=False)(x)
    x = layers.Dropout(0.3)(x)
    x = layers.Dense(64, activation="relu")(x)
    out = layers.Dense(n_classes, activation="softmax")(x)
    model = models.Model(inp, out)
    model.compile(optimizer=tf.keras.optimizers.Adam(lr),
                  loss="sparse_categorical_crossentropy",
                  metrics=["accuracy"])
    return model


def reshape_seq(X):
    """(_, n_features) -> (_, n_features, 1) for Conv1D/LSTM."""
    return X.reshape((X.shape[0], X.shape[1], 1))


class BenignProfiler:
    """Stage-1 adaptive behavioral profiler (manuscript Eqs. 1-6).

    Faithful implementation of the paper's local behavioral profiling with
    adaptive thresholding. Flows are streamed in dataset order and grouped into
    pseudo-windows of W consecutive flows (no timestamp available in this ToN-IoT
    release, so window order = dataset order; stated as a caveat in the chapter).

    Per window t:
      B_t = (f_1..f_n)                      (Eq. 1) behavioral feature vector
      z_i = |f_i - mu_i| / (sigma_i + eps)  (Eq. 2) normalized deviation
      A_t = sum_i w_i z_i                   (Eq. 3) weighted anomaly score
      theta_t = mu_A + k * sigma_A          (Eq. 4) adaptive threshold (rolling)
      SBE if A_t > theta_t  -> forward window to LSTM-CNN; else finalize benign
    Feature stats drift via EWMA (Eqs. 5-6) with learning rate alpha.

    Primary tunable parameter: k (sensitivity). Lower k -> more SBEs (higher
    attack recall, lower offload); higher k -> more offload, more leakage.
    """

    def __init__(self, k=2.0, alpha=0.05, window=64, weights=None, eps=1e-6,
                 warmup=10):
        self.k = k
        self.alpha = alpha
        self.window = window
        self.weights = weights        # None => uniform (sum to 1)
        self.eps = eps
        self.warmup = warmup          # windows used to seed the benign profile
        self.mu = None                # per-feature running mean   (Eq. 5)
        self.sd = None                # per-feature running std    (Eq. 6)

    # --- window construction over the flow sequence ---
    def _windows(self, X):
        n = X.shape[0]
        nw = n // self.window
        # mean-pool features within each window -> behavioral vector B_t (Eq. 1)
        Xw = X[:nw * self.window].reshape(nw, self.window, X.shape[1]).mean(axis=1)
        return Xw, nw

    def fit(self, X_train, y_train, benign_label=0, X_val=None, y_val=None):
        # seed the benign profile on benign training flows (warm start for mu/sd)
        Xb = X_train[y_train == benign_label]
        self.mu = Xb.mean(axis=0)
        self.sd = Xb.std(axis=0) + self.eps
        n = X_train.shape[1]
        if self.weights is None:
            self.weights = np.full(n, 1.0 / n)
        # seed rolling SCORE statistics from benign training windows so the
        # adaptive threshold theta starts calibrated to benign behavior.
        Xw_b, nwb = self._windows(Xb)
        if nwb > 0:
            zb = np.abs(Xw_b - self.mu) / (self.sd + self.eps)
            Ab = (zb * self.weights).sum(axis=1)
            self._A0_mean = float(Ab.mean())
            self._A0_std = float(Ab.std() + self.eps)
        else:
            self._A0_mean, self._A0_std = 0.0, 1.0
        return self

    def _scores_streaming(self, Xw):
        """Run Eqs. 2-6 over the window sequence. Baseline statistics (score
        rolling mean/std AND feature EWMA) are updated ONLY on windows judged
        benign, so confirmed anomalies do not poison the profile. The rolling
        score statistics are seeded from benign training windows (set in fit)."""
        mu = self.mu.copy(); sd = self.sd.copy()
        A_hist = []
        decisions = np.zeros(Xw.shape[0], dtype=bool)   # True => benign (offload)
        # seed rolling score stats from benign training (Eq. 4 baseline)
        run_mean = getattr(self, "_A0_mean", 0.0)
        run_std = getattr(self, "_A0_std", 1.0)
        ewma_beta = 0.05                                # rolling-stat adaptation
        for t in range(Xw.shape[0]):
            f = Xw[t]
            z = np.abs(f - mu) / (sd + self.eps)          # Eq. 2
            A = float(np.sum(self.weights * z))           # Eq. 3
            theta = run_mean + self.k * run_std           # Eq. 4
            is_benign = (A <= theta)
            decisions[t] = is_benign
            A_hist.append(A)
            if is_benign:
                # update baseline ONLY on benign-judged windows (anti-poisoning)
                run_mean = (1 - ewma_beta) * run_mean + ewma_beta * A
                run_std = np.sqrt((1 - ewma_beta) * run_std**2
                                  + ewma_beta * (A - run_mean)**2) + self.eps
                mu = (1 - self.alpha) * mu + self.alpha * f          # Eq. 5
                sd = np.sqrt((1 - self.alpha) * sd**2
                             + self.alpha * (f - mu)**2) + self.eps  # Eq. 6
        return np.array(A_hist), decisions

    def passes_as_benign(self, X):
        """Per-flow benign mask. Flows are windowed; a window finalized benign
        (no SBE) marks all its flows benign-offloaded; SBE windows forward all
        their flows to the classifier. Tail flows beyond the last full window
        are forwarded (conservative)."""
        Xw, nw = self._windows(X)
        _, win_benign = self._scores_streaming(Xw)
        mask = np.zeros(X.shape[0], dtype=bool)
        for w in range(nw):
            if win_benign[w]:
                mask[w * self.window:(w + 1) * self.window] = True
        return mask
