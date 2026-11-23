"""Central configuration for the federated two-stage IDS experiment (Chapter 6).

All experiment knobs live here so every script (data prep, partitioning, manual
FedAvg, Flower, metrics) shares one source of truth and the runs are reproducible.
"""
import os

# ---- paths ----
ROOT       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_CSV   = os.environ.get("TONIOT_CSV", os.path.join(ROOT, "data", "Train_Test_Network.csv"))
PROC_DIR   = os.path.join(ROOT, "processed")
PART_DIR   = os.path.join(ROOT, "partitions")
RESULTS    = os.path.join(ROOT, "results")
for d in (PROC_DIR, PART_DIR, RESULTS):
    os.makedirs(d, exist_ok=True)

# ---- label collapsing (ToN-IoT 'type' -> our 5-class scheme) ----
# Unmapped attack types are DROPPED (per design decision), so Chapter 6 mirrors
# the four real-world classes of Chapter 7 plus benign.
LABEL_MAP = {
    "normal":   "benign",
    "dos":      "dos",
    "ddos":     "ddos",
    "scanning": "portscan",
    "password": "bruteforce",   # ToN-IoT 'password' = brute-force credential attack
    # dropped: injection, xss, ransomware, backdoor, mitm
}
# ---- dataset selection ----
# DATASET=toniot (default, 5 classes) or DATASET=botiot (4 classes).
# Keeps CLASSES consistent everywhere (model output, metrics, profiler).
DATASET = os.environ.get("DATASET", "toniot").lower()

if DATASET == "botiot":
    # Bot-IoT binary detection (benign vs attack); alphabetical for LabelEncoder.
    CLASSES = ["attack", "benign"]
else:
    # ToN-IoT 5-class; alphabetical to match LabelEncoder.
    CLASSES = ["benign", "bruteforce", "ddos", "dos", "portscan"]
DROPPED_TYPES = ["injection", "xss", "ransomware", "backdoor", "mitm"]

# columns that leak identity / would short-circuit learning -> removed
DROP_COLS = ["ts", "src_ip", "dst_ip", "src_port", "dst_port", "label"]

# ---- experiment sweep ----
CLIENT_COUNTS = [5, 10, 20]      # federated client sweep
PARTITIONS    = ["noniid", "iid"]  # non-IID (Dirichlet) + IID baseline
DIRICHLET_ALPHA = 0.5            # fixed across the sweep for fair comparison
SEEDS         = [0, 1, 2]        # repetitions for variance

# ---- federated training ----
NUM_ROUNDS    = 50
LOCAL_EPOCHS  = 1
LOCAL_STEPS   = 20               # cap mini-batches/client/round (anti-drift). None = full epoch
BATCH_SIZE    = 256
LEARNING_RATE = 5e-4             # gentler local steps -> less client drift
EARLY_STOP_PATIENCE = 10         # on global validation macro-F1

# ---- profiler (stage 1) ----
# features used by the lightweight benign-profile gate (cheap to compute)
PROFILER_FEATURES = ["duration", "src_bytes", "dst_bytes", "missed_bytes"]
PROFILER_IQR_K = 1.5             # Tukey fence multiplier for benign bounds
