# verify_adasyn_ram

A small tool to check two things that often go wrong when evaluating deep-learning intrusion detection systems on imbalanced IoT datasets such as ToN-IoT:

1. **Oversampling leakage.** Applying ADASYN (or SMOTE) to the whole dataset *before* the train/test split puts synthetic samples, interpolated from training data, into the test set. The scores then look better than they really are.
2. **Misleading memory measurements.** Comparing "whole test set in one batch" with "one time window at a time + profiler" mixes two effects: batch vs streaming processing, and the effect of the profiler itself. This tool measures them separately.

I wrote it to re-check the results of Chapter 5 of my PhD thesis (two-stage IDS: lightweight traffic profiler + CNN-LSTM classifier), but it works with any flow-based dataset that has a timestamp and a binary label.

## Requirements

- Python 3.8 or newer
- TensorFlow 2.8 or newer (CPU or GPU)

```bash
pip install "tensorflow==2.8.*" imbalanced-learn psutil pandas scikit-learn
pip install pynvml   # optional: GPU utilisation and memory through NVML
```

## Quick start

Run the built-in demo first. It generates a synthetic flow dataset and runs everything in a few minutes, without any download:

```bash
python verify_adasyn_ram.py demo
```

Then run it on the ToN-IoT network CSV files:

```bash
python verify_adasyn_ram.py all \
    --data "/path/to/ToN-IoT/Network_dataset_*.csv" \
    --max-rows 500000 --epochs 10 --max-windows 20000
```

