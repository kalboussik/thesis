"""Stage 3 — aggregate all run outputs into the tables the chapter needs.

Produces:
  results/summary_table.csv     — acc / macro-F1 / offload per (impl, partition, n_clients), mean ± std over seeds
  results/manual_vs_flower.csv  — implementation-agreement check
  results/per_class_<...>.csv   — per-class P/R/F1 for the headline configuration
Run after run_all.sh completes.
"""
import json, glob, os, csv
import numpy as np
from collections import defaultdict
import config as C


def load_results():
    rows = []
    for f in glob.glob(os.path.join(C.RESULTS, "*_full.json")):
        try:
            r = json.load(open(f))["result"]
        except Exception:
            continue
        impl, partition, nc, seed = r["tag"].split("_")
        rows.append({
            "impl": impl, "partition": partition,
            "clients": int(nc[1:]), "seed": int(seed[1:]),
            "accuracy": r["accuracy"], "macro_f1": r["macro_f1"],
            "weighted_f1": r["weighted_f1"],
            "offload": r["profiler_offload_rate"],
            "per_class": r["per_class"], "cm": r["confusion_matrix"],
        })
    return rows


def agg(rows):
    g = defaultdict(list)
    for r in rows:
        g[(r["impl"], r["partition"], r["clients"])].append(r)
    out = []
    for (impl, part, nc), rs in sorted(g.items()):
        def ms(k): 
            v = [x[k] for x in rs]; return np.mean(v), (np.std(v) if len(v) > 1 else 0.0)
        a_m, a_s = ms("accuracy"); f_m, f_s = ms("macro_f1"); o_m, o_s = ms("offload")
        out.append(dict(impl=impl, partition=part, clients=nc, n_seeds=len(rs),
                        acc_mean=a_m, acc_std=a_s, f1_mean=f_m, f1_std=f_s,
                        offload_mean=o_m, offload_std=o_s))
    return out


def main():
    rows = load_results()
    if not rows:
        print("no *_full.json results found yet."); return
    summary = agg(rows)

    with open(os.path.join(C.RESULTS, "summary_table.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["impl","partition","clients","n_seeds",
                    "accuracy_mean","accuracy_std","macroF1_mean","macroF1_std",
                    "offload_mean","offload_std"])
        for s in summary:
            w.writerow([s["impl"],s["partition"],s["clients"],s["n_seeds"],
                        f"{s['acc_mean']:.4f}",f"{s['acc_std']:.4f}",
                        f"{s['f1_mean']:.4f}",f"{s['f1_std']:.4f}",
                        f"{s['offload_mean']:.4f}",f"{s['offload_std']:.4f}"])

    # manual vs flower agreement
    bykey = defaultdict(dict)
    for s in summary:
        bykey[(s["partition"],s["clients"])][s["impl"]] = s
    with open(os.path.join(C.RESULTS, "manual_vs_flower.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["partition","clients","manual_macroF1","flower_macroF1","abs_diff"])
        for (part,nc),impls in sorted(bykey.items()):
            if "manual" in impls and "flower" in impls:
                mm = impls["manual"]["f1_mean"]; ff = impls["flower"]["f1_mean"]
                w.writerow([part,nc,f"{mm:.4f}",f"{ff:.4f}",f"{abs(mm-ff):.4f}"])

    print(">>> wrote results/summary_table.csv and results/manual_vs_flower.csv")
    for s in summary:
        print(f"{s['impl']:7} {s['partition']:7} n={s['clients']:<3} "
              f"acc={s['acc_mean']:.3f}±{s['acc_std']:.3f} "
              f"macroF1={s['f1_mean']:.3f}±{s['f1_std']:.3f} "
              f"offload={s['offload_mean']:.3f}")


if __name__ == "__main__":
    main()
