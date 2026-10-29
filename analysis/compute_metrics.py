"""
compute_metrics.py — Automated evaluation of rate-limiter effectiveness.

Reads the experiment log file (logs/experiment_runs.jsonl), computes
confusion matrices, detection metrics, and latency statistics for each
algorithm, then outputs:
  1. Clean Pandas summary tables to the terminal
  2. Ready-to-paste LaTeX tabular code for the research paper

Confusion Matrix Semantics (for rate-limiting as a binary classifier):
  ┌─────────────────────────────────────────────────────┐
  │               │ Predicted BLOCK │ Predicted ALLOW   │
  │ Actual ATTACK │ True Positive   │ False Negative    │
  │ Actual LEGIT  │ False Positive  │ True Negative     │
  └─────────────────────────────────────────────────────┘

  - TP: Attack request correctly blocked by rate limiter (is_attack=True, blocked=True)
  - FP: Legitimate request incorrectly blocked (is_attack=False, blocked=True)
  - TN: Legitimate request correctly allowed (is_attack=False, blocked=False)
  - FN: Attack request that was NOT blocked (is_attack=True, blocked=False)

Author: Soham Adsare (SY MCA, ICEM Pune)
Guide:  Dr. Dhanashree Patil
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for containerized execution
import matplotlib.pyplot as plt
import seaborn as sns


# ── Configuration ────────────────────────────────────────────

LOG_FILE = Path("logs/experiment_runs.jsonl")
OUTPUT_DIR = Path("analysis/output")


def load_experiment_data(log_path: Path) -> pd.DataFrame:
    """
    Parse the JSON-lines log file into a Pandas DataFrame.
    
    Each line is a JSON object with the schema:
        timestamp, request_id, client_ip, username, algorithm,
        traffic_type, http_status, is_attack, blocked_by_limiter,
        auth_success, latency_ms
    """
    if not log_path.exists():
        print(f"ERROR: Log file not found at {log_path}")
        print("  Run the experiment suite first: python -m simulators.traffic_generator")
        sys.exit(1)

    records = []
    with open(log_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"  WARNING: Skipping malformed line {line_num}: {e}")

    if not records:
        print("ERROR: No valid records found in log file.")
        sys.exit(1)

    df = pd.DataFrame(records)
    print(f"Loaded {len(df):,} request records from {log_path}")
    return df


# ═════════════════════════════════════════════════════════════
# CONFUSION MATRIX COMPUTATION
# ═════════════════════════════════════════════════════════════

def compute_confusion_matrix(group: pd.DataFrame) -> dict:
    """
    Compute confusion matrix components for a group of requests.

    Parameters
    ----------
    group : pd.DataFrame
        Filtered subset (e.g., per algorithm, per traffic type).

    Returns
    -------
    dict
        Contains TP, FP, TN, FN and derived metrics.
    """
    # Ground truth: is_attack flag set by the traffic generator
    # Prediction: blocked_by_limiter flag set by the rate limiter middleware
    is_attack = group["is_attack"].astype(bool)
    is_blocked = group["blocked_by_limiter"].astype(bool)

    tp = int((is_attack & is_blocked).sum())       # Attack correctly blocked
    fp = int((~is_attack & is_blocked).sum())      # Legit incorrectly blocked
    tn = int((~is_attack & ~is_blocked).sum())     # Legit correctly allowed
    fn = int((is_attack & ~is_blocked).sum())      # Attack incorrectly allowed

    total = tp + fp + tn + fn

    # ── Derived Metrics ──────────────────────────────────────
    # Detection Rate (Recall / Sensitivity / True Positive Rate)
    detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    # False Positive Rate (Fall-out)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # Precision (Positive Predictive Value)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

    # F1-Score (harmonic mean of precision and recall)
    f1 = (2 * precision * detection_rate / (precision + detection_rate)
           if (precision + detection_rate) > 0 else 0.0)

    # Accuracy
    accuracy = (tp + tn) / total if total > 0 else 0.0

    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "Total": total,
        "Detection_Rate": round(detection_rate, 4),
        "FPR": round(fpr, 4),
        "Precision": round(precision, 4),
        "F1_Score": round(f1, 4),
        "Accuracy": round(accuracy, 4),
    }


# ═════════════════════════════════════════════════════════════
# LATENCY STATISTICS
# ═════════════════════════════════════════════════════════════

def compute_latency_stats(group: pd.DataFrame) -> dict:
    """
    Compute latency percentile statistics for a group of requests.

    Returns
    -------
    dict
        Mean, Median (p50), p95, p99 latencies in milliseconds.
    """
    latencies = group["latency_ms"].dropna()
    if latencies.empty:
        return {"Mean_ms": 0, "Median_ms": 0, "P95_ms": 0, "P99_ms": 0}

    return {
        "Mean_ms": round(latencies.mean(), 4),
        "Median_ms": round(latencies.median(), 4),
        "P95_ms": round(latencies.quantile(0.95), 4),
        "P99_ms": round(latencies.quantile(0.99), 4),
    }


# ═════════════════════════════════════════════════════════════
# MAIN ANALYSIS PIPELINE
# ═════════════════════════════════════════════════════════════

def run_analysis():
    """
    Full analysis pipeline:
      1. Load experiment data
      2. Compute per-algorithm confusion matrices
      3. Compute per-algorithm × per-profile breakdown
      4. Compute latency statistics
      5. Print Pandas tables
      6. Generate LaTeX tables
      7. Generate visualisation plots
    """
    df = load_experiment_data(LOG_FILE)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    algorithms = sorted(df["algorithm"].unique())
    traffic_types = sorted(df["traffic_type"].unique())

    # ── 1. Per-Algorithm Overall Metrics ─────────────────────
    print("\n" + "="*80)
    print("  TABLE I: DETECTION METRICS BY ALGORITHM (Overall)")
    print("="*80)

    algo_metrics = []
    for algo in algorithms:
        subset = df[df["algorithm"] == algo]
        cm = compute_confusion_matrix(subset)
        cm["Algorithm"] = algo
        algo_metrics.append(cm)

    algo_df = pd.DataFrame(algo_metrics)
    cols_order = ["Algorithm", "TP", "FP", "TN", "FN", "Total",
                  "Detection_Rate", "FPR", "Precision", "F1_Score", "Accuracy"]
    algo_df = algo_df[cols_order]
    print(algo_df.to_string(index=False))

    # ── 2. Per-Algorithm × Per-Traffic-Type Breakdown ────────
    print("\n" + "="*80)
    print("  TABLE II: DETECTION METRICS BY ALGORITHM × TRAFFIC TYPE")
    print("="*80)

    detailed_metrics = []
    for algo in algorithms:
        for ttype in traffic_types:
            subset = df[(df["algorithm"] == algo) & (df["traffic_type"] == ttype)]
            if subset.empty:
                continue
            cm = compute_confusion_matrix(subset)
            cm["Algorithm"] = algo
            cm["Traffic_Type"] = ttype
            detailed_metrics.append(cm)

    detailed_df = pd.DataFrame(detailed_metrics)
    detail_cols = ["Algorithm", "Traffic_Type", "TP", "FP", "TN", "FN",
                   "Detection_Rate", "FPR", "Precision", "F1_Score"]
    detailed_df = detailed_df[[c for c in detail_cols if c in detailed_df.columns]]
    print(detailed_df.to_string(index=False))

    # ── 3. Latency Statistics ────────────────────────────────
    print("\n" + "="*80)
    print("  TABLE III: LATENCY OVERHEAD BY ALGORITHM")
    print("="*80)

    latency_metrics = []
    for algo in algorithms:
        subset = df[df["algorithm"] == algo]
        ls = compute_latency_stats(subset)
        ls["Algorithm"] = algo
        ls["Total_Requests"] = len(subset)
        latency_metrics.append(ls)

    latency_df = pd.DataFrame(latency_metrics)
    lat_cols = ["Algorithm", "Total_Requests", "Mean_ms", "Median_ms", "P95_ms", "P99_ms"]
    latency_df = latency_df[lat_cols]
    print(latency_df.to_string(index=False))

    # ── 4. LaTeX Table Generation ────────────────────────────
    print("\n" + "="*80)
    print("  LaTeX OUTPUT — Copy directly into your Overleaf document")
    print("="*80)

    generate_latex_tables(algo_df, latency_df, detailed_df)

    # ── 5. Visualisation Plots ───────────────────────────────
    generate_plots(algo_df, latency_df, detailed_df, df)

    print(f"\n  Analysis complete. Outputs saved to: {OUTPUT_DIR}/")


# ═════════════════════════════════════════════════════════════
# LaTeX TABLE GENERATION
# ═════════════════════════════════════════════════════════════

def generate_latex_tables(
    algo_df: pd.DataFrame,
    latency_df: pd.DataFrame,
    detailed_df: pd.DataFrame,
) -> None:
    """Generate publication-ready LaTeX tabular code."""

    # ── Table I: Detection Rates ─────────────────────────────
    latex_table1 = r"""
% ──────────────────────────────────────────────────────
% TABLE I: Detection Metrics Comparison
% Auto-generated by compute_metrics.py
% ──────────────────────────────────────────────────────
\begin{table}[htbp]
\centering
\caption{Detection Metrics Comparison of Rate-Limiting Algorithms Against Credential Stuffing Attacks}
\label{tab:detection_metrics}
\begin{tabular}{lcccccc}
\hline
\textbf{Algorithm} & \textbf{TP} & \textbf{FP} & \textbf{TN} & \textbf{FN} & \textbf{Detection Rate} & \textbf{FPR} \\
\hline
"""
    for _, row in algo_df.iterrows():
        latex_table1 += (
            f"{row['Algorithm'].replace('_', ' ').title()} & "
            f"{row['TP']} & {row['FP']} & {row['TN']} & {row['FN']} & "
            f"{row['Detection_Rate']:.4f} & {row['FPR']:.4f} \\\\\n"
        )
    latex_table1 += r"""\hline
\end{tabular}
\end{table}
"""
    print("\n% ═══ TABLE I ═══")
    print(latex_table1)

    # ── Table II: Precision, F1, Accuracy ────────────────────
    latex_table2 = r"""
% ──────────────────────────────────────────────────────
% TABLE II: Precision, F1-Score, and Accuracy
% Auto-generated by compute_metrics.py
% ──────────────────────────────────────────────────────
\begin{table}[htbp]
\centering
\caption{Classification Performance of Rate-Limiting Algorithms}
\label{tab:classification_performance}
\begin{tabular}{lccc}
\hline
\textbf{Algorithm} & \textbf{Precision} & \textbf{F1-Score} & \textbf{Accuracy} \\
\hline
"""
    for _, row in algo_df.iterrows():
        latex_table2 += (
            f"{row['Algorithm'].replace('_', ' ').title()} & "
            f"{row['Precision']:.4f} & {row['F1_Score']:.4f} & "
            f"{row['Accuracy']:.4f} \\\\\n"
        )
    latex_table2 += r"""\hline
\end{tabular}
\end{table}
"""
    print("\n% ═══ TABLE II ═══")
    print(latex_table2)

    # ── Table III: Latency Overhead ──────────────────────────
    latex_table3 = r"""
% ──────────────────────────────────────────────────────
% TABLE III: Latency Overhead Comparison
% Auto-generated by compute_metrics.py
% ──────────────────────────────────────────────────────
\begin{table}[htbp]
\centering
\caption{Latency Overhead of Rate-Limiting Algorithms (milliseconds)}
\label{tab:latency_overhead}
\begin{tabular}{lcccc}
\hline
\textbf{Algorithm} & \textbf{Mean} & \textbf{Median (P50)} & \textbf{P95} & \textbf{P99} \\
\hline
"""
    for _, row in latency_df.iterrows():
        latex_table3 += (
            f"{row['Algorithm'].replace('_', ' ').title()} & "
            f"{row['Mean_ms']:.2f} & {row['Median_ms']:.2f} & "
            f"{row['P95_ms']:.2f} & {row['P99_ms']:.2f} \\\\\n"
        )
    latex_table3 += r"""\hline
\end{tabular}
\end{table}
"""
    print("\n% ═══ TABLE III ═══")
    print(latex_table3)

    # ── Table IV: Per-Profile Breakdown ──────────────────────
    latex_table4 = r"""
% ──────────────────────────────────────────────────────
% TABLE IV: Detection Rates by Traffic Profile
% Auto-generated by compute_metrics.py
% ──────────────────────────────────────────────────────
\begin{table}[htbp]
\centering
\caption{Detection Rates by Algorithm and Traffic Profile}
\label{tab:per_profile_detection}
\begin{tabular}{llcccc}
\hline
\textbf{Algorithm} & \textbf{Traffic Profile} & \textbf{Detection Rate} & \textbf{FPR} & \textbf{Precision} & \textbf{F1} \\
\hline
"""
    for _, row in detailed_df.iterrows():
        algo_name = row["Algorithm"].replace("_", " ").title()
        traffic_name = row["Traffic_Type"].replace("_", " ").title()
        latex_table4 += (
            f"{algo_name} & {traffic_name} & "
            f"{row['Detection_Rate']:.4f} & {row['FPR']:.4f} & "
            f"{row['Precision']:.4f} & {row['F1_Score']:.4f} \\\\\n"
        )
    latex_table4 += r"""\hline
\end{tabular}
\end{table}
"""
    print("\n% ═══ TABLE IV ═══")
    print(latex_table4)

    # ── Save all LaTeX to a file ─────────────────────────────
    all_latex = latex_table1 + latex_table2 + latex_table3 + latex_table4
    latex_path = OUTPUT_DIR / "latex_tables.tex"
    with open(latex_path, "w", encoding="utf-8") as f:
        f.write(all_latex)
    print(f"\n  LaTeX tables saved to: {latex_path}")


# ═════════════════════════════════════════════════════════════
# VISUALISATION PLOTS
# ═════════════════════════════════════════════════════════════

def generate_plots(
    algo_df: pd.DataFrame,
    latency_df: pd.DataFrame,
    detailed_df: pd.DataFrame,
    raw_df: pd.DataFrame,
) -> None:
    """Generate publication-quality plots for the research paper."""

    sns.set_theme(style="whitegrid", font_scale=1.2)
    palette = sns.color_palette("viridis", n_colors=3)

    # ── Plot 1: Detection Metrics Comparison (Grouped Bar) ───
    fig, ax = plt.subplots(figsize=(10, 6))
    metrics_to_plot = ["Detection_Rate", "Precision", "F1_Score", "Accuracy"]
    x = np.arange(len(algo_df))
    width = 0.2

    for i, metric in enumerate(metrics_to_plot):
        bars = ax.bar(
            x + i * width, algo_df[metric], width,
            label=metric.replace("_", " "),
            color=sns.color_palette("Set2", n_colors=4)[i],
            edgecolor="black", linewidth=0.5,
        )
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f"{height:.3f}",
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points",
                        ha="center", va="bottom", fontsize=8)

    ax.set_xlabel("Rate-Limiting Algorithm")
    ax.set_ylabel("Score")
    ax.set_title("Detection Metrics Comparison Across Algorithms")
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels([a.replace("_", "\n").title() for a in algo_df["Algorithm"]])
    ax.legend(loc="lower right")
    ax.set_ylim(0, 1.15)
    plt.tight_layout()
    fig.savefig(OUTPUT_DIR / "detection_metrics_comparison.png", dpi=300)
    plt.close(fig)
    print("  Generated: detection_metrics_comparison.png")

    # ── Plot 2: Latency Distribution (Box Plot) ─────────────
    fig, ax = plt.subplots(figsize=(10, 6))
    latency_data = []
    for algo in sorted(raw_df["algorithm"].unique()):
        subset = raw_df[raw_df["algorithm"] == algo]["latency_ms"].dropna()
        for val in subset:
            latency_data.append({"Algorithm": algo.replace("_", " ").title(), "Latency (ms)": val})

    if latency_data:
        lat_plot_df = pd.DataFrame(latency_data)
        sns.boxplot(data=lat_plot_df, x="Algorithm", y="Latency (ms)",
                    palette="viridis", ax=ax, showfliers=False)
        ax.set_title("Latency Distribution by Algorithm")
        plt.tight_layout()
        fig.savefig(OUTPUT_DIR / "latency_distribution.png", dpi=300)
    plt.close(fig)
    print("  Generated: latency_distribution.png")

    # ── Plot 3: Heatmap — Detection Rate by Algorithm × Profile ──
    if not detailed_df.empty:
        fig, ax = plt.subplots(figsize=(12, 6))
        pivot = detailed_df.pivot_table(
            index="Algorithm", columns="Traffic_Type",
            values="Detection_Rate", aggfunc="first",
        )
        sns.heatmap(
            pivot, annot=True, fmt=".3f", cmap="YlOrRd",
            linewidths=0.5, ax=ax, vmin=0, vmax=1,
        )
        ax.set_title("Detection Rate Heatmap: Algorithm × Traffic Profile")
        ax.set_xlabel("Traffic Profile")
        ax.set_ylabel("Algorithm")
        plt.tight_layout()
        fig.savefig(OUTPUT_DIR / "detection_heatmap.png", dpi=300)
        plt.close(fig)
        print("  Generated: detection_heatmap.png")

    # ── Plot 4: Confusion Matrix Heatmaps (one per algorithm) ──
    for algo in sorted(raw_df["algorithm"].unique()):
        subset = raw_df[raw_df["algorithm"] == algo]
        cm = compute_confusion_matrix(subset)

        fig, ax = plt.subplots(figsize=(6, 5))
        matrix = np.array([[cm["TP"], cm["FN"]], [cm["FP"], cm["TN"]]])
        sns.heatmap(
            matrix, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Blocked", "Allowed"],
            yticklabels=["Attack", "Legitimate"],
            ax=ax, linewidths=1, cbar_kws={"label": "Count"},
        )
        ax.set_title(f"Confusion Matrix — {algo.replace('_', ' ').title()}")
        ax.set_xlabel("Predicted (Rate Limiter Decision)")
        ax.set_ylabel("Actual (Ground Truth)")
        plt.tight_layout()
        fig.savefig(OUTPUT_DIR / f"confusion_matrix_{algo}.png", dpi=300)
        plt.close(fig)
        print(f"  Generated: confusion_matrix_{algo}.png")

    # ── Plot 5: FPR vs Detection Rate (ROC-style scatter) ────
    fig, ax = plt.subplots(figsize=(8, 6))
    for i, (_, row) in enumerate(algo_df.iterrows()):
        ax.scatter(
            row["FPR"], row["Detection_Rate"],
            s=200, zorder=5, color=palette[i % len(palette)],
            edgecolors="black", linewidth=1,
        )
        ax.annotate(
            row["Algorithm"].replace("_", " ").title(),
            (row["FPR"], row["Detection_Rate"]),
            xytext=(10, 10), textcoords="offset points", fontsize=10,
        )
    ax.plot([0, 1], [0, 1], "k--", alpha=0.3, label="Random Classifier")
    ax.set_xlabel("False Positive Rate (FPR)")
    ax.set_ylabel("Detection Rate (Recall)")
    ax.set_title("FPR vs Detection Rate — Algorithm Comparison")
    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.05, 1.05)
    ax.legend()
    plt.tight_layout()
    fig.savefig(OUTPUT_DIR / "fpr_vs_detection_rate.png", dpi=300)
    plt.close(fig)
    print("  Generated: fpr_vs_detection_rate.png")


# ═════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  Rate-Limiter Effectiveness Analysis                    ║")
    print("║  Confusion Matrix & Latency Metrics                     ║")
    print("║  Author: Soham Adsare | Guide: Dr. Dhanashree Patil    ║")
    print("╚══════════════════════════════════════════════════════════╝")
    run_analysis()
