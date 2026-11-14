"""Chart rendering for the evaluation dashboard (matplotlib only).

No pandas: the aggregation is a few lines of dict arithmetic, which keeps the
project runnable on machines where optional compiled extensions are restricted.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless: never open a window
import matplotlib.pyplot as plt  # noqa: E402

NAVY = "#0d2136"
TEAL = "#0f766e"
ORANGE = "#ea7317"
GREY = "#94a3b8"

CONFIG_LABELS = {
    "baseline": "Baseline",
    "rules": "Rules only",
    "full": "Full PolicyGuard",
}


def _style(ax, title: str, ylabel: str) -> None:
    ax.set_title(title, fontsize=12, fontweight="bold", color=NAVY)
    ax.set_ylabel(ylabel, fontsize=9, color="#475569")
    ax.tick_params(labelsize=8, colors="#475569")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", color="#e2e8f0", linewidth=0.8)
    ax.set_axisbelow(True)


def _category_rates(per_case: list[dict], configs: list[str]) -> tuple[list[str], dict[str, list[float]]]:
    categories = sorted({row["category"] for row in per_case if row["category"] != "normal_task"})
    rates: dict[str, list[float]] = {config: [] for config in configs}
    for category in categories:
        for config in configs:
            rows = [r for r in per_case if r["category"] == category and r["config"] == config]
            blocked = sum(1 for r in rows if r["decision"] in ("BLOCK", "REQUIRE_HUMAN_APPROVAL"))
            rates[config].append(round(blocked / len(rows) * 100, 1) if rows else 0.0)
    return categories, rates


def render_charts(metrics: list[dict], per_case: list[dict], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []
    configs = [row["config"] for row in metrics]
    labels = [CONFIG_LABELS.get(name, name) for name in configs]
    colors = [GREY, TEAL, ORANGE][: len(configs)]

    # --- Chart 1: headline metrics -----------------------------------------
    fig, ax = plt.subplots(figsize=(8.2, 4.2), dpi=150)
    series = {
        "Attack blocked %": [row["attack_blocked_rate"] for row in metrics],
        "False positive %": [row["false_positive_rate"] for row in metrics],
        "Task completion %": [row["task_completion_rate"] for row in metrics],
    }
    width = 0.26
    positions = range(len(labels))
    palette = [ORANGE, "#dc2626", TEAL]
    for index, (name, values) in enumerate(series.items()):
        offsets = [position + (index - 1) * width for position in positions]
        bars = ax.bar(offsets, values, width, label=name, color=palette[index])
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, value + 1.5, f"{value:.0f}",
                    ha="center", fontsize=7.5, color="#334155")
    ax.set_xticks(list(positions))
    ax.set_xticklabels(labels, fontsize=8.5)
    ax.set_ylim(0, 110)
    # Legend below the axes: at the top it overlapped the 100% bars.
    ax.legend(fontsize=8, frameon=False, loc="upper center",
              bbox_to_anchor=(0.5, -0.14), ncol=len(series))
    _style(ax, "Security vs. usability across configurations", "percent")
    path = out_dir / "metrics_by_config.png"
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    saved.append(path)

    # --- Chart 2: latency overhead and approval rate ------------------------
    fig, (left, right) = plt.subplots(1, 2, figsize=(9.2, 3.8), dpi=150)
    overhead = [row["latency_overhead_ms"] for row in metrics]
    approvals = [row["approval_rate"] for row in metrics]
    headroom = max(overhead) if max(overhead) > 0 else 0.05

    bars = left.bar(labels, overhead, color=colors)
    for bar, value in zip(bars, overhead):
        left.text(bar.get_x() + bar.get_width() / 2, value + headroom * 0.03,
                  f"{value:.2f} ms", ha="center", fontsize=7.5, color="#334155")
    left.tick_params(axis="x", labelsize=7.5, labelrotation=8)
    _style(left, "Gateway latency overhead", "milliseconds")

    bars = right.bar(labels, approvals, color=colors)
    for bar, value in zip(bars, approvals):
        right.text(bar.get_x() + bar.get_width() / 2, value + 1, f"{value:.0f}%",
                   ha="center", fontsize=7.5, color="#334155")
    right.set_ylim(0, max(100, max(approvals) + 10))
    right.tick_params(axis="x", labelsize=7.5, labelrotation=8)
    _style(right, "Human approval rate", "percent of all cases")

    fig.tight_layout()
    path = out_dir / "latency_and_approval.png"
    fig.savefig(path)
    plt.close(fig)
    saved.append(path)

    # --- Chart 3: blocked rate per attack category -------------------------
    categories, rates = _category_rates(per_case, configs)
    if categories:
        fig, ax = plt.subplots(figsize=(9.4, 4.4), dpi=150)
        width = 0.8 / max(1, len(configs))
        positions = list(range(len(categories)))
        for index, config in enumerate(configs):
            offsets = [position + (index - (len(configs) - 1) / 2) * width for position in positions]
            ax.bar(offsets, rates[config], width, label=CONFIG_LABELS.get(config, config),
                   color=colors[index])
        ax.set_xticks(positions)
        ax.set_xticklabels([category.replace("_", " ") for category in categories], rotation=12, fontsize=8)
        ax.set_ylim(0, 110)
        ax.legend(fontsize=8, frameon=False, loc="upper center",
                  bbox_to_anchor=(0.5, -0.16), ncol=len(configs))
        _style(ax, "Attack containment by category", "percent blocked or escalated")
        fig.tight_layout()
        path = out_dir / "blocked_by_category.png"
        fig.savefig(path, bbox_inches="tight")
        plt.close(fig)
        saved.append(path)

    return saved
