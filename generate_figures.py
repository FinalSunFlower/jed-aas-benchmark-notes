"""Publication figures for the Working Note / archive README."""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt

OUT = Path(__file__).with_name("figures")
OUT.mkdir(exist_ok=True)

plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 11,
        "axes.linewidth": 1.2,
        "axes.spines.right": False,
        "axes.spines.top": False,
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    }
)

BLUE = "#0F4D92"
GREEN = "#2E7D4F"
ORANGE = "#C56A1A"
RED = "#B64342"
GRAY = "#4D4D4D"


def save(fig: plt.Figure, name: str) -> None:
    fig.tight_layout(pad=1.2)
    for ext in ("png", "pdf"):
        fig.savefig(OUT / f"{name}.{ext}", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("wrote", OUT / f"{name}.png")


def fig_ablation() -> None:
    rows = [
        ("v131 drop forge/collapse", 77.76),
        ("v133 Gemma-native hop-2", 75.83),
        ("v134 two-world JSON", 83.16),
        ("v144 full replay budget", 89.46),
        ("v137 disjoint URLs", 89.53),
        ("v145 silver stack", 90.33),
        ("v138 lock Gemma verbose", 90.07),
        ("v142 replay frac 1.0", 90.90),
        ("v65 four-family floor", 90.925),
        ("v136 winning-family reset", 91.235),
        ("v141 no warmup subtract", 91.340),
        ("v150 last-day pack", 91.800),
        ("v143 freeze slowest", 92.015),
    ]
    rows = sorted(rows, key=lambda x: x[1])
    labels, scores = zip(*rows)
    colors = [BLUE if s >= 90.9 else RED for s in scores]
    fig, ax = plt.subplots(figsize=(8.4, 5.6))
    ax.barh(labels, scores, color=colors, height=0.68)
    ax.axvline(94.84, color=ORANGE, ls="--", lw=1.1, label="Public silver ~94.84")
    ax.axvline(90.91, color=GREEN, ls=":", lw=1.1, label="Public bronze ~90.91")
    ax.set_xlabel("Public OptimalGuardrail score")
    ax.set_xlim(70, 100)
    ax.set_title("Isolated public A/Bs on the same single-post skeleton")
    ax.legend(frameon=False, loc="lower right")
    for y, s in enumerate(scores):
        ax.text(s + 0.22, y, f"{s:.3f}", va="center", fontsize=8, color=GRAY)
    save(fig, "ablation_public")


def fig_score_vs_n() -> None:
    ns = list(range(0, 1601, 25))
    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    ax.plot(ns, [0.09 * n for n in ns], color=BLUE, lw=2.0, label=r"$0.09N$ (one unique EXFIL)")
    ax.scatter([1010], [90.9], color=GREEN, zorder=3, s=36, label="v65 band (~1010 findings)")
    ax.scatter([1022], [92.015], color=ORANGE, zorder=3, s=42, label="v143 = 92.015")
    ax.scatter([1054], [94.84], color=RED, zorder=3, s=36, label="public silver ~94.84")
    ax.set_xlabel("Replayed single-post findings $N$")
    ax.set_ylabel("Displayed public score")
    ax.set_title("Closed-form public score vs finding count")
    ax.legend(frameon=False, loc="upper left")
    ax.set_xlim(0, 1600)
    ax.set_ylim(0, 150)
    save(fig, "score_vs_n")


def fig_public_private() -> None:
    fig, axes = plt.subplots(1, 2, figsize=(8.6, 3.8))

    ax = axes[0]
    ax.bar(["Public", "Private"], [92.015, 0.0], color=[BLUE, RED], width=0.55)
    ax.set_ylabel("Selected submission score")
    ax.set_title("Same traces, two instruments")
    ax.set_ylim(0, 110)
    ax.text(0, 92.015 + 2.5, "92.015", ha="center", fontsize=9)
    ax.text(1, 2.5, "0.000", ha="center", fontsize=9, color=RED)

    ax = axes[1]
    ax.bar(["Public rank", "Private rank"], [311, 4075], color=[BLUE, RED], width=0.55)
    ax.set_ylabel("Rank (lower is better)")
    ax.set_title("Field size 4187")
    ax.axhline(4187, color=GRAY, ls=":", lw=0.9)
    ax.set_ylim(0, 4500)
    ax.text(0, 311 + 80, "311", ha="center", fontsize=9)
    ax.text(1, 4075 + 80, "4075", ha="center", fontsize=9)
    fig.suptitle("FinalSunFlower after private-leaderboard reveal", fontsize=12, y=1.02)
    save(fig, "public_vs_private")


if __name__ == "__main__":
    fig_ablation()
    fig_score_vs_n()
    fig_public_private()
