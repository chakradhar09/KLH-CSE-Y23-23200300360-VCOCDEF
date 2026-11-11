#!/usr/bin/env python3
"""Draw the paper's design figures (architecture, custody log, Merkle tree, witness protocol) at IEEE column width.

Writes a PNG (for the .docx) and a PDF (for LaTeX) of each to Doc/figures/. Matplotlib only.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Circle, FancyArrowPatch, FancyBboxPatch

OUT = Path(__file__).resolve().parent.parent / "Doc" / "figures"
COL_W = 3.5  # inches, one IEEE column
INK, MUTED = "#1a1a1a", "#6b6b6b"
CUST, WIT, AUD, GREY = "#e3ebf6", "#e4f0de", "#f5ebdc", "#ececec"
DASH = (0, (4, 2))
MONO = "Courier New"
plt.rcParams.update({"font.family": "Times New Roman", "font.size": 7})


def canvas(h: float):
    fig = plt.figure(figsize=(COL_W, h))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, COL_W)
    ax.set_ylim(0, h)
    ax.set_aspect("equal")
    ax.axis("off")
    return fig, ax


def rect(ax, x, y, w, h, fc="white", ec=INK, lw=0.6, ls="-", r=0.035, z=2):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={r}", fc=fc, ec=ec, lw=lw, ls=ls, zorder=z))


def text(ax, x, y, s, size=7, z=5, **kw):
    ax.text(x, y, s, size=size, zorder=z, linespacing=1.2, **kw)


def module(ax, x, y, w, h, name, desc, fc="white", badges=()):
    """A component box: module name in monospace, one or two lines of description under it."""
    rect(ax, x, y, w, h, fc=fc)
    text(ax, x + w / 2, y + h - 0.06, name, size=6.5, family=MONO, ha="center", va="top", weight="bold")
    lines = name.count("\n") + 1
    text(ax, x + w / 2, y + h - 0.07 - 0.1 * lines, desc, size=6.5, ha="center", va="top")
    for k, n in enumerate(badges):
        badge(ax, x + 0.07 + 0.13 * k, y + h, n)


def badge(ax, x, y, n):
    ax.add_patch(Circle((x, y), 0.052, fc=INK, ec="white", lw=0.4, zorder=8))
    text(ax, x, y, str(n), size=5.5, color="white", weight="bold", ha="center", va="center", z=9)


def arrow(ax, p, q, label=None, at=0.5, dx=0.0, dy=0.03, ls="-", size=6, ha="center", rad=0.0, color=INK):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=6, lw=0.6, color=color, ls=ls,
                                 shrinkA=0, shrinkB=0, connectionstyle=f"arc3,rad={rad}", zorder=6))
    if label:
        x, y = p[0] + (q[0] - p[0]) * at + dx, p[1] + (q[1] - p[1]) * at + dy
        text(ax, x, y, label, size=size, style="italic", ha=ha, va="bottom" if dy >= 0 else "top", color=color)


def save(fig, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / f"{name}.png", dpi=600)
    fig.savefig(OUT / f"{name}.pdf")
    plt.close(fig)


def architecture() -> None:
    fig, ax = canvas(3.62)
    # custodian's machine
    rect(ax, 0.04, 1.8, 3.42, 1.78, fc=CUST, ls=DASH, lw=0.7, r=0.06, z=0)
    text(ax, 0.12, 3.5, "Custodian's machine (lab)", size=7.5, weight="bold", va="top")
    rect(ax, 0.2, 3.02, 3.1, 0.24)
    text(ax, 1.75, 3.14, "cli.py  and  interactive shell  (the same cmd_* functions)", size=6.5, ha="center", va="center")
    xs, w = (0.2, 1.275, 2.35), 0.95
    module(ax, xs[0], 2.38, w, 0.48, "hashing.py", "intake, streaming\nSHA-256, process pool", badges=(1, 2))
    module(ax, xs[1], 2.38, w, 0.48, "merkle.py", "RFC 6962 tree,\ninclusion, consistency", badges=(3,))
    module(ax, xs[2], 2.38, w, 0.48, "hash_chain.py\necdsa_signer.py", "linked, signed log", badges=(4, 5))
    module(ax, 0.2, 1.9, 2.025, 0.32, "db.py", "one SQLite file, append-only triggers", badges=(6,))
    module(ax, xs[2], 1.9, w, 0.32, "checkpoint.py", "signed checkpoint")
    arrow(ax, (0.68, 3.02), (0.68, 2.86), "files, folders", dx=0.04, dy=0.0, ha="left")
    arrow(ax, (xs[0] + w, 2.62), (xs[1], 2.62))
    arrow(ax, (xs[1] + w, 2.62), (xs[2], 2.62))
    arrow(ax, (0.68, 2.38), (0.68, 2.22))
    arrow(ax, (1.75, 2.38), (1.75, 2.22))
    arrow(ax, (2.47, 2.38), (2.15, 2.22))
    arrow(ax, (2.225, 2.06), (xs[2], 2.06))
    # files that leave the custodian's machine
    docs = [(0.2, 1.0, "custody log and\nevidence index (JSON)"), (1.3, 0.8, "anchor.json\n(size, head, root)"),
            (2.35, 0.95, "checkpoint and\nconsistency proof")]
    for x, dw, s in docs:
        rect(ax, x, 1.33, dw, 0.3, r=0.0)
        ax.add_patch(plt.Polygon([(x + dw - 0.08, 1.63), (x + dw, 1.55), (x + dw - 0.08, 1.55)], fc=GREY, ec=INK, lw=0.5, zorder=3))
        text(ax, x + dw / 2 - 0.03, 1.48, s, size=6.2, ha="center", va="center")
    arrow(ax, (0.7, 1.9), (0.7, 1.63), "export", dx=0.04, dy=-0.005, ha="left")
    arrow(ax, (1.7, 1.9), (1.7, 1.63))
    arrow(ax, (2.83, 1.9), (2.83, 1.63))
    # auditor and witnesses
    rect(ax, 0.04, 0.04, 1.62, 1.08, fc=AUD, ls=DASH, lw=0.7, r=0.06, z=0)
    text(ax, 0.12, 0.1, "Auditor's machine", size=7.5, weight="bold", va="bottom")
    module(ax, 0.12, 0.3, 1.32, 0.55, "verifier.py", "recomputes hashes,\nsignatures, roots; checks\nanchor and quorum", badges=(7,))
    rect(ax, 1.76, 0.04, 1.7, 1.08, fc=WIT, ls=DASH, lw=0.7, r=0.06, z=0)
    text(ax, 1.84, 0.1, "Witnesses' machines", size=7.5, weight="bold", va="bottom")
    for x in (1.97, 2.72):
        module(ax, x, 0.3, 0.68, 0.55, "witness.py", "own key and\nstate file;\nnever reads log")
    arrow(ax, (0.7, 1.33), (0.7, 0.85))
    arrow(ax, (1.5, 1.33), (1.2, 0.85))
    arrow(ax, (2.62, 1.33), (2.31, 0.85))
    arrow(ax, (3.05, 1.33), (3.06, 0.85))
    arrow(ax, (1.97, 0.5), (1.44, 0.5))
    text(ax, 1.705, 0.46, "cosigned\ncheckpoint", size=5.5, style="italic", ha="center", va="top",
         bbox=dict(fc="white", ec="none", pad=0.6))
    save(fig, "fig_architecture")


def custody_log() -> None:
    fig, ax = canvas(2.0)
    w, gap, x0, top = 0.76, 0.12, 0.07, 1.9
    rows = [("head", 0.17), ("fields", 0.3), ("prev", 0.15), ("hash", 0.15), ("sig", 0.15)]
    centers = {}
    for i in range(4):
        x = x0 + i * (w + gap)
        new = i == 3
        rect(ax, x, top - sum(h for _, h in rows), w, sum(h for _, h in rows), fc=GREY if new else CUST, r=0.02)
        y = top
        for name, h in rows:
            if name != "head":
                ax.plot([x, x + w], [y, y], color=INK, lw=0.4, zorder=3)
            cy = y - h / 2
            centers[(i, name)] = cy
            label = {"head": f"entry {i}" + (" (new)" if new else ""),
                     "fields": "index, actor, action,\nevidence id(s), time",
                     "prev": "prev = genesis" if i == 0 else "prev_hash",
                     "hash": "entry_hash", "sig": "ECDSA signature"}[name]
            text(ax, x + w / 2, cy, label, size=6.3, ha="center", va="center",
                 weight="bold" if name == "head" else "normal",
                 family=MONO if name in ("prev", "hash") and not (i == 0 and name == "prev") else None)
            y -= h
        if i:
            arrow(ax, (x, centers[(i, "prev")]), (x - gap, centers[(i - 1, "hash")]))
    bottom = top - sum(h for _, h in rows)
    rect(ax, x0, 0.16, 3 * w + 2 * gap, 0.5, fc="white")
    text(ax, x0 + 0.08, 0.6, "Checkpoint (size = 3)", size=6.8, weight="bold", va="top")
    text(ax, x0 + 0.08, 0.47, "log root = RFC 6962 root over entry_hash[0..2],\nchain head, evidence root, time;\n"
         "signed by the custodian, cosigned by witnesses", size=6.3, va="top")
    for i in range(3):
        cx = x0 + i * (w + gap) + w / 2
        arrow(ax, (cx, bottom), (cx, 0.66))
    cx3 = x0 + 3 * (w + gap) + w / 2
    text(ax, cx3, 0.62, "added after the\ncheckpoint:\nnot yet witnessed", size=6.3, style="italic", color=MUTED, ha="center", va="top")
    save(fig, "fig_custody_log")


def merkle_tree() -> None:
    fig, ax = canvas(2.2)
    P = dict(root=(2.0, 2.0), abcF=(1.15, 1.66), ab=(0.62, 1.33), cF=(1.68, 1.33),
             a=(0.4, 1.0), b=(0.84, 1.0), c=(1.46, 1.0), F=(1.9, 1.0), e=(2.95, 1.0),
             s=(2.6, 0.62), s12=(2.25, 0.39), f1=(2.05, 0.14), f2=(2.45, 0.14), f3=(2.98, 0.14))
    edges = [("root", "abcF"), ("root", "e"), ("abcF", "ab"), ("abcF", "cF"), ("ab", "a"), ("ab", "b"),
             ("cF", "c"), ("cF", "F"), ("s", "s12"), ("s", "f3"), ("s12", "f1"), ("s12", "f2")]
    path = {"f2", "s12", "s", "F", "cF", "abcF", "root"}
    sibling = {"f1", "f3", "c", "ab", "e"}
    rect(ax, 1.62, 0.03, 1.84, 0.78, fc="white", ls=DASH, lw=0.6, r=0.05, z=0)
    text(ax, 1.69, 0.74, "folder sub-tree", size=6.3, style="italic", ha="left", va="top")
    for u, v in edges:
        ax.plot(*zip(P[u], P[v]), color=INK, lw=0.6, zorder=1)
    ax.plot(*zip(P["F"], P["s"]), color=INK, lw=0.6, ls=DASH, zorder=1)
    text(ax, 2.71, 0.62, "its root is F", size=6, style="italic", ha="left", va="center")
    text(ax, 2.55, 1.5, "moved up\nunchanged", size=6, style="italic", ha="left", va="center")
    labels = {"root": "", "a": "a", "b": "b", "c": "c", "F": "F", "e": "e", "f1": "f₁", "f2": "f₂", "f3": "f₃"}
    for n, (x, y) in P.items():
        node(ax, x, y, labels.get(n, ""), "path" if n in path else "sib" if n in sibling else "off")
    text(ax, P["root"][0] + 0.11, P["root"][1], "root", size=6.5, ha="left", va="center")
    # legend
    for k, (kind, s) in enumerate([("sib", "hash sent in the proof"), ("path", "recomputed by the verifier"),
                                   ("off", "not needed for this proof")]):
        y = 0.6 - 0.19 * k
        node(ax, 0.16, y, "", kind)
        text(ax, 0.28, y, s, size=6.3, va="center")
    save(fig, "fig_merkle")


def node(ax, x, y, label, kind):
    fc, ec, lw, tc = {"path": ("white", INK, 1.2, INK), "sib": (INK, INK, 0.6, "white"),
                      "off": (GREY, MUTED, 0.5, MUTED)}[kind]
    ax.add_patch(Circle((x, y), 0.075, fc=fc, ec=ec, lw=lw, zorder=4))
    if label:
        text(ax, x, y - 0.005, label, size=6.5, color=tc, ha="center", va="center", style="italic")


def witness_protocol() -> None:
    fig, ax = canvas(3.3)
    cols = {"C": (0.68, "Custodian", CUST), "W": (1.76, "Witness (each)", WIT), "V": (2.84, "Verifier", AUD)}
    for x, title, fc in cols.values():
        rect(ax, x - 0.46, 3.04, 0.92, 0.22, fc=fc)
        text(ax, x, 3.15, title, size=7, weight="bold", ha="center", va="center")
        ax.plot([x, x], [0.04, 3.04], color=MUTED, lw=0.5, ls=DASH, zorder=0)

    def note(col, y, s, n, w=1.12):
        x, _, fc = cols[col]
        h = 0.1 * (s.count("\n") + 1) + 0.09
        rect(ax, x - w / 2, y, w, h, fc=fc)
        text(ax, x - w / 2 + 0.1, y + h - 0.045, s, size=6, va="top")
        badge(ax, x - w / 2 + 0.01, y + h - 0.01, n)

    C, W, V = (cols[k][0] for k in "CWV")
    note("C", 2.52, "sign size, log root, chain\nhead, evidence root, time;\nprove consistency from\nthe last cosigned size", 1)
    arrow(ax, (C, 2.38), (W, 2.38), "checkpoint, proof", dy=0.02)
    note("W", 1.64, "custodian signature valid?\nsame size: same root?\nsmaller: refuse (rollback)\nlarger: proof checks out\nagainst the stored root?", 2)
    arrow(ax, (W, 1.5), (C, 1.5), "refusal; state unchanged", ls=DASH, dy=0.02)
    note("W", 1.15, "save state, then cosign", 3)
    arrow(ax, (W, 1.02), (C, 1.02), "cosignature", dy=0.02)
    arrow(ax, (C, 0.86), (V, 0.86), "log, cosigned checkpoint", at=0.3, dy=0.02)
    note("V", 0.12, "custodian signature valid\nquorum of cosignatures\nroot over first size entries\nevidence root matches\n→ accept; count new entries", 4)
    save(fig, "fig_witness")


if __name__ == "__main__":
    architecture()
    custody_log()
    merkle_tree()
    witness_protocol()
    print("wrote", sorted(p.name for p in OUT.glob("fig_*")))
