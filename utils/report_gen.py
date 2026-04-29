# report_gen.py
# ============================================================================
# PDF REPORT GENERATION
# Mirrors the GUI export functionality.
# Usage:
#   from report_gen import generate_pdf_report
#   generate_pdf_report(output_dir, pdf_path)
# ============================================================================

import sys
from pathlib import Path

from palette import (
    BG_ROOT, BG_CARD, BG_ROW_A, BG_ROW_B, BG_HEADER, BG_TOTALS,
    BG_CRASH_BOX, BG_META_BOX,
    ACCENT, ACCENT2, ACCENT_WARN, ACCENT_ERR, ACCENT_HANG, ACCENT_PURP,
    ACCENT_GREEN,
    TEXT_MAIN, TEXT_DIM, TEXT_BRIGHT,
    BORDER, CHART_COLORS,
)


# ============================================================================
# STATS PARSING
# ============================================================================

def _parse_stats_file(path: Path) -> dict:
    """Parse a single AFL++ fuzzer_stats file into a key/value dict."""
    d = {}
    try:
        with open(path) as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    d[k.strip()] = v.strip()
    except Exception:
        pass
    return d


def _parse_all_stats(output_dir: str):
    """
    Scan output_dir recursively for fuzzer_stats files.
    Returns (merged_dict, [per_instance_dicts]).
    """
    out = Path(output_dir)
    stats_files = sorted(out.rglob("fuzzer_stats"))

    instances = []
    for f in stats_files:
        parsed = _parse_stats_file(f)
        if parsed:
            parsed["_label"] = f.parent.name
            instances.append(parsed)

    if not instances:
        return None, []

    def ival(d, k):
        try: return int(d.get(k, 0))
        except: return 0

    def fval(d, k):
        try: return float(d.get(k, 0))
        except: return 0.0

    merged = {
        "execs_done":     sum(ival(i, "execs_done")     for i in instances),
        "execs_per_sec":  sum(fval(i, "execs_per_sec")  for i in instances),
        "paths_total":    sum(ival(i, "paths_total")     for i in instances),
        "unique_crashes": sum(ival(i, "unique_crashes")  for i in instances),
        "unique_hangs":   sum(ival(i, "unique_hangs")    for i in instances),
        "cycles_done":    sum(ival(i, "cycles_done")     for i in instances),
        "corpus_count":   sum(ival(i, "corpus_count")    for i in instances),
        "saved_crashes":  sum(ival(i, "saved_crashes")   for i in instances),
        "saved_hangs":    sum(ival(i, "saved_hangs")     for i in instances),
        "peak_rss_mb":    sum(ival(i, "peak_rss_mb")     for i in instances),
        "max_depth":      max(ival(i, "max_depth")       for i in instances),
        "start_time":     instances[0].get("start_time",   ""),
        "last_update":    instances[0].get("last_update",  ""),
        "afl_banner":     instances[0].get("afl_banner",   ""),
        "command_line":   instances[0].get("command_line", ""),
        "target_mode":    instances[0].get("target_mode",  ""),
        "stability":      instances[0].get("stability",    ""),
        "bitmap_cvg":     instances[0].get("bitmap_cvg",   ""),
    }

    try:
        start = int(instances[0].get("start_time", 0))
        end   = int(instances[0].get("last_update", 0))
        merged["run_time_sec"] = end - start if end > start else 0
    except Exception:
        merged["run_time_sec"] = 0

    return merged, instances


def _count_crash_files(output_dir: str):
    """Return (crash_count, hang_count, crash_paths[:20], hang_paths[:10])."""
    out = Path(output_dir)
    crashes = list(out.rglob("crashes/id:*"))
    hangs   = list(out.rglob("hangs/id:*"))
    return len(crashes), len(hangs), crashes[:20], hangs[:10]


def _format_duration(seconds: int) -> str:
    seconds = int(seconds)
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    if h > 0:
        return f"{h}h {m}m {s}s"
    elif m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


# ============================================================================
# CHART RENDERING
# ============================================================================

def _render_charts_image(merged: dict, instances: list):
    """Render the five-panel performance chart to an in-memory PNG buffer."""
    import io
    import numpy as np
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    def ival(d, k):
        try: return int(d.get(k, 0))
        except: return 0

    def fval(d, k):
        try: return float(d.get(k, 0))
        except: return 0.0

    labels      = [i.get("_label", f"inst{n}") for n, i in enumerate(instances)]
    paths_vals  = [ival(i, "paths_total")    for i in instances]
    eps_vals    = [fval(i, "execs_per_sec")  for i in instances]
    crash_vals  = [ival(i, "unique_crashes") for i in instances]
    hang_vals   = [ival(i, "unique_hangs")   for i in instances]
    corpus_vals = [ival(i, "corpus_count")   for i in instances]
    depth_vals  = [ival(i, "max_depth")      for i in instances]

    n          = len(labels)
    x          = np.arange(n)
    bar_colors = [CHART_COLORS[i % len(CHART_COLORS)] for i in range(n)]

    TEXT_SUBTLE = "#94a3b8"

    fig = plt.figure(figsize=(16, 10), facecolor=BG_ROOT)
    gs  = fig.add_gridspec(3, 2, height_ratios=[1.2, 1, 1], hspace=0.55, wspace=0.3)

    ax_paths   = fig.add_subplot(gs[0, :])
    ax_eps     = fig.add_subplot(gs[1, 0])
    ax_crashes = fig.add_subplot(gs[1, 1])
    ax_corpus  = fig.add_subplot(gs[2, 0])
    ax_depth   = fig.add_subplot(gs[2, 1])

    def style_ax(ax, title):
        ax.set_facecolor(BG_CARD)
        ax.set_title(title, color=TEXT_BRIGHT, fontsize=12, pad=10, weight="bold")
        ax.tick_params(colors=TEXT_SUBTLE, labelsize=9)
        for spine in ax.spines.values():
            spine.set_edgecolor(BORDER)
        ax.grid(axis="x", linestyle="--", alpha=0.15, color=BORDER)

    style_ax(ax_paths, "Coverage Growth (Paths Found per Instance)")
    bars    = ax_paths.barh(labels, paths_vals, color=bar_colors, edgecolor=BORDER, height=0.6)
    max_val = max(paths_vals) if paths_vals else 1
    for bar, val in zip(bars, paths_vals):
        ax_paths.text(
            bar.get_width() + max_val * 0.01,
            bar.get_y() + bar.get_height() / 2,
            f"{val:,}", va="center", ha="left", color=TEXT_SUBTLE, fontsize=10,
        )
    ax_paths.set_xlabel("Total Paths Discovered", color=TEXT_DIM, fontsize=10)

    style_ax(ax_eps, "Execution Throughput (exec/sec)")
    ax_eps.bar(x, eps_vals, color=bar_colors, edgecolor=BORDER)
    ax_eps.set_xticks(x); ax_eps.set_xticklabels(labels, rotation=30, ha="right")
    ax_eps.set_ylabel("exec/sec", color=TEXT_DIM, fontsize=10)

    style_ax(ax_crashes, "Stability (Crashes & Hangs)")
    w = 0.4
    ax_crashes.bar(x - w/2, crash_vals, w, label="Crashes", color=ACCENT_ERR,  edgecolor=BORDER)
    ax_crashes.bar(x + w/2, hang_vals,  w, label="Hangs",   color=ACCENT_HANG, edgecolor=BORDER)
    ax_crashes.set_xticks(x); ax_crashes.set_xticklabels(labels, rotation=30, ha="right")
    ax_crashes.legend(frameon=False, fontsize=9, labelcolor=TEXT_SUBTLE)
    ax_crashes.set_ylabel("Count", color=TEXT_DIM, fontsize=10)

    style_ax(ax_corpus, "Corpus Growth")
    ax_corpus.bar(x, corpus_vals, color=bar_colors, edgecolor=BORDER)
    ax_corpus.set_xticks(x); ax_corpus.set_xticklabels(labels, rotation=30, ha="right")
    ax_corpus.set_ylabel("Inputs", color=TEXT_DIM, fontsize=10)

    style_ax(ax_depth, "Exploration Depth")
    ax_depth.bar(x, depth_vals, color=bar_colors, edgecolor=BORDER)
    ax_depth.set_xticks(x); ax_depth.set_xticklabels(labels, rotation=30, ha="right")
    ax_depth.set_ylabel("Call Depth", color=TEXT_DIM, fontsize=10)

    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=220, facecolor=BG_ROOT, bbox_inches="tight")
    buf.seek(0)
    plt.close(fig)
    return buf


# ============================================================================
# PDF GENERATION (public API)
# ============================================================================

def generate_pdf_report(output_dir: str, pdf_path: str) -> None:
    """
    Read fuzzer_stats from output_dir and write a PDF report to pdf_path.
    Identical output to the GUI's Export PDF button.
    """
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, Image,
    )

    print(f"[*] Scanning for fuzzer_stats in: {output_dir}")
    merged, instances = _parse_all_stats(output_dir)

    if not merged:
        print("[!] No fuzzer_stats files found — nothing to report.")
        sys.exit(1)

    print(f"[*] Found {len(instances)} instance(s). Building report...")

    def C(h): return colors.HexColor(h)

    W, H   = letter
    MARGIN = 0.55 * inch

    doc = SimpleDocTemplate(
        pdf_path, pagesize=letter,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=MARGIN,
    )

    def bg_canvas(canv, doc):
        canv.saveState()
        canv.setFillColor(C(BG_ROOT))
        canv.rect(0, 0, W, H, fill=1, stroke=0)
        canv.restoreState()

    def sty(name, font="Courier", size=10, color=None, bold=False,
            leading=None, space_before=0, space_after=4, align=0):
        if color is None:
            color = C(TEXT_MAIN)
        return ParagraphStyle(
            name,
            fontName="Courier-Bold" if bold else font,
            fontSize=size,
            textColor=color,
            leading=leading or size * 1.35,
            spaceAfter=space_after,
            spaceBefore=space_before,
            alignment=align,
        )

    def ival(d, k):
        try: return int(d.get(k, 0))
        except: return 0

    def fval(d, k):
        try: return float(d.get(k, 0))
        except: return 0.0

    run_time = _format_duration(merged.get("run_time_sec", 0))
    crash_count, hang_count, crash_files, hang_files = _count_crash_files(output_dir)

    story = []

    # ── Title ─────────────────────────────────────────────────────────────
    story.append(Paragraph(
        "AFL++ Fuzzing Report",
        sty("title", size=20, color=C(ACCENT2), bold=True, space_before=2, space_after=2),
    ))
    story.append(Paragraph(
        f"{len(instances)} instance(s) combined  ·  Output: {output_dir}",
        sty("subtitle", size=10, color=C(TEXT_DIM), space_after=8),
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=C(ACCENT2), spaceAfter=10))

    # ── Summary cards ─────────────────────────────────────────────────────
    story.append(Paragraph(
        "SUMMARY",
        sty("section", size=12, color=C(ACCENT2), bold=True, space_before=14, space_after=4),
    ))
    cards = [
        ("EXECUTIONS",     f"{merged['execs_done']:,}",        C(ACCENT2)),
        ("EXEC / SEC",     f"{merged['execs_per_sec']:,.1f}",  C(ACCENT)),
        ("PATHS FOUND",    f"{merged['paths_total']:,}",       C(ACCENT_WARN)),
        ("UNIQUE CRASHES", f"{merged['unique_crashes']:,}",    C(ACCENT_ERR)  if merged['unique_crashes'] > 0 else C(TEXT_DIM)),
        ("UNIQUE HANGS",   f"{merged['unique_hangs']:,}",      C(ACCENT_HANG) if merged['unique_hangs']   > 0 else C(TEXT_DIM)),
        ("CYCLES DONE",    f"{merged['cycles_done']:,}",       C(ACCENT_PURP)),
        ("RUN TIME",       run_time,                           C(ACCENT_GREEN)),
        ("CORPUS SIZE",    f"{merged['corpus_count']:,}",      C(TEXT_BRIGHT)),
    ]
    CARD_W = (W - MARGIN * 2) / 4

    def card_cell(label, value, color):
        inner = Table(
            [[Paragraph(value, sty("cv", size=16, color=color, bold=True, align=1))],
             [Paragraph(label, sty("cl", size=7,  color=C(TEXT_DIM), align=1))]],
            colWidths=[CARD_W - 8],
        )
        inner.setStyle(TableStyle([
            ("ALIGN",         (0,0), (-1,-1), "CENTER"),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ]))
        return inner

    for row_cards in [cards[:4], cards[4:]]:
        row_data  = [[card_cell(l, v, c) for l, v, c in row_cards]]
        row_table = Table(row_data, colWidths=[CARD_W] * 4)
        row_table.setStyle(TableStyle([
            ("BACKGROUND",     (0,0), (-1,-1), C(BG_CARD)),
            ("GRID",           (0,0), (-1,-1), 0.5, C(BG_ROOT)),
            ("ROUNDEDCORNERS", [4]),
            ("VALIGN",         (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",     (0,0), (-1,-1), 0),
            ("BOTTOMPADDING",  (0,0), (-1,-1), 0),
        ]))
        story.append(row_table)
        story.append(Spacer(1, 4))

    # ── Charts ────────────────────────────────────────────────────────────
    story.append(Paragraph(
        "COVERAGE &amp; PERFORMANCE",
        sty("section", size=12, color=C(ACCENT2), bold=True, space_before=14, space_after=4),
    ))
    chart_buf = _render_charts_image(merged, instances)
    if chart_buf:
        img = Image(chart_buf, width=W - MARGIN * 2, height=(W - MARGIN * 2) * 0.6)
        story.append(img)
        story.append(Spacer(1, 6))

    # ── Per-instance table ────────────────────────────────────────────────
    story.append(Paragraph(
        "PER-INSTANCE BREAKDOWN",
        sty("section", size=12, color=C(ACCENT2), bold=True, space_before=14, space_after=4),
    ))
    headers = ["Instance", "Execs", "Exec/s", "Paths", "Crashes",
               "Hangs", "Cycles", "Corpus", "Depth", "Stability", "Coverage"]
    col_w   = [1.1*inch, 0.85*inch, 0.65*inch, 0.65*inch, 0.65*inch,
               0.65*inch, 0.6*inch, 0.65*inch, 0.6*inch, 0.7*inch, 0.7*inch]

    def hdr_p(t):
        return Paragraph(t, sty("th", size=8, color=C(ACCENT2), bold=True, align=1))

    def cell_p(t, color=None):
        if color is None:
            color = C(TEXT_MAIN)
        return Paragraph(t, sty("td", size=8, color=color, align=1))

    table_data = [[hdr_p(h) for h in headers]]
    for n, inst in enumerate(instances):
        table_data.append([
            cell_p(inst.get("_label", f"inst{n}")),
            cell_p(f"{ival(inst,'execs_done'):,}"),
            cell_p(f"{fval(inst,'execs_per_sec'):,.1f}"),
            cell_p(f"{ival(inst,'paths_total'):,}"),
            cell_p(f"{ival(inst,'unique_crashes'):,}", C(ACCENT_ERR)  if ival(inst,'unique_crashes') > 0 else None),
            cell_p(f"{ival(inst,'unique_hangs'):,}",  C(ACCENT_HANG) if ival(inst,'unique_hangs')   > 0 else None),
            cell_p(f"{ival(inst,'cycles_done'):,}"),
            cell_p(f"{ival(inst,'corpus_count'):,}"),
            cell_p(f"{ival(inst,'max_depth'):,}"),
            cell_p(inst.get("stability",  "n/a")),
            cell_p(inst.get("bitmap_cvg", "n/a")),
        ])
    table_data.append([
        cell_p("COMBINED",                         C(ACCENT_WARN)),
        cell_p(f"{merged['execs_done']:,}",        C(ACCENT_WARN)),
        cell_p(f"{merged['execs_per_sec']:,.1f}",  C(ACCENT_WARN)),
        cell_p(f"{merged['paths_total']:,}",       C(ACCENT_WARN)),
        cell_p(f"{merged['unique_crashes']:,}",    C(ACCENT_WARN)),
        cell_p(f"{merged['unique_hangs']:,}",      C(ACCENT_WARN)),
        cell_p(f"{merged['cycles_done']:,}",       C(ACCENT_WARN)),
        cell_p(f"{merged['corpus_count']:,}",      C(ACCENT_WARN)),
        cell_p(f"{merged['max_depth']:,}",         C(ACCENT_WARN)),
        cell_p("—",                                C(ACCENT_WARN)),
        cell_p("—",                                C(ACCENT_WARN)),
    ])

    n_inst = len(instances)
    row_styles = [
        ("BACKGROUND",    (0, 0),        (-1, 0),        C(BG_HEADER)),
        ("BACKGROUND",    (0, n_inst+1), (-1, n_inst+1), C(BG_TOTALS)),
        ("GRID",          (0, 0),        (-1, -1),        0.4, C(BORDER)),
        ("TOPPADDING",    (0, 0),        (-1, -1),        4),
        ("BOTTOMPADDING", (0, 0),        (-1, -1),        4),
        ("VALIGN",        (0, 0),        (-1, -1),        "MIDDLE"),
    ]
    for i in range(1, n_inst + 1):
        bg = C(BG_ROW_A) if i % 2 == 1 else C(BG_ROW_B)
        row_styles.append(("BACKGROUND", (0, i), (-1, i), bg))
    tbl = Table(table_data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle(row_styles))
    story.append(tbl)

    # ── Crash / hang listing ──────────────────────────────────────────────
    if crash_files or hang_files:
        story.append(Paragraph(
            "CRASH &amp; HANG FILES",
            sty("cs", size=12, color=C(ACCENT_ERR), bold=True, space_before=14, space_after=4),
        ))
        crash_lines = []
        if crash_files:
            crash_lines.append(f"── CRASHES ({len(crash_files)} shown) ──")
            crash_lines += [f"  {f}" for f in crash_files]
        if hang_files:
            crash_lines.append(f"── HANGS ({len(hang_files)} shown) ──")
            crash_lines += [f"  {f}" for f in hang_files]
        crash_tbl = Table(
            [[Paragraph("<br/>".join(str(l) for l in crash_lines),
                        sty("cr", size=8, color=C("#f87171")))]],
            colWidths=[W - MARGIN * 2],
        )
        crash_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), C(BG_CRASH_BOX)),
            ("TOPPADDING",    (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ]))
        story.append(crash_tbl)

    # ── Metadata table ────────────────────────────────────────────────────
    story.append(Paragraph(
        "RUN METADATA",
        sty("section", size=12, color=C(ACCENT2), bold=True, space_before=14, space_after=4),
    ))
    meta_rows = [
        ("Target",        merged.get("afl_banner",   "n/a")),
        ("Command",       merged.get("command_line", "n/a")),
        ("Target mode",   merged.get("target_mode",  "n/a")),
        ("Run time",      run_time),
        ("Peak RSS",      f"{merged.get('peak_rss_mb', 0)} MB (combined)"),
        ("Saved crashes", str(merged.get("saved_crashes", 0))),
        ("Saved hangs",   str(merged.get("saved_hangs",   0))),
        ("Output dir",    str(output_dir)),
    ]
    meta_tbl_data = [
        [Paragraph(k, sty("mk", size=9, color=C(ACCENT),    bold=True)),
         Paragraph(v, sty("mv", size=9, color=C(TEXT_MAIN)))]
        for k, v in meta_rows
    ]
    meta_tbl = Table(meta_tbl_data, colWidths=[1.3*inch, W - MARGIN*2 - 1.3*inch])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C(BG_META_BOX)),
        ("GRID",          (0,0), (-1,-1), 0.3, C(BORDER)),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))
    story.append(meta_tbl)

    doc.build(story, onFirstPage=bg_canvas, onLaterPages=bg_canvas)
    print(f"[*] Report saved to: {pdf_path}")
