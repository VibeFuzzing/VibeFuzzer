# report_gen.py
# ============================================================================
# PDF REPORT GENERATION
# Mirrors the GUI export functionality.
# Public API:
#   report_gen.run(output_dir, report_out)          ← called by vibefuzzer.py
#   report_gen.generate_pdf_report(output_dir, pdf) ← low-level, called by GUI
# ============================================================================

import sys
from datetime import datetime
from pathlib import Path

from utils.palette import (
    BG_ROOT, BG_CARD, BG_ROW_A, BG_ROW_B, BG_HEADER, BG_TOTALS,
    BG_CRASH_BOX, BG_META_BOX,
    ACCENT, ACCENT2, ACCENT_WARN, ACCENT_ERR, ACCENT_HANG, ACCENT_PURP,
    ACCENT_GREEN,
    TEXT_MAIN, TEXT_DIM, TEXT_BRIGHT,
    BORDER, CHART_COLORS,
)


# ============================================================================
# PUBLIC ENTRY POINT  (called by vibefuzzer.py)
# ============================================================================

def run(output_dir: str, report_out: str = None) -> int:
    """
    Generate a timestamped PDF from output_dir.
    Owns all path/timestamp logic so vibefuzzer.py stays clean.
    Returns 0 on success, 1 on failure.
    """
    import traceback
    if not Path(output_dir).is_dir():
        print(f"[!] Output directory not found: {output_dir}")
        return 1
    report_dir = Path(report_out).resolve() if report_out else Path.cwd()
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp    = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = str(report_dir / f"vibefuzzer_report_{stamp}.pdf")
    try:
        generate_pdf_report(output_dir, pdf_path)
    except Exception as e:
        print(f"[!] Failed to generate report: {e}")
        traceback.print_exc()
        return 1
    return 0


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


def _parse_plot_data(path: Path) -> list:
    """
    Parse AFL++ plot_data CSV into a list of row dicts.
    Handles '# relative_time, ...' or '# unix_time, ...' headers.
    Non-numeric values (e.g. map_size '4.95%') are stored as strings.
    """
    rows = []
    try:
        with open(path) as f:
            raw = f.readline()
            headers = [h.strip() for h in raw.lstrip("# ").strip().split(",")]
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",")
                if len(parts) < len(headers):
                    continue
                row = {}
                for h, v in zip(headers, parts):
                    v = v.strip()
                    try:
                        row[h] = float(v.rstrip("%"))
                    except ValueError:
                        row[h] = 0.0
                rows.append(row)
    except (FileNotFoundError, OSError):
        pass
    return rows


def _parse_all_stats(output_dir: str):
    """
    Scan output_dir recursively for fuzzer_stats files.
    Returns (merged_dict, [per_instance_dicts]).
    Each instance dict also gets '_plot_rows' with parsed plot_data.
    """
    out         = Path(output_dir)
    stats_files = sorted(out.rglob("fuzzer_stats"))

    instances = []
    for f in stats_files:
        parsed = _parse_stats_file(f)
        if parsed:
            parsed["_label"]      = f.parent.name
            parsed["_plot_rows"]  = _parse_plot_data(f.parent / "plot_data")
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
        "execs_done":      sum(ival(i, "execs_done")      for i in instances),
        "execs_per_sec":   sum(fval(i, "execs_per_sec")   for i in instances),
        "paths_total":     sum(ival(i, "corpus_count")     for i in instances),
        "unique_crashes":  sum(ival(i, "unique_crashes")   for i in instances),
        "unique_hangs":    sum(ival(i, "unique_hangs")     for i in instances),
        "cycles_done":     sum(ival(i, "cycles_done")      for i in instances),
        "corpus_count":    sum(ival(i, "corpus_count")     for i in instances),
        "saved_crashes":   sum(ival(i, "saved_crashes")    for i in instances),
        "saved_hangs":     sum(ival(i, "saved_hangs")      for i in instances),
        "peak_rss_mb":     sum(ival(i, "peak_rss_mb")      for i in instances),
        "edges_found":     sum(ival(i, "edges_found")      for i in instances),
        "total_edges":     max(ival(i, "total_edges")      for i in instances),
        "pending_total":   sum(ival(i, "pending_total")    for i in instances),
        "pending_favs":    sum(ival(i, "pending_favs")     for i in instances),
        "corpus_favored":  sum(ival(i, "corpus_favored")   for i in instances),
        "fuzz_time":       sum(ival(i, "fuzz_time")        for i in instances),
        "time_wo_finds":   sum(ival(i, "time_wo_finds")    for i in instances),
        "max_depth":       max(ival(i, "max_depth")        for i in instances),
        "start_time":      instances[0].get("start_time",   ""),
        "last_update":     instances[0].get("last_update",  ""),
        "afl_banner":      instances[0].get("afl_banner",   ""),
        "command_line":    instances[0].get("command_line", ""),
        "target_mode":     instances[0].get("target_mode",  ""),
        "stability":       instances[0].get("stability",    ""),
        "bitmap_cvg":      instances[0].get("bitmap_cvg",   ""),
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
    out     = Path(output_dir)
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
    """
    4-panel bar/stat chart (2x2 grid, no time-series — those live in _render_timeseries_image):
      [0,0] Bitmap coverage % per instance
      [0,1] Edges found vs total edges
      [1,0] Pending queue breakdown
      [1,1] Time efficiency (fuzz vs stall)
    """
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

    def pct_cvg(inst):
        """Parse bitmap_cvg string like '5.51%' → float 5.51"""
        raw = inst.get("bitmap_cvg", "0%").replace("%", "").strip()
        try: return float(raw)
        except: return 0.0

    labels      = [i.get("_label", f"inst{n}") for n, i in enumerate(instances)]
    n           = len(labels)
    x           = np.arange(n)
    bar_colors  = [CHART_COLORS[i % len(CHART_COLORS)] for i in range(n)]
    TEXT_SUBTLE = "#94a3b8"

    fig = plt.figure(figsize=(16, 8), facecolor=BG_ROOT)
    gs  = fig.add_gridspec(2, 2, hspace=0.55, wspace=0.35)

    ax_cvg     = fig.add_subplot(gs[0, 0])   # bitmap coverage % per instance
    ax_edges   = fig.add_subplot(gs[0, 1])   # edges found vs total
    ax_pending = fig.add_subplot(gs[1, 0])   # pending queue breakdown
    ax_time_e  = fig.add_subplot(gs[1, 1])   # time efficiency

    def style_ax(ax, title):
        ax.set_facecolor(BG_CARD)
        ax.set_title(title, color=TEXT_BRIGHT, fontsize=11, pad=10, weight="bold")
        ax.tick_params(colors=TEXT_SUBTLE, labelsize=9)
        for spine in ax.spines.values():
            spine.set_edgecolor(BORDER)
        ax.grid(axis="y", linestyle="--", alpha=0.15, color=BORDER)

    # ── Panel 0: Bitmap coverage % per instance ───────────────────────────
    style_ax(ax_cvg, "Bitmap Coverage % per Instance")
    cvg_vals = [pct_cvg(i) for i in instances]
    bars = ax_cvg.bar(x, cvg_vals, color=bar_colors, edgecolor=BORDER)
    ax_cvg.set_xticks(x)
    ax_cvg.set_xticklabels(labels, rotation=20, ha="right")
    ax_cvg.set_ylabel("Coverage %", color=TEXT_DIM, fontsize=10)
    ax_cvg.set_ylim(0, max(max(cvg_vals) * 1.2, 1))
    for bar, val in zip(bars, cvg_vals):
        ax_cvg.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                    f"{val:.2f}%", ha="center", va="bottom",
                    color=TEXT_SUBTLE, fontsize=9)

    # ── Panel 2: Edges found vs total edges ───────────────────────────────
    style_ax(ax_edges, "Edges Found vs Total Edges")
    edges_found = [ival(i, "edges_found") for i in instances]
    total_edges = [ival(i, "total_edges") for i in instances]
    remaining   = [max(t - f, 0) for f, t in zip(edges_found, total_edges)]
    w = 0.5
    ax_edges.bar(x, edges_found, w, label="Found",     color=bar_colors, edgecolor=BORDER)
    ax_edges.bar(x, remaining,   w, label="Remaining",
                 bottom=edges_found, color="#1e293b",  edgecolor=BORDER, alpha=0.6)
    ax_edges.set_xticks(x)
    ax_edges.set_xticklabels(labels, rotation=20, ha="right")
    ax_edges.set_ylabel("Edges", color=TEXT_DIM, fontsize=10)
    ax_edges.legend(frameon=False, fontsize=9, labelcolor=TEXT_SUBTLE)

    # ── Panel 3: Pending queue breakdown ──────────────────────────────────
    style_ax(ax_pending, "Pending Queue Breakdown")
    pend_total  = [ival(i, "pending_total")   for i in instances]
    pend_favs   = [ival(i, "pending_favs")    for i in instances]
    corp_fav    = [ival(i, "corpus_favored")  for i in instances]
    w = 0.25
    ax_pending.bar(x - w,   pend_total, w, label="Pending total",    color=ACCENT_WARN, edgecolor=BORDER)
    ax_pending.bar(x,       pend_favs,  w, label="Pending favoured", color=ACCENT_PURP, edgecolor=BORDER)
    ax_pending.bar(x + w,   corp_fav,   w, label="Corpus favoured",  color=ACCENT_GREEN,edgecolor=BORDER)
    ax_pending.set_xticks(x)
    ax_pending.set_xticklabels(labels, rotation=20, ha="right")
    ax_pending.set_ylabel("Count", color=TEXT_DIM, fontsize=10)
    ax_pending.legend(frameon=False, fontsize=8, labelcolor=TEXT_SUBTLE)

    # ── Panel 4: Time efficiency ──────────────────────────────────────────
    style_ax(ax_time_e, "Time Efficiency (fuzz vs stall)")
    fuzz_t   = [ival(i, "fuzz_time")     / 3600 for i in instances]  # hours
    stall_t  = [ival(i, "time_wo_finds") / 3600 for i in instances]
    w = 0.35
    ax_time_e.bar(x - w/2, fuzz_t,  w, label="Fuzz time (h)",   color=ACCENT_GREEN, edgecolor=BORDER)
    ax_time_e.bar(x + w/2, stall_t, w, label="Stall time (h)",  color=ACCENT_ERR,   edgecolor=BORDER)
    ax_time_e.set_xticks(x)
    ax_time_e.set_xticklabels(labels, rotation=20, ha="right")
    ax_time_e.set_ylabel("Hours", color=TEXT_DIM, fontsize=10)
    ax_time_e.legend(frameon=False, fontsize=9, labelcolor=TEXT_SUBTLE)

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=220, facecolor=BG_ROOT, bbox_inches="tight")
    buf.seek(0)
    plt.close(fig)
    return buf


def _render_timeseries_image(instances: list):
    """
    Three full-width time-series panels on a separate image (separate PDF page):
      [0] Edges found over time
      [1] Corpus size over time
      [2] Avg exec speed over time  (raw + 10-sample rolling mean overlay)
    """
    import io
    import numpy as np
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    TEXT_SUBTLE = "#94a3b8"

    EDGE_COLS   = ["edges_found", "edges found", "total_edges"]
    CORPUS_COLS = ["corpus_count", "corpus count", "paths_total"]
    EXEC_COLS   = ["execs_per_sec", "execs per sec", "exec_per_sec"]

    def _find_col(row, candidates):
        for c in candidates:
            if c in row:
                return c
        return None

    def _xs(rows):
        if "relative_time" in rows[0]:
            return [r.get("relative_time", 0) / 60 for r in rows]
        t0 = rows[0].get("unix_time", 0)
        return [(r.get("unix_time", 0) - t0) / 60 for r in rows]

    fig, axes = plt.subplots(3, 1, figsize=(16, 11), facecolor=BG_ROOT)
    fig.subplots_adjust(hspace=0.45)

    specs = [
        (axes[0], "Edges Found Over Time",        EDGE_COLS,   "Edges Found", False),
        (axes[1], "Corpus Size Over Time",         CORPUS_COLS, "Corpus Size", False),
        (axes[2], "Exec Speed Over Time (avg/min)",EXEC_COLS,   "Exec / sec",  True),
    ]

    WINDOW = 12  # ~1 minute of samples at ~5s intervals

    for ax, title, col_candidates, ylabel, avg_only in specs:
        ax.set_facecolor(BG_CARD)
        ax.tick_params(colors=TEXT_SUBTLE, labelsize=9)
        ax.set_title(title, color=TEXT_BRIGHT, fontsize=11, pad=10, weight="bold")
        for spine in ax.spines.values():
            spine.set_edgecolor(BORDER)
        ax.grid(linestyle="--", alpha=0.2, color=BORDER)

        any_data = False
        for idx, inst in enumerate(instances):
            rows = inst.get("_plot_rows", [])
            if not rows:
                continue
            col = _find_col(rows[0], col_candidates)
            if col is None:
                continue
            xs    = _xs(rows)
            ys    = [r.get(col, 0) for r in rows]
            color = CHART_COLORS[idx % len(CHART_COLORS)]
            label = inst.get("_label")

            if avg_only and len(ys) >= WINDOW:
                # Centred windowed mean — no edge artifacts
                half = WINDOW // 2
                ys_avg = [
                    sum(ys[max(0, i - half): i + half + 1]) /
                    len(ys[max(0, i - half): i + half + 1])
                    for i in range(len(ys))
                ]
                ax.plot(xs, ys_avg, color=color, linewidth=2.0,
                        label=label, zorder=3)
                ax.fill_between(xs, ys_avg, alpha=0.08, color=color)
            else:
                ax.plot(xs, ys, color=color, linewidth=2.0,
                        label=label, zorder=3)
                ax.fill_between(xs, ys, alpha=0.08, color=color)
            any_data = True

        if any_data:
            ax.legend(frameon=False, fontsize=9, labelcolor=TEXT_SUBTLE)
            ax.set_xlabel("Time (minutes)", color=TEXT_DIM, fontsize=10)
            ax.set_ylabel(ylabel,           color=TEXT_DIM, fontsize=10)
            if avg_only:
                ax.set_ylim(bottom=0)
        else:
            ax.text(0.5, 0.5, "No plot_data available",
                    ha="center", va="center", transform=ax.transAxes,
                    color=TEXT_SUBTLE, fontsize=10)

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=220, facecolor=BG_ROOT, bbox_inches="tight")
    buf.seek(0)
    plt.close(fig)
    return buf


# ============================================================================
# PDF GENERATION (low-level public API, also called by GUI)
# ============================================================================

def generate_pdf_report(output_dir: str, pdf_path: str) -> None:
    """
    Read fuzzer_stats (and plot_data) from output_dir and write a PDF to pdf_path.
    """
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, Image, PageBreak,
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

    # ── Title ──────────────────────────────────────────────────────────────
    story.append(Paragraph(
        "AFL++ Fuzzing Report",
        sty("title", size=20, color=C(ACCENT2), bold=True, space_before=2, space_after=2),
    ))
    story.append(Paragraph(
        f"{len(instances)} instance(s) combined  ·  Output: {output_dir}",
        sty("subtitle", size=10, color=C(TEXT_DIM), space_after=8),
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=C(ACCENT2), spaceAfter=10))

    # ── Summary cards ──────────────────────────────────────────────────────
    story.append(Paragraph(
        "SUMMARY",
        sty("section", size=12, color=C(ACCENT2), bold=True, space_before=14, space_after=4),
    ))

    # Bitmap coverage — pull from primary instance
    bitmap_cvg_str = merged.get("bitmap_cvg", "n/a")

    cards = [
        ("EXECUTIONS",     f"{merged['execs_done']:,}",       C(ACCENT2)),
        ("EXEC / SEC",     f"{merged['execs_per_sec']:,.1f}", C(ACCENT)),
        ("EDGES FOUND",    f"{merged['edges_found']:,}",      C(ACCENT_WARN)),
        ("UNIQUE CRASHES", f"{merged['unique_crashes']:,}",   C(ACCENT_ERR)  if merged['unique_crashes'] > 0 else C(TEXT_DIM)),
        ("UNIQUE HANGS",   f"{merged['unique_hangs']:,}",     C(ACCENT_HANG) if merged['unique_hangs']   > 0 else C(TEXT_DIM)),
        ("BITMAP CVG",     bitmap_cvg_str,                    C(ACCENT_PURP)),
        ("RUN TIME",       run_time,                          C(ACCENT_GREEN)),
        ("CORPUS SIZE",    f"{merged['corpus_count']:,}",     C(TEXT_BRIGHT)),
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

    # ── Time-series charts (flows directly after summary) ─────────────────
    story.append(Paragraph(
        "COVERAGE OVER TIME",
        sty("section", size=12, color=C(ACCENT2), bold=True, space_before=14, space_after=6),
    ))
    ts_buf = _render_timeseries_image(instances)
    if ts_buf:
        # figure is 16×11 → aspect 11/16 = 0.6875 → height ~366pt, fits on page 1
        img_w  = W - MARGIN * 2
        img_ts = Image(ts_buf, width=img_w, height=img_w * (11/16))
        story.append(img_ts)
        story.append(Spacer(1, 6))

    # ── Bar / stat charts ──────────────────────────────────────────────────
    story.append(Paragraph(
        "COVERAGE &amp; PERFORMANCE",
        sty("section", size=12, color=C(ACCENT2), bold=True, space_before=14, space_after=6),
    ))
    chart_buf = _render_charts_image(merged, instances)
    if chart_buf:
        # figure is 16×8 → aspect 0.5
        img_w = W - MARGIN * 2
        img   = Image(chart_buf, width=img_w, height=img_w * 0.5)
        story.append(img)
        story.append(Spacer(1, 6))

    # ── Per-instance table ─────────────────────────────────────────────────
    story.append(Paragraph(
        "PER-INSTANCE BREAKDOWN",
        sty("section", size=12, color=C(ACCENT2), bold=True, space_before=14, space_after=4),
    ))
    headers = ["Instance", "Execs", "Exec/s", "Edges", "Crashes",
               "Hangs", "Cycles", "Corpus", "Bitmap%", "Stability", "Pending"]
    col_w   = [1.0*inch, 0.85*inch, 0.6*inch, 0.7*inch, 0.65*inch,
               0.6*inch, 0.6*inch, 0.65*inch, 0.65*inch, 0.7*inch, 0.65*inch]

    def hdr_p(t):
        return Paragraph(t, sty("th", size=8, color=C(ACCENT2), bold=True, align=1))

    def cell_p(t, color=None):
        if color is None:
            color = C(TEXT_MAIN)
        return Paragraph(t, sty("td", size=8, color=color, align=1))

    table_data = [[hdr_p(h) for h in headers]]
    for n_i, inst in enumerate(instances):
        table_data.append([
            cell_p(inst.get("_label", f"inst{n_i}")),
            cell_p(f"{ival(inst,'execs_done'):,}"),
            cell_p(f"{fval(inst,'execs_per_sec'):,.1f}"),
            cell_p(f"{ival(inst,'edges_found'):,}"),
            cell_p(f"{ival(inst,'unique_crashes'):,}", C(ACCENT_ERR)  if ival(inst,'unique_crashes') > 0 else None),
            cell_p(f"{ival(inst,'unique_hangs'):,}",  C(ACCENT_HANG) if ival(inst,'unique_hangs')   > 0 else None),
            cell_p(f"{ival(inst,'cycles_done'):,}"),
            cell_p(f"{ival(inst,'corpus_count'):,}"),
            cell_p(inst.get("bitmap_cvg", "n/a")),
            cell_p(inst.get("stability",  "n/a")),
            cell_p(f"{ival(inst,'pending_total'):,}"),
        ])
    table_data.append([
        cell_p("COMBINED",                         C(ACCENT_WARN)),
        cell_p(f"{merged['execs_done']:,}",        C(ACCENT_WARN)),
        cell_p(f"{merged['execs_per_sec']:,.1f}",  C(ACCENT_WARN)),
        cell_p(f"{merged['edges_found']:,}",       C(ACCENT_WARN)),
        cell_p(f"{merged['unique_crashes']:,}",    C(ACCENT_WARN)),
        cell_p(f"{merged['unique_hangs']:,}",      C(ACCENT_WARN)),
        cell_p(f"{merged['cycles_done']:,}",       C(ACCENT_WARN)),
        cell_p(f"{merged['corpus_count']:,}",      C(ACCENT_WARN)),
        cell_p("—",                                C(ACCENT_WARN)),
        cell_p("—",                                C(ACCENT_WARN)),
        cell_p(f"{merged['pending_total']:,}",     C(ACCENT_WARN)),
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

    # ── Crash / hang listing ───────────────────────────────────────────────
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

    # ── Metadata table ─────────────────────────────────────────────────────
    story.append(Paragraph(
        "RUN METADATA",
        sty("section", size=12, color=C(ACCENT2), bold=True, space_before=14, space_after=4),
    ))
    meta_rows = [
        ("Target",         merged.get("afl_banner",   "n/a")),
        ("Command",        merged.get("command_line", "n/a")),
        ("Target mode",    merged.get("target_mode",  "n/a")),
        ("Run time",       run_time),
        ("Edges found",    f"{merged.get('edges_found', 0):,} / {merged.get('total_edges', 0):,}"),
        ("Bitmap coverage",merged.get("bitmap_cvg",   "n/a")),
        ("Pending total",  str(merged.get("pending_total", 0))),
        ("Peak RSS",       f"{merged.get('peak_rss_mb', 0)} MB (combined)"),
        ("Saved crashes",  str(merged.get("saved_crashes", 0))),
        ("Saved hangs",    str(merged.get("saved_hangs",   0))),
        ("Output dir",     str(output_dir)),
    ]
    meta_tbl_data = [
        [Paragraph(k, sty("mk", size=9, color=C(ACCENT),    bold=True)),
         Paragraph(v, sty("mv", size=9, color=C(TEXT_MAIN)))]
        for k, v in meta_rows
    ]
    meta_tbl = Table(meta_tbl_data, colWidths=[1.4*inch, W - MARGIN*2 - 1.4*inch])
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