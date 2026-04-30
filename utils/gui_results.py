# gui_results.py
# ============================================================================
# ResultsMixin — builds the post-fuzzing results / coverage screen and wires
# the PDF export button.  All stats parsing and chart rendering is delegated
# to report_gen.py so there is no duplicated logic.
# ============================================================================

import customtkinter as ctk
from tkinter import filedialog, messagebox

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from utils.palette import (
    BG_ROOT, BG_CARD, BG_HEADER, BG_ROW_A, BG_ROW_B, BG_TOTALS,
    BG_CRASH_BOX, BG_META_BOX,
    ACCENT, ACCENT2, ACCENT_WARN, ACCENT_ERR, ACCENT_HANG, ACCENT_PURP,
    ACCENT_GREEN,
    TEXT_MAIN, TEXT_DIM, TEXT_BRIGHT, TEXT_SUBTLE,
    BORDER, CHART_COLORS,
)
# Reuse the headless stats helpers from report_gen — no duplication.
from utils.report_gen import (
    _parse_all_stats,
    _count_crash_files,
    _format_duration,
    generate_pdf_report,
)


class ResultsMixin:
    """
    Provides build_final_coverage_screen() and download_pdf().
    Requires self.final_output_dir and the WidgetMixin helpers.
    """

    # ── Public entry-points ───────────────────────────────────────────────────

    def build_final_coverage_screen(self):
        self.clear()
        self.geometry("1100x800")
        self.configure(fg_color=BG_ROOT)

        merged, instances = _parse_all_stats(self.final_output_dir)

        outer = ctk.CTkFrame(self, fg_color=BG_ROOT)
        outer.pack(fill="both", expand=True)

        bar = self._title_bar(
            outer, "AFL++ Fuzzing Report",
            subtitle=f"{len(instances)} instance(s) combined",
        )
        self._build_action_buttons(bar)

        scroll = ctk.CTkScrollableFrame(outer, fg_color=BG_ROOT)
        scroll.pack(fill="both", expand=True, padx=10, pady=10)

        if not merged:
            ctk.CTkLabel(
                scroll,
                text="No fuzzer_stats files found in output directory.",
                font=("Courier", 14), text_color=ACCENT_ERR,
            ).pack(pady=40)
            return

        self._build_summary_cards(scroll, merged)
        self._build_charts(scroll, instances)
        self._build_instance_table(scroll, merged, instances)
        self._build_crash_listing(scroll)
        self._build_metadata_box(scroll, merged)

    def download_pdf(self):
        merged, _ = _parse_all_stats(self.final_output_dir)
        if not merged:
            messagebox.showerror("Error", "No fuzzer_stats files found — nothing to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            title="Save Fuzzing Results PDF",
        )
        if not file_path:
            return

        try:
            generate_pdf_report(self.final_output_dir, file_path)
            messagebox.showinfo("Success", f"PDF saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save PDF: {e}")

    # ── Private builders ──────────────────────────────────────────────────────

    def _build_action_buttons(self, bar):
        btn_frame = ctk.CTkFrame(bar, fg_color="transparent")
        btn_frame.pack(side="right", padx=10)
        self._btn(btn_frame, "Export PDF",  self.download_pdf,          width=110).pack(side="left", padx=5, pady=8)
        self._btn(btn_frame, "Run Again",   self.build_config_screen,   width=110, primary=False).pack(side="left", padx=5, pady=8)

    def _build_summary_cards(self, parent, merged):
        run_time = _format_duration(merged.get("run_time_sec", 0))

        cards_frame = ctk.CTkFrame(parent, fg_color="transparent")
        cards_frame.pack(fill="x", pady=(0, 10))

        summary_cards = [
            ("EXECUTIONS",     f"{merged['execs_done']:,}",        ACCENT2),
            ("EXEC/SEC",       f"{merged['execs_per_sec']:,.1f}",  ACCENT),
            ("EDGES FOUND",    f"{merged['edges_found']:,}",       ACCENT_WARN),
            ("UNIQUE CRASHES", f"{merged['unique_crashes']:,}",    ACCENT_ERR  if merged['unique_crashes'] > 0 else TEXT_DIM),
            ("UNIQUE HANGS",   f"{merged['unique_hangs']:,}",      ACCENT_HANG if merged['unique_hangs']   > 0 else TEXT_DIM),
            ("BITMAP CVG",     merged.get('bitmap_cvg', 'n/a'),   ACCENT_PURP),
            ("RUN TIME",       run_time,                           ACCENT_GREEN),
            ("CORPUS SIZE",    f"{merged['corpus_count']:,}",      TEXT_BRIGHT),
        ]

        for i, (label, value, color) in enumerate(summary_cards):
            card = ctk.CTkFrame(cards_frame, fg_color=BG_CARD, corner_radius=8)
            card.grid(row=0, column=i, padx=4, pady=4, sticky="nsew")
            cards_frame.grid_columnconfigure(i, weight=1)
            ctk.CTkLabel(card, text=value, font=("Courier Bold", 18), text_color=color).pack(pady=(10, 2))
            ctk.CTkLabel(card, text=label, font=("Courier", 9),       text_color=TEXT_DIM).pack(pady=(0, 10))

    def _build_charts(self, parent, instances):
        self._section_label(parent, "COVERAGE & PERFORMANCE")

        def ival(d, k):
            try: return int(d.get(k, 0))
            except: return 0

        def fval(d, k):
            try: return float(d.get(k, 0))
            except: return 0.0

        def pct_cvg(inst):
            raw = inst.get("bitmap_cvg", "0%").replace("%", "").strip()
            try: return float(raw)
            except: return 0.0

        labels     = [i.get("_label", f"inst{n}") for n, i in enumerate(instances)]
        n          = len(labels)
        x          = list(range(n))
        bar_colors = [CHART_COLORS[i % len(CHART_COLORS)] for i in range(n)]

        fig = plt.Figure(figsize=(11, 9), facecolor=BG_ROOT)
        gs  = gridspec.GridSpec(3, 2, figure=fig,
                                height_ratios=[1.3, 1, 1],
                                hspace=0.55, wspace=0.35)

        ax_time    = fig.add_subplot(gs[0, :])   # full-width time series
        ax_cvg     = fig.add_subplot(gs[1, 0])   # bitmap coverage %
        ax_edges   = fig.add_subplot(gs[1, 1])   # edges found vs total
        ax_pending = fig.add_subplot(gs[2, 0])   # pending queue breakdown
        ax_time_e  = fig.add_subplot(gs[2, 1])   # time efficiency

        def style_ax(ax, title):
            ax.set_facecolor(BG_CARD)
            ax.tick_params(colors=TEXT_DIM, labelsize=8)
            ax.set_title(title, color=TEXT_SUBTLE, fontsize=9, pad=6)
            for spine in ax.spines.values():
                spine.set_edgecolor(BORDER)
            ax.grid(axis="y", linestyle="--", alpha=0.15, color=BORDER)

        # ── Panel 0: Coverage over time ───────────────────────────────────
        ax_time.set_facecolor(BG_CARD)
        ax_time.tick_params(colors=TEXT_DIM, labelsize=8)
        ax_time.set_title("Edge Coverage Over Time", color=TEXT_SUBTLE, fontsize=9, pad=6)
        for spine in ax_time.spines.values():
            spine.set_edgecolor(BORDER)
        ax_time.grid(linestyle="--", alpha=0.2, color=BORDER)

        EDGE_COLS   = ["edges_found", "edges found", "total_edges"]
        CORPUS_COLS = ["corpus_count", "corpus count", "paths_total"]

        def _find_col(row, candidates):
            for c in candidates:
                if c in row:
                    return c
            return None

        any_plot = False
        for idx, inst in enumerate(instances):
            rows = inst.get("_plot_rows", [])
            if not rows:
                continue
            col = _find_col(rows[0], EDGE_COLS) or _find_col(rows[0], CORPUS_COLS)
            if col is None:
                continue
            if "relative_time" in rows[0]:
                xs = [r.get("relative_time", 0) / 60 for r in rows]
            else:
                t0 = rows[0].get("unix_time", 0)
                xs = [(r.get("unix_time", 0) - t0) / 60 for r in rows]
            ys    = [r.get(col, 0) for r in rows]
            color = CHART_COLORS[idx % len(CHART_COLORS)]
            ax_time.plot(xs, ys, color=color, linewidth=1.8,
                         label=inst.get("_label"), zorder=3)
            ax_time.fill_between(xs, ys, alpha=0.08, color=color)
            any_plot = True

        if any_plot:
            ax_time.legend(fontsize=7, facecolor=BG_HEADER, labelcolor=TEXT_DIM)
            ax_time.set_xlabel("Time (minutes)", color=TEXT_DIM, fontsize=8)
            ax_time.set_ylabel("Edges Found",    color=TEXT_DIM, fontsize=8)
        else:
            ax_time.text(0.5, 0.5, "No plot_data available",
                         ha="center", va="center", transform=ax_time.transAxes,
                         color=TEXT_SUBTLE, fontsize=9)

        # ── Panel 1: Bitmap coverage % ────────────────────────────────────
        style_ax(ax_cvg, "Bitmap Coverage % per Instance")
        cvg_vals = [pct_cvg(i) for i in instances]
        bars = ax_cvg.bar(x, cvg_vals, color=bar_colors, edgecolor=BORDER)
        ax_cvg.set_xticks(x)
        ax_cvg.set_xticklabels(labels, rotation=20, ha="right", fontsize=7)
        ax_cvg.set_ylabel("Coverage %", color=TEXT_DIM, fontsize=8)
        ax_cvg.set_ylim(0, max(max(cvg_vals) * 1.2, 1))
        for bar, val in zip(bars, cvg_vals):
            ax_cvg.text(bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + 0.05,
                        f"{val:.2f}%", ha="center", va="bottom",
                        color=TEXT_SUBTLE, fontsize=8)

        # ── Panel 2: Edges found vs total ─────────────────────────────────
        style_ax(ax_edges, "Edges Found vs Total")
        edges_found = [ival(i, "edges_found") for i in instances]
        total_edges = [ival(i, "total_edges") for i in instances]
        remaining   = [max(t - f, 0) for f, t in zip(edges_found, total_edges)]
        w = 0.5
        ax_edges.bar(x, edges_found, w, label="Found",     color=bar_colors, edgecolor=BORDER)
        ax_edges.bar(x, remaining,   w, label="Remaining",
                     bottom=edges_found, color="#1e293b", edgecolor=BORDER, alpha=0.6)
        ax_edges.set_xticks(x)
        ax_edges.set_xticklabels(labels, rotation=20, ha="right", fontsize=7)
        ax_edges.set_ylabel("Edges", color=TEXT_DIM, fontsize=8)
        ax_edges.legend(fontsize=7, facecolor=BG_HEADER, labelcolor=TEXT_DIM)

        # ── Panel 3: Pending queue breakdown ──────────────────────────────
        style_ax(ax_pending, "Pending Queue Breakdown")
        pend_total = [ival(i, "pending_total")  for i in instances]
        pend_favs  = [ival(i, "pending_favs")   for i in instances]
        corp_fav   = [ival(i, "corpus_favored") for i in instances]
        bw = 0.25
        xi = [v - bw   for v in x]
        xm = [v        for v in x]
        xr = [v + bw   for v in x]
        ax_pending.bar(xi, pend_total, bw, label="Pending",          color=ACCENT_WARN,  edgecolor=BORDER)
        ax_pending.bar(xm, pend_favs,  bw, label="Pending favoured", color=ACCENT_PURP,  edgecolor=BORDER)
        ax_pending.bar(xr, corp_fav,   bw, label="Corpus favoured",  color=ACCENT_GREEN, edgecolor=BORDER)
        ax_pending.set_xticks(x)
        ax_pending.set_xticklabels(labels, rotation=20, ha="right", fontsize=7)
        ax_pending.set_ylabel("Count", color=TEXT_DIM, fontsize=8)
        ax_pending.legend(fontsize=7, facecolor=BG_HEADER, labelcolor=TEXT_DIM)

        # ── Panel 4: Time efficiency ──────────────────────────────────────
        style_ax(ax_time_e, "Time Efficiency (fuzz vs stall)")
        fuzz_t  = [ival(i, "fuzz_time")     / 3600 for i in instances]
        stall_t = [ival(i, "time_wo_finds") / 3600 for i in instances]
        bw = 0.35
        ax_time_e.bar([v - bw/2 for v in x], fuzz_t,  bw, label="Fuzz time (h)",  color=ACCENT_GREEN, edgecolor=BORDER)
        ax_time_e.bar([v + bw/2 for v in x], stall_t, bw, label="Stall time (h)", color=ACCENT_ERR,   edgecolor=BORDER)
        ax_time_e.set_xticks(x)
        ax_time_e.set_xticklabels(labels, rotation=20, ha="right", fontsize=7)
        ax_time_e.set_ylabel("Hours", color=TEXT_DIM, fontsize=8)
        ax_time_e.legend(fontsize=7, facecolor=BG_HEADER, labelcolor=TEXT_DIM)

        canvas_widget = FigureCanvasTkAgg(fig, master=parent)
        canvas_widget.draw()
        canvas_widget.get_tk_widget().pack(fill="x", pady=(0, 10))

    def _build_instance_table(self, parent, merged, instances):
        self._section_label(parent, "PER-INSTANCE BREAKDOWN")

        def ival(d, k):
            try: return int(d.get(k, 0))
            except: return 0

        def fval(d, k):
            try: return float(d.get(k, 0))
            except: return 0.0

        table_frame = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8)
        table_frame.pack(fill="x", padx=4, pady=(0, 10))

        headers    = ["Instance", "Execs", "Exec/s", "Edges", "Crashes", "Hangs",
                      "Cycles", "Corpus", "Bitmap%", "Stability", "Pending"]
        col_widths = [120, 100, 80, 90, 80, 80, 70, 80, 80, 90, 80]

        header_row = ctk.CTkFrame(table_frame, fg_color=BG_HEADER)
        header_row.pack(fill="x")
        for h, w in zip(headers, col_widths):
            ctk.CTkLabel(
                header_row, text=h, font=("Courier Bold", 10),
                text_color=ACCENT2, width=w, anchor="center",
            ).pack(side="left", padx=2, pady=6)

        for n, inst in enumerate(instances):
            row_bg = BG_ROW_A if n % 2 == 0 else BG_ROW_B
            row = ctk.CTkFrame(table_frame, fg_color=row_bg)
            row.pack(fill="x")
            vals = [
                inst.get("_label", f"inst{n}"),
                f"{ival(inst,'execs_done'):,}",
                f"{fval(inst,'execs_per_sec'):,.1f}",
                f"{ival(inst,'edges_found'):,}",
                f"{ival(inst,'unique_crashes'):,}",
                f"{ival(inst,'unique_hangs'):,}",
                f"{ival(inst,'cycles_done'):,}",
                f"{ival(inst,'corpus_count'):,}",
                inst.get("bitmap_cvg", "n/a"),
                inst.get("stability",  "n/a"),
                f"{ival(inst,'pending_total'):,}",
            ]
            for val, cw in zip(vals, col_widths):
                ctk.CTkLabel(
                    row, text=val, font=("Courier", 10),
                    text_color=TEXT_MAIN, width=cw, anchor="center",
                ).pack(side="left", padx=2, pady=4)

        totals_row = ctk.CTkFrame(table_frame, fg_color=BG_TOTALS)
        totals_row.pack(fill="x")
        run_time = _format_duration(merged.get("run_time_sec", 0))
        totals = [
            "COMBINED",
            f"{merged['execs_done']:,}",
            f"{merged['execs_per_sec']:,.1f}",
            f"{merged['edges_found']:,}",
            f"{merged['unique_crashes']:,}",
            f"{merged['unique_hangs']:,}",
            f"{merged['cycles_done']:,}",
            f"{merged['corpus_count']:,}",
            "—",
            "—",
            f"{merged['pending_total']:,}",
        ]
        for val, cw in zip(totals, col_widths):
            ctk.CTkLabel(
                totals_row, text=val, font=("Courier Bold", 10),
                text_color=ACCENT_WARN, width=cw, anchor="center",
            ).pack(side="left", padx=2, pady=5)

    def _build_crash_listing(self, parent):
        crash_count, hang_count, crash_files, hang_files = _count_crash_files(self.final_output_dir)
        if not (crash_files or hang_files):
            return

        self._section_label(parent, "CRASH & HANG FILES", color=ACCENT_ERR)
        crash_box = ctk.CTkTextbox(
            parent, height=140, font=("Courier", 10),
            fg_color=BG_CRASH_BOX, text_color="#f87171",
            border_color=BORDER,
        )
        crash_box.pack(fill="x", padx=4, pady=(0, 10))

        if crash_files:
            crash_box.insert("end", f"── CRASHES ({len(crash_files)} shown) ──\n")
            for f in crash_files:
                crash_box.insert("end", f"  {f}\n")
        if hang_files:
            crash_box.insert("end", f"\n── HANGS ({len(hang_files)} shown) ──\n")
            for f in hang_files:
                crash_box.insert("end", f"  {f}\n")
        crash_box.configure(state="disabled")

    def _build_metadata_box(self, parent, merged):
        run_time = _format_duration(merged.get("run_time_sec", 0))
        self._section_label(parent, "RUN METADATA")
        meta_box = ctk.CTkTextbox(
            parent, height=165, font=("Courier", 10),
            fg_color=BG_META_BOX, text_color=TEXT_SUBTLE,
            border_color=BORDER,
        )
        meta_box.pack(fill="x", padx=4, pady=(0, 10))
        meta_lines = [
            f"Target:        {merged.get('afl_banner',   'n/a')}",
            f"Command:       {merged.get('command_line', 'n/a')}",
            f"Target mode:   {merged.get('target_mode',  'n/a')}",
            f"Run time:      {run_time}",
            f"Edges found:   {merged.get('edges_found', 0):,} / {merged.get('total_edges', 0):,}",
            f"Bitmap cvg:    {merged.get('bitmap_cvg', 'n/a')}",
            f"Pending total: {merged.get('pending_total', 0):,}",
            f"Peak RSS:      {merged.get('peak_rss_mb', 0)} MB (combined)",
            f"Saved crashes: {merged.get('saved_crashes', 0)}",
            f"Saved hangs:   {merged.get('saved_hangs',   0)}",
            f"Output dir:    {self.final_output_dir}",
        ]
        meta_box.insert("end", "\n".join(meta_lines))
        meta_box.configure(state="disabled")