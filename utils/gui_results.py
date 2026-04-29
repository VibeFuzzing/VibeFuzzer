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
            ("PATHS FOUND",    f"{merged['paths_total']:,}",       ACCENT_WARN),
            ("UNIQUE CRASHES", f"{merged['unique_crashes']:,}",    ACCENT_ERR  if merged['unique_crashes'] > 0 else TEXT_DIM),
            ("UNIQUE HANGS",   f"{merged['unique_hangs']:,}",      ACCENT_HANG if merged['unique_hangs']   > 0 else TEXT_DIM),
            ("CYCLES DONE",    f"{merged['cycles_done']:,}",       ACCENT_PURP),
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

        labels      = [i.get("_label", f"inst{n}") for n, i in enumerate(instances)]
        bar_colors  = [CHART_COLORS[i % len(CHART_COLORS)] for i in range(len(labels))]
        paths_vals  = [ival(i, "paths_total")    for i in instances]
        eps_vals    = [fval(i, "execs_per_sec")  for i in instances]
        crash_vals  = [ival(i, "unique_crashes") for i in instances]
        hang_vals   = [ival(i, "unique_hangs")   for i in instances]
        corpus_vals = [ival(i, "corpus_count")   for i in instances]
        depth_vals  = [ival(i, "max_depth")      for i in instances]

        fig = plt.Figure(figsize=(11, 7), facecolor=BG_ROOT)
        gs  = gridspec.GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.35)

        ax_paths   = fig.add_subplot(gs[0, :2])
        ax_eps     = fig.add_subplot(gs[0, 2])
        ax_crashes = fig.add_subplot(gs[1, 0])
        ax_corpus  = fig.add_subplot(gs[1, 1])
        ax_depth   = fig.add_subplot(gs[1, 2])

        def style_ax(ax, title):
            ax.set_facecolor(BG_CARD)
            ax.tick_params(colors=TEXT_DIM, labelsize=8)
            ax.set_title(title, color=TEXT_SUBTLE, fontsize=9, pad=6)
            for spine in ax.spines.values():
                spine.set_edgecolor(BORDER)

        style_ax(ax_paths, "Paths Found per Instance")
        bars = ax_paths.barh(labels, paths_vals, color=bar_colors, edgecolor=BORDER, height=0.5)
        max_val = max(paths_vals) if paths_vals else 1
        for bar, val in zip(bars, paths_vals):
            ax_paths.text(
                bar.get_width() + max_val * 0.01,
                bar.get_y() + bar.get_height() / 2,
                f"{val:,}", va="center", ha="left", color=TEXT_SUBTLE, fontsize=8,
            )
        ax_paths.set_xlabel("Paths", color=TEXT_DIM, fontsize=8)

        style_ax(ax_eps, "Exec/sec per Instance")
        ax_eps.bar(labels, eps_vals, color=bar_colors, edgecolor=BORDER)
        ax_eps.set_ylabel("exec/s", color=TEXT_DIM, fontsize=8)
        ax_eps.tick_params(axis="x", rotation=20)

        style_ax(ax_crashes, "Crashes & Hangs")
        x = list(range(len(labels)))
        w = 0.35
        ax_crashes.bar([xi - w/2 for xi in x], crash_vals, width=w,
                       label="crashes", color=ACCENT_ERR,  edgecolor=BORDER)
        ax_crashes.bar([xi + w/2 for xi in x], hang_vals,  width=w,
                       label="hangs",   color=ACCENT_HANG, edgecolor=BORDER)
        ax_crashes.set_xticks(x)
        ax_crashes.set_xticklabels(labels, rotation=20, fontsize=7)
        ax_crashes.legend(fontsize=7, facecolor=BG_HEADER, labelcolor=TEXT_DIM)

        style_ax(ax_corpus, "Corpus Size per Instance")
        ax_corpus.bar(labels, corpus_vals, color=bar_colors, edgecolor=BORDER)
        ax_corpus.set_ylabel("entries", color=TEXT_DIM, fontsize=8)
        ax_corpus.tick_params(axis="x", rotation=20)

        style_ax(ax_depth, "Max Call Depth per Instance")
        ax_depth.bar(labels, depth_vals, color=bar_colors, edgecolor=BORDER)
        ax_depth.set_ylabel("depth", color=TEXT_DIM, fontsize=8)
        ax_depth.tick_params(axis="x", rotation=20)

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

        headers    = ["Instance", "Execs", "Exec/s", "Paths", "Crashes", "Hangs",
                      "Cycles", "Corpus", "Max Depth", "Stability", "Coverage"]
        col_widths = [120, 100, 80, 80, 80, 80, 70, 80, 90, 90, 90]

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
                f"{ival(inst,'paths_total'):,}",
                f"{ival(inst,'unique_crashes'):,}",
                f"{ival(inst,'unique_hangs'):,}",
                f"{ival(inst,'cycles_done'):,}",
                f"{ival(inst,'corpus_count'):,}",
                f"{ival(inst,'max_depth'):,}",
                inst.get("stability", "n/a"),
                inst.get("bitmap_cvg", "n/a"),
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
            f"{merged['paths_total']:,}",
            f"{merged['unique_crashes']:,}",
            f"{merged['unique_hangs']:,}",
            f"{merged['cycles_done']:,}",
            f"{merged['corpus_count']:,}",
            f"{merged['max_depth']:,}",
            "—", "—",
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
            parent, height=130, font=("Courier", 10),
            fg_color=BG_META_BOX, text_color=TEXT_SUBTLE,
            border_color=BORDER,
        )
        meta_box.pack(fill="x", padx=4, pady=(0, 10))
        meta_lines = [
            f"Target:        {merged.get('afl_banner',   'n/a')}",
            f"Command:       {merged.get('command_line', 'n/a')}",
            f"Target mode:   {merged.get('target_mode',  'n/a')}",
            f"Run time:      {run_time}",
            f"Peak RSS:      {merged.get('peak_rss_mb', 0)} MB (combined)",
            f"Saved crashes: {merged.get('saved_crashes', 0)}",
            f"Saved hangs:   {merged.get('saved_hangs',   0)}",
            f"Output dir:    {self.final_output_dir}",
        ]
        meta_box.insert("end", "\n".join(meta_lines))
        meta_box.configure(state="disabled")
