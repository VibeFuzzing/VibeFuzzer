import customtkinter as ctk
from tkinter import filedialog
from tkinter import messagebox
import subprocess
import threading
import time
import os
import shutil
from pathlib import Path
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

ctk.set_appearance_mode("dark")

VALID_PROTOCOLS = ["HTTP"]


class VibeFuzzerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Vibe Fuzzer")
        self.geometry("900x750")

        self.monitoring = False
        self.coverage_data = []

        self.use_target_binary = ctk.BooleanVar()
        self.use_custom_build = ctk.BooleanVar()
        self.use_configure_args = ctk.BooleanVar()
        self.use_make_args = ctk.BooleanVar()
        self.use_target_args = ctk.BooleanVar()
        self.use_afl_args = ctk.BooleanVar()
        self.no_llm = ctk.BooleanVar()

        self.build_config_screen()

    # =========================================================
    # CONFIG SCREEN
    # =========================================================
    def build_config_screen(self):
        self.clear()

        frame = ctk.CTkFrame(self)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Vibe Fuzzer", font=("Arial", 24)).pack(pady=10)

        self.target_source_dir = self.clickable_file_entry(
            frame, "Select Target Source Folder"
        )

        self.binary_frame = ctk.CTkFrame(frame)
        self.binary_frame.pack(fill="x", pady=5)

        self.binary_checkbox = ctk.CTkCheckBox(
            self.binary_frame,
            text="Target Binary",
            variable=self.use_target_binary,
            command=self.toggle_target_binary
        )
        self.binary_checkbox.pack(side="left", padx=(0, 10), anchor="w")

        self.target_binary_path = ctk.CTkEntry(
            self.binary_frame,
            placeholder_text="Select Target Binary Location"
        )
        self.target_binary_path.pack(side="left", fill="x", expand=True)

        def browse_binary():
            path = filedialog.askopenfilename()
            if path:
                self.target_binary_path.delete(0, "end")
                self.target_binary_path.insert(0, path)

        self.binary_browse_btn = ctk.CTkButton(
            self.binary_frame,
            text="Browse",
            width=80,
            command=browse_binary
        )
        self.binary_browse_btn.pack(side="right")

        # hide initially
        self.target_binary_path.pack_forget()
        self.binary_browse_btn.pack_forget()

        self.target_args_frame = ctk.CTkFrame(frame)
        self.target_args_frame.pack(fill="x", pady=5)
        self.target_args_checkbox = ctk.CTkCheckBox(
            self.target_args_frame, text="Target Args",
            variable=self.use_target_args, command=self.toggle_target_args
        )
        self.target_args_checkbox.pack(side="left", padx=(0, 10), fill="y", anchor="w")
        self.target_args_input = ctk.CTkEntry(self.target_args_frame, placeholder_text="Target Args")
        self.target_args_input.pack(side="left", fill="x", expand=True)
        self.target_args_input.pack_forget()

        self.input_dir = self.clickable_file_entry(
            frame, "Select Input Directory (default ./input)"
        )
        self.output_dir = self.clickable_file_entry(
            frame, "Select Output Directory (default ./output)"
        )

        protocol_frame = ctk.CTkFrame(frame)
        protocol_frame.pack(fill="x", pady=5)

        ctk.CTkLabel(
            protocol_frame,
            text="Protocol",
            width=120,
            anchor="w"
        ).pack(side="left", padx=(2, 10))

        self.protocol = ctk.CTkComboBox(protocol_frame, values=VALID_PROTOCOLS)
        self.protocol.pack(side="left", fill="x", expand=True, padx=(0, 5))

        self.custom_build_frame = ctk.CTkFrame(frame)
        self.custom_build_frame.pack(fill="x", pady=5)
        self.custom_build_checkbox = ctk.CTkCheckBox(
            self.custom_build_frame, text="Custom Build Command",
            variable=self.use_custom_build, command=self.toggle_custom_build
        )
        self.custom_build_checkbox.pack(side="left", padx=(0, 10), fill="y", anchor="w")
        self.custom_build = ctk.CTkEntry(self.custom_build_frame, placeholder_text="Custom Build Command")
        self.custom_build.pack(side="left", fill="x", expand=True)
        self.custom_build.pack_forget()

        self.configure_args_frame = ctk.CTkFrame(frame)
        self.configure_args_frame.pack(fill="x", pady=5)
        self.configure_args_checkbox = ctk.CTkCheckBox(
            self.configure_args_frame, text="Configure Args",
            variable=self.use_configure_args, command=self.toggle_configure_args
        )
        self.configure_args_checkbox.pack(side="left", padx=(0, 10), fill="y", anchor="w")
        self.configure_args = ctk.CTkEntry(self.configure_args_frame, placeholder_text="Configure Args")
        self.configure_args.pack(side="left", fill="x", expand=True)
        self.configure_args.pack_forget()

        self.make_args_frame = ctk.CTkFrame(frame)
        self.make_args_frame.pack(fill="x", pady=5)
        self.make_args_checkbox = ctk.CTkCheckBox(
            self.make_args_frame, text="Make Args",
            variable=self.use_make_args, command=self.toggle_make_args
        )
        self.make_args_checkbox.pack(side="left", padx=(0, 10), fill="y", anchor="w")
        self.make_args = ctk.CTkEntry(self.make_args_frame, placeholder_text="Make Args")
        self.make_args.pack(side="left", fill="x", expand=True)
        self.make_args.pack_forget()

        self.afl_args_frame = ctk.CTkFrame(frame)
        self.afl_args_frame.pack(fill="x", pady=5)
        self.afl_args_checkbox = ctk.CTkCheckBox(
            self.afl_args_frame, text="AFL Args",
            variable=self.use_afl_args, command=self.toggle_afl_args
        )
        self.afl_args_checkbox.pack(side="left", padx=(0, 10), fill="y", anchor="w")
        self.afl_args_input = ctk.CTkEntry(self.afl_args_frame, placeholder_text="AFL Args")
        self.afl_args_input.pack(side="left", fill="x", expand=True)
        self.afl_args_input.pack_forget()

        self.llm_frame = ctk.CTkFrame(frame)
        self.llm_frame.pack(fill="x", pady=5)
        self.no_llm_checkbox = ctk.CTkCheckBox(
            self.llm_frame, text="Disable LLM Seeds",
            variable=self.no_llm, command=self.toggle_num_seeds
        )
        self.no_llm_checkbox.pack(side="left", padx=(0, 10), fill="y", anchor="w")
        self.num_seeds = ctk.CTkEntry(self.llm_frame, placeholder_text="Num Seeds (default 10)")
        self.num_seeds.pack(side="left", fill="x", expand=True)

        self.start_button = ctk.CTkButton(frame, text="Start", command=self.start)
        self.start_button.pack(pady=20)

    def clickable_file_entry(self, parent, placeholder, is_file=False):
        frame = ctk.CTkFrame(parent)
        frame.pack(pady=5, fill="x")

        entry = ctk.CTkEntry(frame, placeholder_text=placeholder)
        entry.pack(side="left", fill="x", expand=True, padx=(0, 5))

        def open_picker():
            path = filedialog.askopenfilename() if is_file else filedialog.askdirectory()
            if path:
                entry.delete(0, "end")
                entry.insert(0, path)

        browse_btn = ctk.CTkButton(frame, text="Browse", width=80, command=open_picker)
        browse_btn.pack(side="right")

        return entry

    def entry(self, parent, placeholder):
        e = ctk.CTkEntry(parent, placeholder_text=placeholder)
        e.pack(pady=5, fill="x")
        return e

    def toggle_target_binary(self):
        if self.use_target_binary.get():
            self.target_binary_path.pack(side="left", fill="x", expand=True)
            self.binary_browse_btn.pack(side="right")
        else:
            self.target_binary_path.pack_forget()
            self.binary_browse_btn.pack_forget()

    def toggle_num_seeds(self):
        if self.no_llm.get():
            self.num_seeds.pack_forget()
        else:
            self.num_seeds.pack(side="left", fill="x", expand=True)

    def toggle_custom_build(self):
        if self.use_custom_build.get():
            self.custom_build.pack(side="left", fill="x", expand=True)
        else:
            self.custom_build.pack_forget()

    def toggle_configure_args(self):
        if self.use_configure_args.get():
            self.configure_args.pack(side="left", fill="x", expand=True)
        else:
            self.configure_args.pack_forget()

    def toggle_make_args(self):
        if self.use_make_args.get():
            self.make_args.pack(side="left", fill="x", expand=True)
        else:
            self.make_args.pack_forget()

    def toggle_target_args(self):
        if self.use_target_args.get():
            self.target_args_input.pack(side="left", fill="x", expand=True)
        else:
            self.target_args_input.pack_forget()

    def toggle_afl_args(self):
        if self.use_afl_args.get():
            self.afl_args_input.pack(side="left", fill="x", expand=True)
        else:
            self.afl_args_input.pack_forget()

    def is_dir_empty(self, path):
        return not any(Path(path).iterdir())

    def validate_fields(self):
        fields = [
            (self.use_custom_build, self.custom_build, "Custom Build Command"),
            (self.use_configure_args, self.configure_args, "Configure Args"),
            (self.use_make_args, self.make_args, "Make Args"),
            (self.use_target_args, self.target_args_input, "Target Args"),
            (self.use_afl_args, self.afl_args_input, "AFL Args"),
        ]
        for toggle, entry, name in fields:
            if toggle.get() and not entry.get().strip():
                messagebox.showerror("Error", f"{name} is checked but no value was provided.")
                return False
        return True

    # =========================================================
    # START
    # =========================================================
    def start(self):
        if not self.validate_fields():
            return

        target_dir = self.target_source_dir.get()
        if not target_dir or not os.path.isdir(target_dir):
            messagebox.showerror("Error", "Please provide a valid target source directory.")
            return

        if self.input_dir.get() and not os.path.isdir(self.input_dir.get()):
            messagebox.showerror("Error", "Invalid input directory.")
            return

        if self.output_dir.get() and not os.path.isdir(self.output_dir.get()):
            messagebox.showerror("Error", "Invalid output directory.")
            return

        # use defaults if fields are empty, but still create dirs if they don't exist
        input_dir = self.input_dir.get() or "./input"
        output_dir = self.output_dir.get() or "./output"

        os.makedirs(input_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)

        self.final_output_dir = output_dir

        directory = Path(input_dir)
        if self.no_llm.get() and self.is_dir_empty(directory):
            messagebox.showerror("Error", "Input directory must contain at least one seed when LLM seeds are disabled.")
            return
        
        binary_path = None

        if self.use_target_binary.get():
            binary_path = self.target_binary_path.get().strip()

            if not binary_path:
                messagebox.showerror("Error", "Target Binary is enabled but no path was provided.")
                return

            binary_name = Path(binary_path).name
        else:
            # fallback to source dir
            target_dir = self.target_source_dir.get()
            binary_name = ""  # or handle differently depending on your wrapper

        # We cannot assume target_dir will always be the binary's parent 
        target_dir = self.target_source_dir.get()

        cmd = ["python3", "vibefuzzer.py", target_dir]
        if binary_path:
            cmd += ["--binary", binary_path]

        if self.protocol.get():
            cmd += ["--protocol", self.protocol.get()]
        if self.use_custom_build.get() and self.custom_build.get():
            cmd += ["--custom-build", self.custom_build.get()]
        if self.use_configure_args.get() and self.configure_args.get():
            cmd += ["--configure-args", self.configure_args.get()]
        if self.use_make_args.get() and self.make_args.get():
            cmd += ["--make-args", self.make_args.get()]

        cmd += ["--input", input_dir, "--output", output_dir]

        if self.use_afl_args.get() and self.afl_args_input.get():
            cmd += ["--afl-args"] + self.afl_args_input.get().split()

        cmd += ["--debug-ui"]

        if self.no_llm.get():
            cmd += ["--no-llm-seeds"]
        if self.num_seeds.get():
            cmd += ["--num-seeds", self.num_seeds.get() if self.num_seeds.get() else "10"]
        if self.use_target_args.get() and self.target_args_input.get():
            cmd += ["--target-args"] + self.target_args_input.get().split()

        print(f"Running command: {' '.join(cmd)}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        for line in process.stdout:
            print(line, end="")
            if "[*] Fuzzers are alive in tmux. Wrapper exiting." in line:
                break

        print("[*] Launching Tmux UI...")

        attach_cmd = "tmux attach-session -t vibefuzzer; tmux kill-session -t vibefuzzer 2>/dev/null"
        wsl_distro = os.environ.get("WSL_DISTRO_NAME")

        if wsl_distro:
            if shutil.which("wt.exe"):
                term_cmd = ["wt.exe", "new-tab", "wsl.exe", "-d", wsl_distro, "--", "bash", "-c", attach_cmd]
            else:
                term_cmd = ["cmd.exe", "/c", "start", "wsl.exe", "-d", wsl_distro, "--", "bash", "-c", attach_cmd]
        else:
            term_program = os.environ.get("TERM_PROGRAM", "")
            if term_program == "iTerm.app":
                term_cmd = ["osascript", "-e", f'tell app "iTerm" to create window with default profile command "{attach_cmd}"']
            elif term_program == "Apple_Terminal":
                term_cmd = ["osascript", "-e", f'tell app "Terminal" to do script "{attach_cmd}"']
            elif os.environ.get("GNOME_TERMINAL_SCREEN"):
                term_cmd = ["gnome-terminal", "--", "bash", "-c", attach_cmd]
            elif os.environ.get("KONSOLE_VERSION"):
                term_cmd = ["konsole", "-e", "bash", "-c", attach_cmd]
            elif os.environ.get("KITTY_WINDOW_ID"):
                term_cmd = ["kitty", "bash", "-c", attach_cmd]
            elif shutil.which("xterm"):
                term_cmd = ["xterm", "-e", "bash", "-c", attach_cmd]
            else:
                messagebox.showerror("Error", "Could not detect your terminal emulator.")
                return

        try:
            subprocess.Popen(term_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (FileNotFoundError, OSError) as e:
            messagebox.showerror("Error", f"Failed to launch terminal: {str(e)}")
            return

        self.withdraw()
        threading.Thread(target=self.monitor_tmux_session, daemon=True).start()

    def monitor_tmux_session(self):
        while True:
            result = subprocess.run(["tmux", "has-session", "-t", "vibefuzzer"],
                                    capture_output=True, text=True)
            if result.returncode != 0:
                print("[*] Tmux session has ended. Showing results...")
                self.after(0, self.show_results)
                break
            time.sleep(1)

    def show_results(self):
        self.deiconify()
        self.build_final_coverage_screen()

    # =========================================================
    # STATS PARSING
    # =========================================================
    def parse_stats_file(self, path):
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

    def parse_all_stats(self):
        """
        Find all fuzzer_stats files, parse them, and return a merged
        summary dict plus a list of per-instance dicts.
        """
        output_dir = Path(self.final_output_dir)
        stats_files = sorted(output_dir.rglob("fuzzer_stats"))

        instances = []
        for f in stats_files:
            parsed = self.parse_stats_file(f)
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
            "execs_done":     sum(ival(i, "execs_done") for i in instances),
            "execs_per_sec":  sum(fval(i, "execs_per_sec") for i in instances),
            "paths_total":    sum(ival(i, "paths_total") for i in instances),
            "unique_crashes": sum(ival(i, "unique_crashes") for i in instances),
            "unique_hangs":   sum(ival(i, "unique_hangs") for i in instances),
            "cycles_done":    sum(ival(i, "cycles_done") for i in instances),
            "corpus_count":   sum(ival(i, "corpus_count") for i in instances),
            "saved_crashes":  sum(ival(i, "saved_crashes") for i in instances),
            "saved_hangs":    sum(ival(i, "saved_hangs") for i in instances),
            "peak_rss_mb":    sum(ival(i, "peak_rss_mb") for i in instances),
            "max_depth":      max(ival(i, "max_depth") for i in instances),
            # Single-value fields from first instance
            "start_time":     instances[0].get("start_time", ""),
            "last_update":    instances[0].get("last_update", ""),
            "afl_banner":     instances[0].get("afl_banner", ""),
            "command_line":   instances[0].get("command_line", ""),
            "target_mode":    instances[0].get("target_mode", ""),
            "stability":      instances[0].get("stability", ""),
            "bitmap_cvg":     instances[0].get("bitmap_cvg", ""),
        }

        try:
            start = int(instances[0].get("start_time", 0))
            end   = int(instances[0].get("last_update", 0))
            merged["run_time_sec"] = end - start if end > start else 0
        except Exception:
            merged["run_time_sec"] = 0

        return merged, instances

    def count_crash_files(self):
        output_dir = Path(self.final_output_dir)
        crashes = list(output_dir.rglob("crashes/id:*"))
        hangs   = list(output_dir.rglob("hangs/id:*"))
        return len(crashes), len(hangs), crashes[:20], hangs[:10]

    def format_duration(self, seconds):
        seconds = int(seconds)
        h = seconds // 3600
        m = (seconds % 3600) // 60
        s = seconds % 60
        if h > 0:
            return f"{h}h {m}m {s}s"
        elif m > 0:
            return f"{m}m {s}s"
        return f"{s}s"

    # =========================================================
    # FINAL COVERAGE SCREEN
    # =========================================================
    def build_final_coverage_screen(self):
        self.clear()
        self.geometry("1100x800")

        merged, instances = self.parse_all_stats()

        outer = ctk.CTkFrame(self)
        outer.pack(fill="both", expand=True)

        # Title bar
        title_bar = ctk.CTkFrame(outer, fg_color="#1a1a2e")
        title_bar.pack(fill="x")
        ctk.CTkLabel(title_bar, text="AFL++ Fuzzing Report",
                     font=("Courier Bold", 22), text_color="#00ff88").pack(side="left", padx=20, pady=12)
        ctk.CTkLabel(title_bar, text=f"{len(instances)} instance(s) combined",
                     font=("Courier", 12), text_color="#888888").pack(side="left", padx=5)

        btn_frame = ctk.CTkFrame(title_bar, fg_color="transparent")
        btn_frame.pack(side="right", padx=10)
        ctk.CTkButton(btn_frame, text="Export PDF", width=110,
                      command=self.download_pdf).pack(side="left", padx=5, pady=8)
        ctk.CTkButton(btn_frame, text="Run Again", width=110, fg_color="#333355",
                      command=self.build_config_screen).pack(side="left", padx=5, pady=8)

        scroll = ctk.CTkScrollableFrame(outer)
        scroll.pack(fill="both", expand=True, padx=10, pady=10)

        if not merged:
            ctk.CTkLabel(scroll, text="No fuzzer_stats files found in output directory.",
                         font=("Courier", 14), text_color="#ff4444").pack(pady=40)
            return

        # ── Summary cards ──────────────────────────────────────
        cards_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        cards_frame.pack(fill="x", pady=(0, 10))

        crash_count, hang_count, crash_files, hang_files = self.count_crash_files()
        run_time = self.format_duration(merged.get("run_time_sec", 0))

        summary_cards = [
            ("EXECUTIONS",     f"{merged['execs_done']:,}",        "#00ff88"),
            ("EXEC/SEC",       f"{merged['execs_per_sec']:,.1f}",  "#00ccff"),
            ("PATHS FOUND",    f"{merged['paths_total']:,}",       "#ffcc00"),
            ("UNIQUE CRASHES", f"{merged['unique_crashes']:,}",    "#ff4444" if merged['unique_crashes'] > 0 else "#888888"),
            ("UNIQUE HANGS",   f"{merged['unique_hangs']:,}",      "#ff8800" if merged['unique_hangs'] > 0 else "#888888"),
            ("CYCLES DONE",    f"{merged['cycles_done']:,}",       "#cc88ff"),
            ("RUN TIME",       run_time,                           "#88ddff"),
            ("CORPUS SIZE",    f"{merged['corpus_count']:,}",      "#aaffaa"),
        ]

        for i, (label, value, color) in enumerate(summary_cards):
            card = ctk.CTkFrame(cards_frame, fg_color="#1e1e2e", corner_radius=8)
            card.grid(row=0, column=i, padx=4, pady=4, sticky="nsew")
            cards_frame.grid_columnconfigure(i, weight=1)
            ctk.CTkLabel(card, text=value, font=("Courier Bold", 18), text_color=color).pack(pady=(10, 2))
            ctk.CTkLabel(card, text=label, font=("Courier", 9), text_color="#666666").pack(pady=(0, 10))

        # ── Charts ─────────────────────────────────────────────
        ctk.CTkLabel(scroll, text="COVERAGE & PERFORMANCE",
                     font=("Courier Bold", 13), text_color="#00ff88").pack(anchor="w", padx=4, pady=(10, 4))

        fig = plt.Figure(figsize=(11, 7), facecolor="#0d0d1a")
        gs  = gridspec.GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.35)

        ax_paths   = fig.add_subplot(gs[0, :2])
        ax_eps     = fig.add_subplot(gs[0, 2])
        ax_crashes = fig.add_subplot(gs[1, 0])
        ax_corpus  = fig.add_subplot(gs[1, 1])
        ax_depth   = fig.add_subplot(gs[1, 2])

        COLORS = ["#00ff88", "#00ccff", "#ffcc00", "#ff4444", "#cc88ff", "#ff8800"]

        def style_ax(ax, title):
            ax.set_facecolor("#111122")
            ax.tick_params(colors="#666666", labelsize=8)
            ax.set_title(title, color="#aaaaaa", fontsize=9, pad=6)
            for spine in ax.spines.values():
                spine.set_edgecolor("#333344")

        labels = [i.get("_label", f"inst{n}") for n, i in enumerate(instances)]

        def ival(d, k):
            try: return int(d.get(k, 0))
            except: return 0

        def fval(d, k):
            try: return float(d.get(k, 0))
            except: return 0.0

        paths_vals  = [ival(i, "paths_total")    for i in instances]
        eps_vals    = [fval(i, "execs_per_sec")  for i in instances]
        crash_vals  = [ival(i, "unique_crashes") for i in instances]
        hang_vals   = [ival(i, "unique_hangs")   for i in instances]
        corpus_vals = [ival(i, "corpus_count")   for i in instances]
        depth_vals  = [ival(i, "max_depth")      for i in instances]

        bar_colors = [COLORS[i % len(COLORS)] for i in range(len(labels))]

        # Paths per instance (horizontal bar)
        style_ax(ax_paths, "Paths Found per Instance")
        bars = ax_paths.barh(labels, paths_vals, color=bar_colors, edgecolor="#333344", height=0.5)
        for bar, val in zip(bars, paths_vals):
            offset = max(paths_vals) * 0.01 if max(paths_vals) > 0 else 1
            ax_paths.text(bar.get_width() + offset, bar.get_y() + bar.get_height() / 2,
                          f"{val:,}", va="center", ha="left", color="#aaaaaa", fontsize=8)
        ax_paths.set_xlabel("Paths", color="#aaaaaa", fontsize=8)

        # Exec/sec per instance
        style_ax(ax_eps, "Exec/sec per Instance")
        ax_eps.bar(labels, eps_vals, color=bar_colors, edgecolor="#333344")
        ax_eps.set_ylabel("exec/s", color="#aaaaaa", fontsize=8)
        ax_eps.tick_params(axis="x", rotation=20)

        # Crashes & hangs grouped
        style_ax(ax_crashes, "Crashes & Hangs")
        x = list(range(len(labels)))
        w = 0.35
        ax_crashes.bar([xi - w/2 for xi in x], crash_vals, width=w,
                       label="crashes", color="#ff4444", edgecolor="#333344")
        ax_crashes.bar([xi + w/2 for xi in x], hang_vals, width=w,
                       label="hangs", color="#ff8800", edgecolor="#333344")
        ax_crashes.set_xticks(x)
        ax_crashes.set_xticklabels(labels, rotation=20, fontsize=7)
        ax_crashes.legend(fontsize=7, facecolor="#1a1a2e", labelcolor="#aaaaaa")

        # Corpus count
        style_ax(ax_corpus, "Corpus Size per Instance")
        ax_corpus.bar(labels, corpus_vals, color=bar_colors, edgecolor="#333344")
        ax_corpus.set_ylabel("entries", color="#aaaaaa", fontsize=8)
        ax_corpus.tick_params(axis="x", rotation=20)

        # Max depth
        style_ax(ax_depth, "Max Call Depth per Instance")
        ax_depth.bar(labels, depth_vals, color=bar_colors, edgecolor="#333344")
        ax_depth.set_ylabel("depth", color="#aaaaaa", fontsize=8)
        ax_depth.tick_params(axis="x", rotation=20)

        canvas_widget = FigureCanvasTkAgg(fig, master=scroll)
        canvas_widget.draw()
        canvas_widget.get_tk_widget().pack(fill="x", pady=(0, 10))

        # ── Per-instance table ─────────────────────────────────
        ctk.CTkLabel(scroll, text="PER-INSTANCE BREAKDOWN",
                     font=("Courier Bold", 13), text_color="#00ff88").pack(anchor="w", padx=4, pady=(10, 4))

        table_frame = ctk.CTkFrame(scroll, fg_color="#111122", corner_radius=8)
        table_frame.pack(fill="x", padx=4, pady=(0, 10))

        headers    = ["Instance", "Execs", "Exec/s", "Paths", "Crashes", "Hangs",
                      "Cycles", "Corpus", "Max Depth", "Stability", "Coverage"]
        col_widths = [120, 100, 80, 80, 80, 80, 70, 80, 90, 90, 90]

        header_row = ctk.CTkFrame(table_frame, fg_color="#1a1a2e")
        header_row.pack(fill="x")
        for h, w in zip(headers, col_widths):
            ctk.CTkLabel(header_row, text=h, font=("Courier Bold", 10),
                         text_color="#00ff88", width=w, anchor="center").pack(side="left", padx=2, pady=6)

        for n, inst in enumerate(instances):
            row_bg = "#131325" if n % 2 == 0 else "#0f0f1e"
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
                ctk.CTkLabel(row, text=val, font=("Courier", 10),
                             text_color="#cccccc", width=cw, anchor="center").pack(side="left", padx=2, pady=4)

        # Combined totals row
        totals_row = ctk.CTkFrame(table_frame, fg_color="#1e1e3a")
        totals_row.pack(fill="x")
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
            ctk.CTkLabel(totals_row, text=val, font=("Courier Bold", 10),
                         text_color="#ffcc00", width=cw, anchor="center").pack(side="left", padx=2, pady=5)

        # ── Crash file list ────────────────────────────────────
        if crash_files or hang_files:
            ctk.CTkLabel(scroll, text="CRASH & HANG FILES",
                         font=("Courier Bold", 13), text_color="#ff4444").pack(anchor="w", padx=4, pady=(10, 4))

            crash_box = ctk.CTkTextbox(scroll, height=140, font=("Courier", 10),
                                       fg_color="#110a0a", text_color="#ff9999")
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

        # ── Run metadata ───────────────────────────────────────
        ctk.CTkLabel(scroll, text="RUN METADATA",
                     font=("Courier Bold", 13), text_color="#00ff88").pack(anchor="w", padx=4, pady=(10, 4))

        meta_box = ctk.CTkTextbox(scroll, height=130, font=("Courier", 10),
                                  fg_color="#0d0d1a", text_color="#aaaaaa")
        meta_box.pack(fill="x", padx=4, pady=(0, 10))
        meta_lines = [
            f"Target:        {merged.get('afl_banner', 'n/a')}",
            f"Command:       {merged.get('command_line', 'n/a')}",
            f"Target mode:   {merged.get('target_mode', 'n/a')}",
            f"Run time:      {run_time}",
            f"Peak RSS:      {merged.get('peak_rss_mb', 0)} MB (combined)",
            f"Saved crashes: {merged.get('saved_crashes', 0)}",
            f"Saved hangs:   {merged.get('saved_hangs', 0)}",
            f"Output dir:    {self.final_output_dir}",
        ]
        meta_box.insert("end", "\n".join(meta_lines))
        meta_box.configure(state="disabled")

    # =========================================================
    # PDF EXPORT
    # =========================================================
    def download_pdf(self):
        merged, instances = self.parse_all_stats()
        if not merged:
            messagebox.showerror("Error", "No fuzzer_stats files found — nothing to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            title="Save Fuzzing Results PDF"
        )
        if not file_path:
            return

        try:
            self._render_pdf(file_path, merged, instances)
            messagebox.showinfo("Success", f"PDF saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save PDF: {e}")

    def _render_pdf(self, file_path, merged, instances):
        import io
        import tempfile
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, Image, KeepTogether
        )

        # ── Colour palette (mirrors GUI) ──────────────────────
        BG         = colors.HexColor("#0d0d1a")
        CARD_BG    = colors.HexColor("#1e1e2e")
        ROW_A      = colors.HexColor("#131325")
        ROW_B      = colors.HexColor("#0f0f1e")
        HDR_BG     = colors.HexColor("#1a1a2e")
        TOTALS_BG  = colors.HexColor("#1e1e3a")
        GREEN      = colors.HexColor("#00ff88")
        CYAN       = colors.HexColor("#00ccff")
        YELLOW     = colors.HexColor("#ffcc00")
        RED        = colors.HexColor("#ff4444")
        ORANGE     = colors.HexColor("#ff8800")
        PURPLE     = colors.HexColor("#cc88ff")
        LIGHT_BLUE = colors.HexColor("#88ddff")
        LIGHT_GREEN= colors.HexColor("#aaffaa")
        GREY       = colors.HexColor("#888888")
        DIM        = colors.HexColor("#666666")
        TEXT       = colors.HexColor("#cccccc")
        WHITE      = colors.HexColor("#ffffff")

        W, H = letter
        MARGIN = 0.55 * inch

        doc = SimpleDocTemplate(
            file_path, pagesize=letter,
            leftMargin=MARGIN, rightMargin=MARGIN,
            topMargin=MARGIN, bottomMargin=MARGIN
        )

        def bg_canvas(canv, doc):
            canv.saveState()
            canv.setFillColor(BG)
            canv.rect(0, 0, W, H, fill=1, stroke=0)
            canv.restoreState()

        # ── Styles ────────────────────────────────────────────
        def sty(name, font="Courier", size=10, color=TEXT, bold=False,
                leading=None, space_before=0, space_after=4, align=0):
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

        title_sty    = sty("title",    size=20, color=GREEN,  bold=True,  space_before=2, space_after=2)
        subtitle_sty = sty("subtitle", size=10, color=GREY,   space_after=8)
        section_sty  = sty("section",  size=12, color=GREEN,  bold=True,  space_before=14, space_after=4)
        label_sty    = sty("label",    size=8,  color=DIM)
        meta_sty     = sty("meta",     size=9,  color=TEXT)
        crash_sty    = sty("crash",    size=8,  color=colors.HexColor("#ff9999"))

        def ival(d, k):
            try: return int(d.get(k, 0))
            except: return 0
        def fval(d, k):
            try: return float(d.get(k, 0))
            except: return 0.0

        run_time = self.format_duration(merged.get("run_time_sec", 0))
        crash_count, hang_count, crash_files, hang_files = self.count_crash_files()

        story = []

        # ── Title bar ─────────────────────────────────────────
        story.append(Paragraph("AFL++ Fuzzing Report", title_sty))
        story.append(Paragraph(f"{len(instances)} instance(s) combined  ·  Output: {self.final_output_dir}", subtitle_sty))
        story.append(HRFlowable(width="100%", thickness=1, color=GREEN, spaceAfter=10))

        # ── Summary cards table ───────────────────────────────
        story.append(Paragraph("SUMMARY", section_sty))

        cards = [
            ("EXECUTIONS",     f"{merged['execs_done']:,}",        GREEN),
            ("EXEC / SEC",     f"{merged['execs_per_sec']:,.1f}",  CYAN),
            ("PATHS FOUND",    f"{merged['paths_total']:,}",       YELLOW),
            ("UNIQUE CRASHES", f"{merged['unique_crashes']:,}",    RED   if merged['unique_crashes'] > 0 else GREY),
            ("UNIQUE HANGS",   f"{merged['unique_hangs']:,}",      ORANGE if merged['unique_hangs'] > 0 else GREY),
            ("CYCLES DONE",    f"{merged['cycles_done']:,}",       PURPLE),
            ("RUN TIME",       run_time,                           LIGHT_BLUE),
            ("CORPUS SIZE",    f"{merged['corpus_count']:,}",      LIGHT_GREEN),
        ]

        # Build 4-column card rows (2 rows of 4)
        CARD_W = (W - MARGIN * 2) / 4

        def card_cell(label, value, color):
            inner = Table(
                [[Paragraph(value, sty("cv", size=16, color=color, bold=True, align=1))],
                 [Paragraph(label, sty("cl", size=7,  color=DIM,   align=1))]],
                colWidths=[CARD_W - 8]
            )
            inner.setStyle(TableStyle([
                ("ALIGN",       (0,0), (-1,-1), "CENTER"),
                ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
                ("TOPPADDING",  (0,0), (-1,-1), 6),
                ("BOTTOMPADDING",(0,0),(-1,-1), 6),
            ]))
            return inner

        for row_cards in [cards[:4], cards[4:]]:
            row_data  = [[card_cell(l, v, c) for l, v, c in row_cards]]
            row_table = Table(row_data, colWidths=[CARD_W] * 4)
            row_table.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), CARD_BG),
                ("GRID",          (0,0), (-1,-1), 0.5, BG),
                ("ROUNDEDCORNERS",[4]),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
                ("TOPPADDING",    (0,0), (-1,-1), 0),
                ("BOTTOMPADDING", (0,0), (-1,-1), 0),
            ]))
            story.append(row_table)
            story.append(Spacer(1, 4))

        # ── Charts ────────────────────────────────────────────
        story.append(Paragraph("COVERAGE &amp; PERFORMANCE", section_sty))

        chart_buf = self._render_charts_image(merged, instances)
        if chart_buf:
            img = Image(chart_buf, width=W - MARGIN * 2, height=(W - MARGIN * 2) * 0.6)
            story.append(img)
            story.append(Spacer(1, 6))

        # ── Per-instance table ─────────────────────────────────
        story.append(Paragraph("PER-INSTANCE BREAKDOWN", section_sty))

        headers = ["Instance", "Execs", "Exec/s", "Paths", "Crashes",
                   "Hangs", "Cycles", "Corpus", "Depth", "Stability", "Coverage"]
        col_w   = [1.1*inch, 0.85*inch, 0.65*inch, 0.65*inch, 0.65*inch,
                   0.65*inch, 0.6*inch, 0.65*inch, 0.6*inch, 0.7*inch, 0.7*inch]

        def hdr_p(t):
            return Paragraph(t, sty("th", size=8, color=GREEN, bold=True, align=1))
        def cell_p(t, color=TEXT):
            return Paragraph(t, sty("td", size=8, color=color, align=1))

        table_data = [[hdr_p(h) for h in headers]]
        for n, inst in enumerate(instances):
            table_data.append([
                cell_p(inst.get("_label", f"inst{n}")),
                cell_p(f"{ival(inst,'execs_done'):,}"),
                cell_p(f"{fval(inst,'execs_per_sec'):,.1f}"),
                cell_p(f"{ival(inst,'paths_total'):,}"),
                cell_p(f"{ival(inst,'unique_crashes'):,}", RED if ival(inst,'unique_crashes') > 0 else TEXT),
                cell_p(f"{ival(inst,'unique_hangs'):,}",  ORANGE if ival(inst,'unique_hangs') > 0 else TEXT),
                cell_p(f"{ival(inst,'cycles_done'):,}"),
                cell_p(f"{ival(inst,'corpus_count'):,}"),
                cell_p(f"{ival(inst,'max_depth'):,}"),
                cell_p(inst.get("stability", "n/a")),
                cell_p(inst.get("bitmap_cvg", "n/a")),
            ])

        # Totals row
        table_data.append([
            cell_p("COMBINED", YELLOW),
            cell_p(f"{merged['execs_done']:,}",       YELLOW),
            cell_p(f"{merged['execs_per_sec']:,.1f}",  YELLOW),
            cell_p(f"{merged['paths_total']:,}",       YELLOW),
            cell_p(f"{merged['unique_crashes']:,}",    YELLOW),
            cell_p(f"{merged['unique_hangs']:,}",      YELLOW),
            cell_p(f"{merged['cycles_done']:,}",       YELLOW),
            cell_p(f"{merged['corpus_count']:,}",      YELLOW),
            cell_p(f"{merged['max_depth']:,}",         YELLOW),
            cell_p("—", YELLOW),
            cell_p("—", YELLOW),
        ])

        tbl = Table(table_data, colWidths=col_w, repeatRows=1)
        n_inst = len(instances)
        row_styles = [
            ("BACKGROUND",    (0, 0),      (-1, 0),          HDR_BG),
            ("BACKGROUND",    (0, n_inst+1),(-1, n_inst+1),  TOTALS_BG),
            ("GRID",          (0, 0),      (-1, -1),         0.4, colors.HexColor("#333344")),
            ("TOPPADDING",    (0, 0),      (-1, -1),         4),
            ("BOTTOMPADDING", (0, 0),      (-1, -1),         4),
            ("VALIGN",        (0, 0),      (-1, -1),         "MIDDLE"),
        ]
        for i in range(1, n_inst + 1):
            bg = ROW_A if i % 2 == 1 else ROW_B
            row_styles.append(("BACKGROUND", (0, i), (-1, i), bg))
        tbl.setStyle(TableStyle(row_styles))
        story.append(tbl)

        # ── Crash file list ────────────────────────────────────
        if crash_files or hang_files:
            story.append(Paragraph("CRASH &amp; HANG FILES", sty("cs", size=12, color=RED, bold=True, space_before=14, space_after=4)))
            crash_lines = []
            if crash_files:
                crash_lines.append(f"── CRASHES ({len(crash_files)} shown) ──")
                crash_lines += [f"  {f}" for f in crash_files]
            if hang_files:
                crash_lines.append(f"── HANGS ({len(hang_files)} shown) ──")
                crash_lines += [f"  {f}" for f in hang_files]
            crash_tbl = Table(
                [[Paragraph("<br/>".join(crash_lines), crash_sty)]],
                colWidths=[W - MARGIN * 2]
            )
            crash_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#110a0a")),
                ("TOPPADDING",    (0,0), (-1,-1), 8),
                ("BOTTOMPADDING", (0,0), (-1,-1), 8),
                ("LEFTPADDING",   (0,0), (-1,-1), 10),
            ]))
            story.append(crash_tbl)

        # ── Metadata ──────────────────────────────────────────
        story.append(Paragraph("RUN METADATA", section_sty))
        meta_rows = [
            ("Target",        merged.get("afl_banner",   "n/a")),
            ("Command",       merged.get("command_line", "n/a")),
            ("Target mode",   merged.get("target_mode",  "n/a")),
            ("Run time",      run_time),
            ("Peak RSS",      f"{merged.get('peak_rss_mb', 0)} MB (combined)"),
            ("Saved crashes", str(merged.get("saved_crashes", 0))),
            ("Saved hangs",   str(merged.get("saved_hangs",   0))),
            ("Output dir",    str(self.final_output_dir)),
        ]
        meta_tbl_data = [
            [Paragraph(k, sty("mk", size=9, color=CYAN,  bold=True)),
             Paragraph(v, sty("mv", size=9, color=TEXT))]
            for k, v in meta_rows
        ]
        meta_tbl = Table(meta_tbl_data, colWidths=[1.3*inch, W - MARGIN*2 - 1.3*inch])
        meta_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#0d0d1a")),
            ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#222233")),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ]))
        story.append(meta_tbl)

        doc.build(story, onFirstPage=bg_canvas, onLaterPages=bg_canvas)

    def _render_charts_image(self, merged, instances):
        """
        Render high-quality, publication-ready charts and return a PNG buffer.
        Optimized for readability in PDFs.
        """
        import io
        matplotlib.use("Agg")
        import numpy as np

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

        n = len(labels)
        x = np.arange(n)

        # ── Figure setup (wider + taller for print clarity) ──
        fig = plt.figure(figsize=(16, 10), facecolor="#0d0d1a")

        # Grid: big top chart + 2 rows of smaller charts
        gs = fig.add_gridspec(3, 2, height_ratios=[1.2, 1, 1], hspace=0.55, wspace=0.3)

        ax_paths   = fig.add_subplot(gs[0, :])   # full width
        ax_eps     = fig.add_subplot(gs[1, 0])
        ax_crashes = fig.add_subplot(gs[1, 1])
        ax_corpus  = fig.add_subplot(gs[2, 0])
        ax_depth   = fig.add_subplot(gs[2, 1])

        # ── Color palette ──
        COLORS = ["#00ff88", "#00ccff", "#ffcc00", "#ff4444", "#cc88ff", "#ff8800"]
        bar_colors = [COLORS[i % len(COLORS)] for i in range(n)]

        # ── Styling helper ──
        def style_ax(ax, title):
            ax.set_facecolor("#111122")
            ax.set_title(title, color="#ffffff", fontsize=12, pad=10, weight="bold")
            ax.tick_params(colors="#bbbbbb", labelsize=9)
            for spine in ax.spines.values():
                spine.set_edgecolor("#333344")
            ax.grid(axis="x", linestyle="--", alpha=0.2)

        # ─────────────────────────────────────────────
        # 1. PATHS (PRIMARY CHART - horizontal, full width)
        # ─────────────────────────────────────────────
        style_ax(ax_paths, "Coverage Growth (Paths Found per Instance)")

        bars = ax_paths.barh(labels, paths_vals, color=bar_colors, edgecolor="#222233", height=0.6)

        max_val = max(paths_vals) if paths_vals else 1
        for bar, val in zip(bars, paths_vals):
            ax_paths.text(
                bar.get_width() + max_val * 0.01,
                bar.get_y() + bar.get_height() / 2,
                f"{val:,}",
                va="center",
                ha="left",
                color="#dddddd",
                fontsize=10
            )

        ax_paths.set_xlabel("Total Paths Discovered", color="#cccccc", fontsize=10)

        # ─────────────────────────────────────────────
        # 2. EXECUTION SPEED
        # ─────────────────────────────────────────────
        style_ax(ax_eps, "Execution Throughput (exec/sec)")
        ax_eps.bar(x, eps_vals, color=bar_colors, edgecolor="#222233")
        ax_eps.set_xticks(x)
        ax_eps.set_xticklabels(labels, rotation=30, ha="right")
        ax_eps.set_ylabel("exec/sec", color="#cccccc", fontsize=10)

        # ─────────────────────────────────────────────
        # 3. CRASHES & HANGS
        # ─────────────────────────────────────────────
        style_ax(ax_crashes, "Stability (Crashes & Hangs)")
        width = 0.4

        ax_crashes.bar(x - width/2, crash_vals, width,
                    label="Crashes", edgecolor="#222233")
        ax_crashes.bar(x + width/2, hang_vals, width,
                    label="Hangs", edgecolor="#222233")

        ax_crashes.set_xticks(x)
        ax_crashes.set_xticklabels(labels, rotation=30, ha="right")
        ax_crashes.legend(frameon=False, fontsize=9)
        ax_crashes.set_ylabel("Count", color="#cccccc", fontsize=10)

        # ─────────────────────────────────────────────
        # 4. CORPUS SIZE
        # ─────────────────────────────────────────────
        style_ax(ax_corpus, "Corpus Growth")
        ax_corpus.bar(x, corpus_vals, color=bar_colors, edgecolor="#222233")
        ax_corpus.set_xticks(x)
        ax_corpus.set_xticklabels(labels, rotation=30, ha="right")
        ax_corpus.set_ylabel("Inputs", color="#cccccc", fontsize=10)

        # ─────────────────────────────────────────────
        # 5. MAX DEPTH
        # ─────────────────────────────────────────────
        style_ax(ax_depth, "Exploration Depth")
        ax_depth.bar(x, depth_vals, color=bar_colors, edgecolor="#222233")
        ax_depth.set_xticks(x)
        ax_depth.set_xticklabels(labels, rotation=30, ha="right")
        ax_depth.set_ylabel("Call Depth", color="#cccccc", fontsize=10)

        # ── Tight layout for clean PDF embedding ──
        plt.tight_layout()

        # ── Export high-res image ──
        buf = io.BytesIO()
        fig.savefig(
            buf,
            format="png",
            dpi=220,
            facecolor="#0d0d1a",
            bbox_inches="tight"
        )
        buf.seek(0)
        plt.close(fig)

        return buf

    # =========================================================
    # STOP
    # =========================================================
    def stop(self):
        self.monitoring = False
        subprocess.run(["tmux", "kill-session", "-t", "vibefuzzer"])
        self.build_results_screen()

    # =========================================================
    # RESULTS
    # =========================================================
    def build_results_screen(self):
        self.clear()
        frame = ctk.CTkFrame(self)
        frame.pack(expand=True)
        ctk.CTkButton(frame, text="Generate Report", command=self.generate_pdf).pack(pady=10)
        ctk.CTkButton(frame, text="Run Again", command=self.build_config_screen).pack(pady=10)

    def generate_pdf(self):
        from reportlab.platypus import SimpleDocTemplate, Paragraph
        from reportlab.lib.styles import getSampleStyleSheet
        output = self.output_dir.get()
        pdf = os.path.join(output, "report.pdf")
        doc = SimpleDocTemplate(pdf)
        styles = getSampleStyleSheet()
        content = [Paragraph("Fuzzing Report", styles["Title"])]
        doc.build(content)

    # =========================================================
    def clear(self):
        for w in self.winfo_children():
            w.destroy()


if __name__ == "__main__":
    app = VibeFuzzerGUI()
    app.mainloop()
