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

# ── PALETTE ──────────────────────────────────────────────────────────────────
BG_ROOT      = "#06090f"   # near-black navy — window background
BG_FRAME     = "#0b1120"   # deep navy — main frame
BG_CARD      = "#0f1829"   # card / panel background
BG_HEADER    = "#0d1526"   # title bars
BG_ROW_A     = "#111d35"   # table row A
BG_ROW_B     = "#0e1730"   # table row B
BG_TOTALS    = "#13203d"   # totals row
BG_CRASH_BOX = "#110d1a"   # crash textbox (slight purple tint)
BG_META_BOX  = "#0b1120"   # metadata textbox

ACCENT       = "#3b82f6"   # vivid blue — primary accent
ACCENT_HOVER = "#2563eb"   # darker blue hover
ACCENT2      = "#60a5fa"   # sky blue — secondary accent
ACCENT_GREEN = "#22d3ee"   # cyan-teal for key numbers
ACCENT_WARN  = "#f59e0b"   # amber — warnings / combined row
ACCENT_ERR   = "#ef4444"   # red — crashes
ACCENT_HANG  = "#f97316"   # orange — hangs
ACCENT_PURP  = "#a78bfa"   # purple — misc stats

TEXT_MAIN    = "#cbd5e1"   # primary text
TEXT_DIM     = "#64748b"   # dimmed / labels
TEXT_BRIGHT  = "#e2e8f0"   # bright text
TEXT_SUBTLE  = "#94a3b8"   # subtle text

BORDER       = "#1e3a5f"   # subtle border color

VALID_PROTOCOLS = ["HTTP"]

HELP_SECTIONS = [
    ("Overview", """VibeFuzzer is an AFL++-based network fuzzer that uses an LLM mutator to intelligently generate and mutate protocol-aware inputs. It wraps AFL++, libdesock, and an Ollama-powered C mutator into a single GUI workflow."""),

    ("Quick Start", """1. Select the target source folder (the directory containing the server's source code).
2. Optionally specify a binary path relative to the source folder (e.g. objs/nginx). Leave blank to auto-detect.
3. Choose the protocol the target speaks (HTTP, FTP, SMTP, etc).
4. Set input/output directories, or leave blank to use ./input and ./output.
5. Click Start. VibeFuzzer will build the target, generate seeds, and launch AFL++ in a tmux session."""),

    ("Target Source Folder", """The root directory of the server you want to fuzz. VibeFuzzer will instrument and build it automatically using afl-clang-fast.

Supported build systems: CMake, Meson, Autotools (./configure), and plain Make. If none are detected, standard Make is used as a fallback."""),

    ("Target Binary (optional)", """The path to the compiled binary, relative to the source folder. For example:
  objs/nginx
  src/server
  build/ftpd

If left unchecked, VibeFuzzer will auto-scan the source directory for instrumented ELF executables after building. Auto-detection fails if multiple instrumented binaries are found — in that case, specify the binary explicitly."""),

    ("Protocol", """The network protocol the target speaks. This is used to generate meaningful seed inputs for the LLM and for corpus initialisation.

Supported: HTTP, FTP, SMTP, RTSP, DNS, SIP.

If your protocol isn't listed, select the closest match or use --no-llm-seeds with a manual corpus."""),

    ("Input / Output Directories", """Input: the seed corpus directory. AFL++ reads initial inputs from here. Defaults to ./input.
Output: where AFL++ writes crashes, hangs, and coverage data. Defaults to ./output.

If LLM seeds are enabled, VibeFuzzer will populate the input directory automatically before fuzzing starts. If you disable LLM seeds, the input directory must contain at least one seed file."""),

    ("LLM Seeds", """By default, VibeFuzzer uses Ollama (afl-mutator model) to generate protocol-aware seed inputs before fuzzing. This requires Ollama to be running locally.

Num Seeds: how many seeds to generate (default 10). More seeds improve initial coverage but slow startup.

Disable LLM Seeds: skip generation entirely and use your existing corpus. You must provide at least one seed in the input directory."""),

    ("Custom Build / Configure / Make Args", """Override or augment the build process:

Custom Build Command: replaces the entire build step with a shell command you provide. The AFL++ compiler wrappers (CC=afl-clang-fast) are prepended automatically.

Configure Args: extra arguments passed to ./configure or cmake/meson setup (e.g. --disable-ssl).

Make Args: extra arguments for the compile step (e.g. -j4)."""),

    ("AFL Args", """Extra flags passed directly to afl-fuzz before the -- separator. Examples:
  -p fast          use the fast power schedule
  -p explore       use the exploration schedule
  -c /path/to/cmplog   enable CmpLog for better coverage

These are applied to both the primary and secondary AFL++ instances."""),

    ("Target Args", """Arguments passed to the target binary after the -- separator in the afl-fuzz command. Use these for flags your server needs at startup. Example:
  -c /etc/nginx/fuzz.conf
  -p 8080"""),

    ("Fuzzing Instances", """VibeFuzzer runs two AFL++ instances in parallel inside a tmux session:

Primary (afl-fuzz -M): the main instance running standard AFL++ mutations.
Secondary (afl-fuzz -S): a secondary instance using the custom LLM mutator. It queries Ollama every 200 executions to generate semantically meaningful mutations based on the current corpus.

Both instances share the same output directory and synchronise their queues automatically via AFL++'s parallel fuzzing protocol."""),

    ("Results & Reports", """When the tmux session ends, VibeFuzzer shows a results screen with:
  - Execution count, exec/sec, paths found, crashes, hangs
  - Per-instance breakdown table
  - Coverage and performance charts
  - Crash and hang file listing

Click Export PDF to save a full report. Click Run Again to start a new session."""),

    ("Prerequisites", """Before using VibeFuzzer, run setup.sh to build all dependencies:
  ./setup.sh

This builds AFL++, libdesock, and the LLM mutator (.so). It also pulls the afl-mutator Ollama model.

Requirements: clang, make, cmake, libcurl, libcjson, tmux, ollama."""),
]


class VibeFuzzerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Vibe Fuzzer")
        self.geometry("900x750")
        self.configure(fg_color=BG_ROOT)

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

    # ── SHARED WIDGET HELPERS ─────────────────────────────────────────────────
    def _styled_frame(self, parent, **kwargs):
        return ctk.CTkFrame(parent, fg_color=BG_FRAME, **kwargs)

    def _title_bar(self, parent, title_text, subtitle=None):
        bar = ctk.CTkFrame(parent, fg_color=BG_HEADER, corner_radius=0)
        bar.pack(fill="x")

        left = ctk.CTkFrame(bar, fg_color="transparent")
        left.pack(side="left", padx=20, pady=12)
        ctk.CTkLabel(
            left, text=title_text,
            font=("Courier Bold", 18), text_color=ACCENT2
        ).pack(side="left")
        if subtitle:
            ctk.CTkLabel(
                left, text=f"  {subtitle}",
                font=("Courier", 11), text_color=TEXT_DIM
            ).pack(side="left", padx=(8, 0))
        return bar

    def _section_label(self, parent, text, color=ACCENT2):
        ctk.CTkLabel(
            parent, text=text,
            font=("Courier Bold", 13), text_color=color
        ).pack(anchor="w", padx=4, pady=(10, 4))

    def _btn(self, parent, text, command, width=110, primary=True, **kwargs):
        fg    = ACCENT       if primary else BG_CARD
        hover = ACCENT_HOVER if primary else "#1a2540"
        tc    = "#ffffff"    if primary else TEXT_SUBTLE
        return ctk.CTkButton(
            parent, text=text, width=width,
            fg_color=fg, hover_color=hover, text_color=tc,
            font=("Courier", 12),
            command=command, **kwargs
        )

    def _checkbox(self, parent, text, variable, command):
        return ctk.CTkCheckBox(
            parent, text=text,
            variable=variable, command=command,
            text_color=TEXT_MAIN,
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            checkmark_color="#ffffff",
            border_color=BORDER,
            font=("Courier", 12),
        )

    def _entry(self, parent, placeholder):
        return ctk.CTkEntry(
            parent,
            placeholder_text=placeholder,
            fg_color=BG_CARD,
            border_color=BORDER,
            text_color=TEXT_BRIGHT,
            placeholder_text_color=TEXT_DIM,
            font=("Courier", 12),
        )

    # =========================================================
    # HELP SCREEN
    # =========================================================
    def show_help(self):
        self.clear()
        self.geometry("900x750")

        outer = ctk.CTkFrame(self, fg_color=BG_ROOT)
        outer.pack(fill="both", expand=True)

        bar = self._title_bar(outer, "VibeFuzzer — Help")
        self._btn(
            bar, "← Back", self.build_config_screen,
            width=90, primary=False
        ).pack(side="right", padx=15, pady=10)

        scroll = ctk.CTkScrollableFrame(outer, fg_color=BG_ROOT)
        scroll.pack(fill="both", expand=True, padx=0, pady=0)

        for section_title, section_body in HELP_SECTIONS:
            header_frame = ctk.CTkFrame(scroll, fg_color=BG_HEADER, corner_radius=6)
            header_frame.pack(fill="x", padx=16, pady=(14, 0))
            ctk.CTkLabel(
                header_frame,
                text=section_title.upper(),
                font=("Courier Bold", 11),
                text_color=ACCENT2,
                anchor="w"
            ).pack(padx=14, pady=6, anchor="w")

            body_frame = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=0)
            body_frame.pack(fill="x", padx=16, pady=(0, 2))
            ctk.CTkLabel(
                body_frame,
                text=section_body,
                font=("Courier", 11),
                text_color=TEXT_DIM,
                anchor="w",
                justify="left",
                wraplength=820,
            ).pack(padx=14, pady=10, anchor="w")

        self._btn(
            scroll, "← Back to Configuration",
            self.build_config_screen, width=240, primary=False
        ).pack(pady=20)

    # =========================================================
    # CONFIG SCREEN
    # =========================================================
    def build_config_screen(self):
        self.clear()
        self.configure(fg_color=BG_ROOT)

        frame = ctk.CTkFrame(self, fg_color=BG_FRAME)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        # Title row
        title_row = ctk.CTkFrame(frame, fg_color=BG_HEADER, corner_radius=8)
        title_row.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(
            title_row, text="Vibe Fuzzer",
            font=("Courier Bold", 24), text_color=ACCENT2
        ).pack(side="left", padx=16, pady=10)
        self._btn(
            title_row, "?", self.show_help,
            width=32, primary=False
        ).pack(side="right", padx=10, pady=8)

        self.target_source_dir = self.clickable_file_entry(
            frame, "Select Target Source Folder"
        )

        # Target binary row
        self.binary_frame = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=6)
        self.binary_frame.pack(fill="x", pady=5)

        self.binary_checkbox = self._checkbox(
            self.binary_frame, "Target Binary",
            self.use_target_binary, self.toggle_target_binary
        )
        self.binary_checkbox.pack(side="left", padx=(10, 10), pady=8, anchor="w")

        self.target_binary_path = self._entry(self.binary_frame, "Select Target Binary Location")
        self.target_binary_path.pack(side="left", fill="x", expand=True)

        def browse_binary():
            path = filedialog.askopenfilename()
            if path:
                self.target_binary_path.delete(0, "end")
                self.target_binary_path.insert(0, path)

        self.binary_browse_btn = self._btn(self.binary_frame, "Browse", browse_binary, width=80)
        self.binary_browse_btn.pack(side="right", padx=8, pady=6)

        self.target_binary_path.pack_forget()
        self.binary_browse_btn.pack_forget()

        # Target args row
        self.target_args_frame = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=6)
        self.target_args_frame.pack(fill="x", pady=5)
        self.target_args_checkbox = self._checkbox(
            self.target_args_frame, "Target Args",
            self.use_target_args, self.toggle_target_args
        )
        self.target_args_checkbox.pack(side="left", padx=(10, 10), pady=8, anchor="w")
        self.target_args_input = self._entry(self.target_args_frame, "Target Args")
        self.target_args_input.pack(side="left", fill="x", expand=True)
        self.target_args_input.pack_forget()

        self.input_dir = self.clickable_file_entry(
            frame, "Select Input Directory (default ./input)"
        )
        self.output_dir = self.clickable_file_entry(
            frame, "Select Output Directory (default ./output)"
        )

        # Protocol row
        protocol_frame = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=6)
        protocol_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(
            protocol_frame, text="Protocol",
            width=120, anchor="w",
            text_color=TEXT_MAIN, font=("Courier", 12)
        ).pack(side="left", padx=(10, 10), pady=8)
        self.protocol = ctk.CTkComboBox(
            protocol_frame, values=VALID_PROTOCOLS,
            fg_color=BG_CARD, border_color=BORDER,
            button_color=ACCENT, button_hover_color=ACCENT_HOVER,
            text_color=TEXT_BRIGHT, dropdown_fg_color=BG_HEADER,
            dropdown_text_color=TEXT_BRIGHT,
            font=("Courier", 12),
        )
        self.protocol.pack(side="left", fill="x", expand=True, padx=(0, 10), pady=6)

        # Optional checkbox rows
        self.custom_build_frame = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=6)
        self.custom_build_frame.pack(fill="x", pady=5)
        self.custom_build_checkbox = self._checkbox(
            self.custom_build_frame, "Custom Build Command",
            self.use_custom_build, self.toggle_custom_build
        )
        self.custom_build_checkbox.pack(side="left", padx=(10, 10), pady=8, anchor="w")
        self.custom_build = self._entry(self.custom_build_frame, "Custom Build Command")
        self.custom_build.pack(side="left", fill="x", expand=True)
        self.custom_build.pack_forget()

        self.configure_args_frame = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=6)
        self.configure_args_frame.pack(fill="x", pady=5)
        self.configure_args_checkbox = self._checkbox(
            self.configure_args_frame, "Configure Args",
            self.use_configure_args, self.toggle_configure_args
        )
        self.configure_args_checkbox.pack(side="left", padx=(10, 10), pady=8, anchor="w")
        self.configure_args = self._entry(self.configure_args_frame, "Configure Args")
        self.configure_args.pack(side="left", fill="x", expand=True)
        self.configure_args.pack_forget()

        self.make_args_frame = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=6)
        self.make_args_frame.pack(fill="x", pady=5)
        self.make_args_checkbox = self._checkbox(
            self.make_args_frame, "Make Args",
            self.use_make_args, self.toggle_make_args
        )
        self.make_args_checkbox.pack(side="left", padx=(10, 10), pady=8, anchor="w")
        self.make_args = self._entry(self.make_args_frame, "Make Args")
        self.make_args.pack(side="left", fill="x", expand=True)
        self.make_args.pack_forget()

        self.afl_args_frame = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=6)
        self.afl_args_frame.pack(fill="x", pady=5)
        self.afl_args_checkbox = self._checkbox(
            self.afl_args_frame, "AFL Args",
            self.use_afl_args, self.toggle_afl_args
        )
        self.afl_args_checkbox.pack(side="left", padx=(10, 10), pady=8, anchor="w")
        self.afl_args_input = self._entry(self.afl_args_frame, "AFL Args")
        self.afl_args_input.pack(side="left", fill="x", expand=True)
        self.afl_args_input.pack_forget()

        self.llm_frame = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=6)
        self.llm_frame.pack(fill="x", pady=5)
        self.no_llm_checkbox = self._checkbox(
            self.llm_frame, "Disable LLM Seeds",
            self.no_llm, self.toggle_num_seeds
        )
        self.no_llm_checkbox.pack(side="left", padx=(10, 10), pady=8, anchor="w")
        self.num_seeds = self._entry(self.llm_frame, "Num Seeds (default 10)")
        self.num_seeds.pack(side="left", fill="x", expand=True)

        self.start_button = self._btn(frame, "Start", self.start, width=200)
        self.start_button.pack(pady=20)

    def clickable_file_entry(self, parent, placeholder, is_file=False):
        frame = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=6)
        frame.pack(pady=5, fill="x")

        entry = self._entry(frame, placeholder)
        entry.pack(side="left", fill="x", expand=True, padx=(8, 5), pady=6)

        def open_picker():
            path = filedialog.askopenfilename() if is_file else filedialog.askdirectory()
            if path:
                entry.delete(0, "end")
                entry.insert(0, path)

        browse_btn = self._btn(frame, "Browse", open_picker, width=80)
        browse_btn.pack(side="right", padx=6, pady=6)

        return entry

    def entry(self, parent, placeholder):
        e = self._entry(parent, placeholder)
        e.pack(pady=5, fill="x")
        return e

    def toggle_target_binary(self):
        if self.use_target_binary.get():
            self.target_binary_path.pack(side="left", fill="x", expand=True)
            self.binary_browse_btn.pack(side="right", padx=8, pady=6)
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
            target_dir = self.target_source_dir.get()
            binary_name = ""

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
        self.configure(fg_color=BG_ROOT)

        merged, instances = self.parse_all_stats()

        outer = ctk.CTkFrame(self, fg_color=BG_ROOT)
        outer.pack(fill="both", expand=True)

        bar = self._title_bar(
            outer, "AFL++ Fuzzing Report",
            subtitle=f"{len(instances)} instance(s) combined"
        )

        btn_frame = ctk.CTkFrame(bar, fg_color="transparent")
        btn_frame.pack(side="right", padx=10)
        self._btn(btn_frame, "Export PDF", self.download_pdf, width=110).pack(side="left", padx=5, pady=8)
        self._btn(btn_frame, "Run Again", self.build_config_screen, width=110, primary=False).pack(side="left", padx=5, pady=8)

        scroll = ctk.CTkScrollableFrame(outer, fg_color=BG_ROOT)
        scroll.pack(fill="both", expand=True, padx=10, pady=10)

        if not merged:
            ctk.CTkLabel(scroll, text="No fuzzer_stats files found in output directory.",
                         font=("Courier", 14), text_color=ACCENT_ERR).pack(pady=40)
            return

        cards_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        cards_frame.pack(fill="x", pady=(0, 10))

        crash_count, hang_count, crash_files, hang_files = self.count_crash_files()
        run_time = self.format_duration(merged.get("run_time_sec", 0))

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
            ctk.CTkLabel(card, text=label, font=("Courier", 9), text_color=TEXT_DIM).pack(pady=(0, 10))

        self._section_label(scroll, "COVERAGE & PERFORMANCE")

        # Charts — use the dark blue palette
        CHART_COLORS = [ACCENT2, ACCENT, ACCENT_PURP, ACCENT_WARN, ACCENT_GREEN, ACCENT_HANG]
        CHART_BG     = BG_ROOT
        CHART_PANEL  = BG_CARD
        CHART_SPINE  = BORDER

        fig = plt.Figure(figsize=(11, 7), facecolor=CHART_BG)
        gs  = gridspec.GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.35)

        ax_paths   = fig.add_subplot(gs[0, :2])
        ax_eps     = fig.add_subplot(gs[0, 2])
        ax_crashes = fig.add_subplot(gs[1, 0])
        ax_corpus  = fig.add_subplot(gs[1, 1])
        ax_depth   = fig.add_subplot(gs[1, 2])

        def style_ax(ax, title):
            ax.set_facecolor(CHART_PANEL)
            ax.tick_params(colors=TEXT_DIM, labelsize=8)
            ax.set_title(title, color=TEXT_SUBTLE, fontsize=9, pad=6)
            for spine in ax.spines.values():
                spine.set_edgecolor(CHART_SPINE)

        labels      = [i.get("_label", f"inst{n}") for n, i in enumerate(instances)]
        bar_colors  = [CHART_COLORS[i % len(CHART_COLORS)] for i in range(len(labels))]

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

        style_ax(ax_paths, "Paths Found per Instance")
        bars = ax_paths.barh(labels, paths_vals, color=bar_colors, edgecolor=CHART_SPINE, height=0.5)
        for bar, val in zip(bars, paths_vals):
            offset = max(paths_vals) * 0.01 if max(paths_vals) > 0 else 1
            ax_paths.text(bar.get_width() + offset, bar.get_y() + bar.get_height() / 2,
                          f"{val:,}", va="center", ha="left", color=TEXT_SUBTLE, fontsize=8)
        ax_paths.set_xlabel("Paths", color=TEXT_DIM, fontsize=8)

        style_ax(ax_eps, "Exec/sec per Instance")
        ax_eps.bar(labels, eps_vals, color=bar_colors, edgecolor=CHART_SPINE)
        ax_eps.set_ylabel("exec/s", color=TEXT_DIM, fontsize=8)
        ax_eps.tick_params(axis="x", rotation=20)

        style_ax(ax_crashes, "Crashes & Hangs")
        x = list(range(len(labels)))
        w = 0.35
        ax_crashes.bar([xi - w/2 for xi in x], crash_vals, width=w,
                       label="crashes", color=ACCENT_ERR, edgecolor=CHART_SPINE)
        ax_crashes.bar([xi + w/2 for xi in x], hang_vals, width=w,
                       label="hangs", color=ACCENT_HANG, edgecolor=CHART_SPINE)
        ax_crashes.set_xticks(x)
        ax_crashes.set_xticklabels(labels, rotation=20, fontsize=7)
        ax_crashes.legend(fontsize=7, facecolor=BG_HEADER, labelcolor=TEXT_DIM)

        style_ax(ax_corpus, "Corpus Size per Instance")
        ax_corpus.bar(labels, corpus_vals, color=bar_colors, edgecolor=CHART_SPINE)
        ax_corpus.set_ylabel("entries", color=TEXT_DIM, fontsize=8)
        ax_corpus.tick_params(axis="x", rotation=20)

        style_ax(ax_depth, "Max Call Depth per Instance")
        ax_depth.bar(labels, depth_vals, color=bar_colors, edgecolor=CHART_SPINE)
        ax_depth.set_ylabel("depth", color=TEXT_DIM, fontsize=8)
        ax_depth.tick_params(axis="x", rotation=20)

        canvas_widget = FigureCanvasTkAgg(fig, master=scroll)
        canvas_widget.draw()
        canvas_widget.get_tk_widget().pack(fill="x", pady=(0, 10))

        self._section_label(scroll, "PER-INSTANCE BREAKDOWN")

        table_frame = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=8)
        table_frame.pack(fill="x", padx=4, pady=(0, 10))

        headers    = ["Instance", "Execs", "Exec/s", "Paths", "Crashes", "Hangs",
                      "Cycles", "Corpus", "Max Depth", "Stability", "Coverage"]
        col_widths = [120, 100, 80, 80, 80, 80, 70, 80, 90, 90, 90]

        header_row = ctk.CTkFrame(table_frame, fg_color=BG_HEADER)
        header_row.pack(fill="x")
        for h, w in zip(headers, col_widths):
            ctk.CTkLabel(header_row, text=h, font=("Courier Bold", 10),
                         text_color=ACCENT2, width=w, anchor="center").pack(side="left", padx=2, pady=6)

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
                ctk.CTkLabel(row, text=val, font=("Courier", 10),
                             text_color=TEXT_MAIN, width=cw, anchor="center").pack(side="left", padx=2, pady=4)

        totals_row = ctk.CTkFrame(table_frame, fg_color=BG_TOTALS)
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
                         text_color=ACCENT_WARN, width=cw, anchor="center").pack(side="left", padx=2, pady=5)

        if crash_files or hang_files:
            self._section_label(scroll, "CRASH & HANG FILES", color=ACCENT_ERR)
            crash_box = ctk.CTkTextbox(scroll, height=140, font=("Courier", 10),
                                       fg_color=BG_CRASH_BOX, text_color="#f87171",
                                       border_color=BORDER)
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

        self._section_label(scroll, "RUN METADATA")
        meta_box = ctk.CTkTextbox(scroll, height=130, font=("Courier", 10),
                                  fg_color=BG_META_BOX, text_color=TEXT_SUBTLE,
                                  border_color=BORDER)
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

        # PDF colors matching the dark blue scheme
        PDF_BG      = colors.HexColor(BG_ROOT)
        PDF_CARD    = colors.HexColor(BG_CARD)
        PDF_ROW_A   = colors.HexColor(BG_ROW_A)
        PDF_ROW_B   = colors.HexColor(BG_ROW_B)
        PDF_HDR     = colors.HexColor(BG_HEADER)
        PDF_TOTALS  = colors.HexColor(BG_TOTALS)
        PDF_ACCENT  = colors.HexColor(ACCENT2)
        PDF_CYAN    = colors.HexColor(ACCENT)
        PDF_YELLOW  = colors.HexColor(ACCENT_WARN)
        PDF_RED     = colors.HexColor(ACCENT_ERR)
        PDF_ORANGE  = colors.HexColor(ACCENT_HANG)
        PDF_PURPLE  = colors.HexColor(ACCENT_PURP)
        PDF_LBLUE   = colors.HexColor(ACCENT_GREEN)
        PDF_LGREEN  = colors.HexColor(TEXT_BRIGHT)
        PDF_GREY    = colors.HexColor(TEXT_DIM)
        PDF_DIM     = colors.HexColor(TEXT_DIM)
        PDF_TEXT    = colors.HexColor(TEXT_MAIN)
        PDF_BORDER  = colors.HexColor(BORDER)

        W, H = letter
        MARGIN = 0.55 * inch

        doc = SimpleDocTemplate(
            file_path, pagesize=letter,
            leftMargin=MARGIN, rightMargin=MARGIN,
            topMargin=MARGIN, bottomMargin=MARGIN
        )

        def bg_canvas(canv, doc):
            canv.saveState()
            canv.setFillColor(PDF_BG)
            canv.rect(0, 0, W, H, fill=1, stroke=0)
            canv.restoreState()

        def sty(name, font="Courier", size=10, color=PDF_TEXT, bold=False,
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

        title_sty    = sty("title",    size=20, color=PDF_ACCENT, bold=True,  space_before=2, space_after=2)
        subtitle_sty = sty("subtitle", size=10, color=PDF_GREY,   space_after=8)
        section_sty  = sty("section",  size=12, color=PDF_ACCENT, bold=True,  space_before=14, space_after=4)
        label_sty    = sty("label",    size=8,  color=PDF_DIM)
        meta_sty     = sty("meta",     size=9,  color=PDF_TEXT)
        crash_sty    = sty("crash",    size=8,  color=colors.HexColor("#f87171"))

        def ival(d, k):
            try: return int(d.get(k, 0))
            except: return 0
        def fval(d, k):
            try: return float(d.get(k, 0))
            except: return 0.0

        run_time = self.format_duration(merged.get("run_time_sec", 0))
        crash_count, hang_count, crash_files, hang_files = self.count_crash_files()

        story = []

        story.append(Paragraph("AFL++ Fuzzing Report", title_sty))
        story.append(Paragraph(f"{len(instances)} instance(s) combined  ·  Output: {self.final_output_dir}", subtitle_sty))
        story.append(HRFlowable(width="100%", thickness=1, color=PDF_ACCENT, spaceAfter=10))
        story.append(Paragraph("SUMMARY", section_sty))

        cards = [
            ("EXECUTIONS",     f"{merged['execs_done']:,}",        PDF_ACCENT),
            ("EXEC / SEC",     f"{merged['execs_per_sec']:,.1f}",  PDF_CYAN),
            ("PATHS FOUND",    f"{merged['paths_total']:,}",       PDF_YELLOW),
            ("UNIQUE CRASHES", f"{merged['unique_crashes']:,}",    PDF_RED    if merged['unique_crashes'] > 0 else PDF_GREY),
            ("UNIQUE HANGS",   f"{merged['unique_hangs']:,}",      PDF_ORANGE if merged['unique_hangs']   > 0 else PDF_GREY),
            ("CYCLES DONE",    f"{merged['cycles_done']:,}",       PDF_PURPLE),
            ("RUN TIME",       run_time,                           PDF_LBLUE),
            ("CORPUS SIZE",    f"{merged['corpus_count']:,}",      PDF_LGREEN),
        ]

        CARD_W = (W - MARGIN * 2) / 4

        def card_cell(label, value, color):
            inner = Table(
                [[Paragraph(value, sty("cv", size=16, color=color, bold=True, align=1))],
                 [Paragraph(label, sty("cl", size=7,  color=PDF_DIM, align=1))]],
                colWidths=[CARD_W - 8]
            )
            inner.setStyle(TableStyle([
                ("ALIGN",        (0,0), (-1,-1), "CENTER"),
                ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
                ("TOPPADDING",   (0,0), (-1,-1), 6),
                ("BOTTOMPADDING",(0,0), (-1,-1), 6),
            ]))
            return inner

        for row_cards in [cards[:4], cards[4:]]:
            row_data  = [[card_cell(l, v, c) for l, v, c in row_cards]]
            row_table = Table(row_data, colWidths=[CARD_W] * 4)
            row_table.setStyle(TableStyle([
                ("BACKGROUND",     (0,0), (-1,-1), PDF_CARD),
                ("GRID",           (0,0), (-1,-1), 0.5, PDF_BG),
                ("ROUNDEDCORNERS", [4]),
                ("VALIGN",         (0,0), (-1,-1), "MIDDLE"),
                ("TOPPADDING",     (0,0), (-1,-1), 0),
                ("BOTTOMPADDING",  (0,0), (-1,-1), 0),
            ]))
            story.append(row_table)
            story.append(Spacer(1, 4))

        story.append(Paragraph("COVERAGE &amp; PERFORMANCE", section_sty))

        chart_buf = self._render_charts_image(merged, instances)
        if chart_buf:
            img = Image(chart_buf, width=W - MARGIN * 2, height=(W - MARGIN * 2) * 0.6)
            story.append(img)
            story.append(Spacer(1, 6))

        story.append(Paragraph("PER-INSTANCE BREAKDOWN", section_sty))

        headers = ["Instance", "Execs", "Exec/s", "Paths", "Crashes",
                   "Hangs", "Cycles", "Corpus", "Depth", "Stability", "Coverage"]
        col_w   = [1.1*inch, 0.85*inch, 0.65*inch, 0.65*inch, 0.65*inch,
                   0.65*inch, 0.6*inch, 0.65*inch, 0.6*inch, 0.7*inch, 0.7*inch]

        def hdr_p(t):
            return Paragraph(t, sty("th", size=8, color=PDF_ACCENT, bold=True, align=1))
        def cell_p(t, color=PDF_TEXT):
            return Paragraph(t, sty("td", size=8, color=color, align=1))

        table_data = [[hdr_p(h) for h in headers]]
        for n, inst in enumerate(instances):
            table_data.append([
                cell_p(inst.get("_label", f"inst{n}")),
                cell_p(f"{ival(inst,'execs_done'):,}"),
                cell_p(f"{fval(inst,'execs_per_sec'):,.1f}"),
                cell_p(f"{ival(inst,'paths_total'):,}"),
                cell_p(f"{ival(inst,'unique_crashes'):,}", PDF_RED    if ival(inst,'unique_crashes') > 0 else PDF_TEXT),
                cell_p(f"{ival(inst,'unique_hangs'):,}",  PDF_ORANGE if ival(inst,'unique_hangs')   > 0 else PDF_TEXT),
                cell_p(f"{ival(inst,'cycles_done'):,}"),
                cell_p(f"{ival(inst,'corpus_count'):,}"),
                cell_p(f"{ival(inst,'max_depth'):,}"),
                cell_p(inst.get("stability", "n/a")),
                cell_p(inst.get("bitmap_cvg", "n/a")),
            ])

        table_data.append([
            cell_p("COMBINED", PDF_YELLOW),
            cell_p(f"{merged['execs_done']:,}",       PDF_YELLOW),
            cell_p(f"{merged['execs_per_sec']:,.1f}",  PDF_YELLOW),
            cell_p(f"{merged['paths_total']:,}",       PDF_YELLOW),
            cell_p(f"{merged['unique_crashes']:,}",    PDF_YELLOW),
            cell_p(f"{merged['unique_hangs']:,}",      PDF_YELLOW),
            cell_p(f"{merged['cycles_done']:,}",       PDF_YELLOW),
            cell_p(f"{merged['corpus_count']:,}",      PDF_YELLOW),
            cell_p(f"{merged['max_depth']:,}",         PDF_YELLOW),
            cell_p("—", PDF_YELLOW),
            cell_p("—", PDF_YELLOW),
        ])

        tbl = Table(table_data, colWidths=col_w, repeatRows=1)
        n_inst = len(instances)
        row_styles = [
            ("BACKGROUND",    (0, 0),         (-1, 0),          PDF_HDR),
            ("BACKGROUND",    (0, n_inst+1),  (-1, n_inst+1),   PDF_TOTALS),
            ("GRID",          (0, 0),         (-1, -1),         0.4, PDF_BORDER),
            ("TOPPADDING",    (0, 0),         (-1, -1),         4),
            ("BOTTOMPADDING", (0, 0),         (-1, -1),         4),
            ("VALIGN",        (0, 0),         (-1, -1),         "MIDDLE"),
        ]
        for i in range(1, n_inst + 1):
            bg = PDF_ROW_A if i % 2 == 1 else PDF_ROW_B
            row_styles.append(("BACKGROUND", (0, i), (-1, i), bg))
        tbl.setStyle(TableStyle(row_styles))
        story.append(tbl)

        if crash_files or hang_files:
            story.append(Paragraph("CRASH &amp; HANG FILES", sty("cs", size=12, color=PDF_RED, bold=True, space_before=14, space_after=4)))
            crash_lines = []
            if crash_files:
                crash_lines.append(f"── CRASHES ({len(crash_files)} shown) ──")
                crash_lines += [f"  {f}" for f in crash_files]
            if hang_files:
                crash_lines.append(f"── HANGS ({len(hang_files)} shown) ──")
                crash_lines += [f"  {f}" for f in hang_files]
            crash_tbl = Table(
                [[Paragraph("<br/>".join(str(l) for l in crash_lines), crash_sty)]],
                colWidths=[W - MARGIN * 2]
            )
            crash_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor(BG_CRASH_BOX)),
                ("TOPPADDING",    (0,0), (-1,-1), 8),
                ("BOTTOMPADDING", (0,0), (-1,-1), 8),
                ("LEFTPADDING",   (0,0), (-1,-1), 10),
            ]))
            story.append(crash_tbl)

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
            [Paragraph(k, sty("mk", size=9, color=PDF_CYAN, bold=True)),
             Paragraph(v, sty("mv", size=9, color=PDF_TEXT))]
            for k, v in meta_rows
        ]
        meta_tbl = Table(meta_tbl_data, colWidths=[1.3*inch, W - MARGIN*2 - 1.3*inch])
        meta_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor(BG_META_BOX)),
            ("GRID",          (0,0), (-1,-1), 0.3, PDF_BORDER),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ]))
        story.append(meta_tbl)

        doc.build(story, onFirstPage=bg_canvas, onLaterPages=bg_canvas)

    def _render_charts_image(self, merged, instances):
        import io
        import numpy as np
        matplotlib.use("Agg")

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

        CHART_COLORS = [ACCENT2, ACCENT, ACCENT_PURP, ACCENT_WARN, ACCENT_GREEN, ACCENT_HANG]
        bar_colors   = [CHART_COLORS[i % len(CHART_COLORS)] for i in range(n)]

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
        bars = ax_paths.barh(labels, paths_vals, color=bar_colors, edgecolor=BORDER, height=0.6)
        max_val = max(paths_vals) if paths_vals else 1
        for bar, val in zip(bars, paths_vals):
            ax_paths.text(bar.get_width() + max_val * 0.01, bar.get_y() + bar.get_height() / 2,
                          f"{val:,}", va="center", ha="left", color=TEXT_SUBTLE, fontsize=10)
        ax_paths.set_xlabel("Total Paths Discovered", color=TEXT_DIM, fontsize=10)

        style_ax(ax_eps, "Execution Throughput (exec/sec)")
        ax_eps.bar(x, eps_vals, color=bar_colors, edgecolor=BORDER)
        ax_eps.set_xticks(x)
        ax_eps.set_xticklabels(labels, rotation=30, ha="right")
        ax_eps.set_ylabel("exec/sec", color=TEXT_DIM, fontsize=10)

        style_ax(ax_crashes, "Stability (Crashes & Hangs)")
        width = 0.4
        ax_crashes.bar(x - width/2, crash_vals, width, label="Crashes", color=ACCENT_ERR, edgecolor=BORDER)
        ax_crashes.bar(x + width/2, hang_vals,  width, label="Hangs",   color=ACCENT_HANG, edgecolor=BORDER)
        ax_crashes.set_xticks(x)
        ax_crashes.set_xticklabels(labels, rotation=30, ha="right")
        ax_crashes.legend(frameon=False, fontsize=9, labelcolor=TEXT_SUBTLE)
        ax_crashes.set_ylabel("Count", color=TEXT_DIM, fontsize=10)

        style_ax(ax_corpus, "Corpus Growth")
        ax_corpus.bar(x, corpus_vals, color=bar_colors, edgecolor=BORDER)
        ax_corpus.set_xticks(x)
        ax_corpus.set_xticklabels(labels, rotation=30, ha="right")
        ax_corpus.set_ylabel("Inputs", color=TEXT_DIM, fontsize=10)

        style_ax(ax_depth, "Exploration Depth")
        ax_depth.bar(x, depth_vals, color=bar_colors, edgecolor=BORDER)
        ax_depth.set_xticks(x)
        ax_depth.set_xticklabels(labels, rotation=30, ha="right")
        ax_depth.set_ylabel("Call Depth", color=TEXT_DIM, fontsize=10)

        plt.tight_layout()

        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=220, facecolor=BG_ROOT, bbox_inches="tight")
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
        self.configure(fg_color=BG_ROOT)
        frame = ctk.CTkFrame(self, fg_color=BG_FRAME)
        frame.pack(expand=True)
        self._btn(frame, "Generate Report", self.generate_pdf).pack(pady=10)
        self._btn(frame, "Run Again", self.build_config_screen, primary=False).pack(pady=10)

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