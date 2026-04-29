# vibefuzzer_gui.py
# ============================================================================
# Main application — config screen, start logic, tmux monitoring.
# All widget helpers come from WidgetMixin; all results rendering from
# ResultsMixin.  Stats parsing and PDF generation live in report_gen.py.
# ============================================================================

import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from palette import BG_ROOT, BG_FRAME, BG_CARD, BG_HEADER, ACCENT2, VALID_PROTOCOLS, HELP_SECTIONS
from gui_widgets import WidgetMixin
from gui_results import ResultsMixin

ctk.set_appearance_mode("dark")


class VibeFuzzerGUI(WidgetMixin, ResultsMixin, ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Vibe Fuzzer")
        self.geometry("900x750")
        self.configure(fg_color=BG_ROOT)

        self.monitoring = False

        # Boolean toggles
        self.use_target_binary  = ctk.BooleanVar()
        self.use_custom_build   = ctk.BooleanVar()
        self.use_configure_args = ctk.BooleanVar()
        self.use_make_args      = ctk.BooleanVar()
        self.use_target_args    = ctk.BooleanVar()
        self.use_afl_args       = ctk.BooleanVar()
        self.no_llm             = ctk.BooleanVar()

        self.build_config_screen()

    # =========================================================================
    # HELP SCREEN
    # =========================================================================

    def show_help(self):
        self.clear()
        self.geometry("900x750")

        outer = ctk.CTkFrame(self, fg_color=BG_ROOT)
        outer.pack(fill="both", expand=True)

        bar = self._title_bar(outer, "VibeFuzzer — Help")
        self._btn(bar, "← Back", self.build_config_screen, width=90, primary=False).pack(
            side="right", padx=15, pady=10
        )

        scroll = ctk.CTkScrollableFrame(outer, fg_color=BG_ROOT)
        scroll.pack(fill="both", expand=True)

        for section_title, section_body in HELP_SECTIONS:
            header_frame = ctk.CTkFrame(scroll, fg_color=BG_HEADER, corner_radius=6)
            header_frame.pack(fill="x", padx=16, pady=(14, 0))
            ctk.CTkLabel(
                header_frame, text=section_title.upper(),
                font=("Courier Bold", 11), text_color=ACCENT2, anchor="w",
            ).pack(padx=14, pady=6, anchor="w")

            body_frame = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=0)
            body_frame.pack(fill="x", padx=16, pady=(0, 2))
            ctk.CTkLabel(
                body_frame, text=section_body,
                font=("Courier", 11), text_color="#64748b",
                anchor="w", justify="left", wraplength=820,
            ).pack(padx=14, pady=10, anchor="w")

        self._btn(scroll, "← Back to Configuration", self.build_config_screen,
                  width=240, primary=False).pack(pady=20)

    # =========================================================================
    # CONFIG SCREEN
    # =========================================================================

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
            font=("Courier Bold", 24), text_color=ACCENT2,
        ).pack(side="left", padx=16, pady=10)
        self._btn(title_row, "?", self.show_help, width=32, primary=False).pack(
            side="right", padx=10, pady=8
        )

        # Core path entries
        self.target_source_dir = self.clickable_file_entry(frame, "Select Target Source Folder")

        # Target binary (checkbox-revealed)
        self.binary_frame = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=6)
        self.binary_frame.pack(fill="x", pady=5)
        self.binary_checkbox = self._checkbox(
            self.binary_frame, "Target Binary",
            self.use_target_binary, self.toggle_target_binary,
        )
        self.binary_checkbox.pack(side="left", padx=(10, 10), pady=8, anchor="w")
        self.target_binary_path = self._entry(self.binary_frame, "Select Target Binary Location")
        self.target_binary_path.pack(side="left", fill="x", expand=True)
        self.binary_browse_btn = self._btn(
            self.binary_frame, "Browse",
            lambda: self._browse_path(self.target_binary_path, is_file=True),
            width=80,
        )
        self.binary_browse_btn.pack(side="right", padx=8, pady=6)
        # start hidden
        self.target_binary_path.pack_forget()
        self.binary_browse_btn.pack_forget()

        # Target args
        _, _, self.target_args_input = self.checkbox_entry_row(
            frame, "Target Args", self.use_target_args,
            self.toggle_target_args, "Target Args",
        )

        self.input_dir  = self.clickable_file_entry(frame, "Select Input Directory (default ./input)")
        self.output_dir = self.clickable_file_entry(frame, "Select Output Directory (default ./output)")

        # Protocol
        protocol_frame = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=6)
        protocol_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(
            protocol_frame, text="Protocol", width=120, anchor="w",
            text_color="#cbd5e1", font=("Courier", 12),
        ).pack(side="left", padx=(10, 10), pady=8)
        self.protocol = ctk.CTkComboBox(
            protocol_frame, values=VALID_PROTOCOLS,
            fg_color=BG_CARD, border_color="#1e3a5f",
            button_color="#3b82f6", button_hover_color="#2563eb",
            text_color="#e2e8f0", dropdown_fg_color=BG_HEADER,
            dropdown_text_color="#e2e8f0", font=("Courier", 12),
        )
        self.protocol.pack(side="left", fill="x", expand=True, padx=(0, 10), pady=6)

        # Optional checkbox rows
        _, _, self.custom_build    = self.checkbox_entry_row(frame, "Custom Build Command", self.use_custom_build,   self.toggle_custom_build,   "Custom Build Command")
        _, _, self.configure_args  = self.checkbox_entry_row(frame, "Configure Args",       self.use_configure_args, self.toggle_configure_args,  "Configure Args")
        _, _, self.make_args       = self.checkbox_entry_row(frame, "Make Args",             self.use_make_args,      self.toggle_make_args,       "Make Args")
        _, _, self.afl_args_input  = self.checkbox_entry_row(frame, "AFL Args",              self.use_afl_args,       self.toggle_afl_args,        "AFL Args")

        # LLM seeds
        self.llm_frame = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=6)
        self.llm_frame.pack(fill="x", pady=5)
        self._checkbox(
            self.llm_frame, "Disable LLM Seeds",
            self.no_llm, self.toggle_num_seeds,
        ).pack(side="left", padx=(10, 10), pady=8, anchor="w")
        self.num_seeds = self._entry(self.llm_frame, "Num Seeds (default 10)")
        self.num_seeds.pack(side="left", fill="x", expand=True)

        self._btn(frame, "Start", self.start, width=200).pack(pady=20)

    # ── Toggle helpers ────────────────────────────────────────────────────────

    def _browse_path(self, entry_widget, is_file=False):
        path = filedialog.askopenfilename() if is_file else filedialog.askdirectory()
        if path:
            entry_widget.delete(0, "end")
            entry_widget.insert(0, path)

    def toggle_target_binary(self):
        if self.use_target_binary.get():
            self.target_binary_path.pack(side="left", fill="x", expand=True)
            self.binary_browse_btn.pack(side="right", padx=8, pady=6)
        else:
            self.target_binary_path.pack_forget()
            self.binary_browse_btn.pack_forget()

    def _toggle_entry(self, flag_var, entry_widget):
        if flag_var.get():
            entry_widget.pack(side="left", fill="x", expand=True)
        else:
            entry_widget.pack_forget()

    def toggle_num_seeds(self):
        if self.no_llm.get():
            self.num_seeds.pack_forget()
        else:
            self.num_seeds.pack(side="left", fill="x", expand=True)

    def toggle_custom_build(self):    self._toggle_entry(self.use_custom_build,   self.custom_build)
    def toggle_configure_args(self):  self._toggle_entry(self.use_configure_args, self.configure_args)
    def toggle_make_args(self):       self._toggle_entry(self.use_make_args,       self.make_args)
    def toggle_target_args(self):     self._toggle_entry(self.use_target_args,     self.target_args_input)
    def toggle_afl_args(self):        self._toggle_entry(self.use_afl_args,        self.afl_args_input)

    # =========================================================================
    # VALIDATION
    # =========================================================================

    def _is_dir_empty(self, path):
        return not any(Path(path).iterdir())

    def _validate_fields(self):
        optional_fields = [
            (self.use_custom_build,   self.custom_build,   "Custom Build Command"),
            (self.use_configure_args, self.configure_args, "Configure Args"),
            (self.use_make_args,      self.make_args,      "Make Args"),
            (self.use_target_args,    self.target_args_input, "Target Args"),
            (self.use_afl_args,       self.afl_args_input,    "AFL Args"),
        ]
        for toggle, entry, name in optional_fields:
            if toggle.get() and not entry.get().strip():
                messagebox.showerror("Error", f"{name} is checked but no value was provided.")
                return False
        return True

    # =========================================================================
    # START
    # =========================================================================

    def start(self):
        if not self._validate_fields():
            return

        target_dir = self.target_source_dir.get()
        if not target_dir or not os.path.isdir(target_dir):
            messagebox.showerror("Error", "Please provide a valid target source directory.")
            return

        for label, path in [("input", self.input_dir.get()), ("output", self.output_dir.get())]:
            if path and not os.path.isdir(path):
                messagebox.showerror("Error", f"Invalid {label} directory.")
                return

        input_dir  = self.input_dir.get()  or "./input"
        output_dir = self.output_dir.get() or "./output"
        os.makedirs(input_dir,  exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)
        self.final_output_dir = output_dir

        if self.no_llm.get() and self._is_dir_empty(Path(input_dir)):
            messagebox.showerror(
                "Error",
                "Input directory must contain at least one seed when LLM seeds are disabled.",
            )
            return

        # Build command
        binary_path = self.target_binary_path.get().strip() if self.use_target_binary.get() else None
        if self.use_target_binary.get() and not binary_path:
            messagebox.showerror("Error", "Target Binary is enabled but no path was provided.")
            return

        cmd = ["python3", "vibefuzzer.py", target_dir]
        if binary_path:
            cmd += ["--binary", binary_path]
        if self.protocol.get():
            cmd += ["--protocol", self.protocol.get()]
        if self.use_custom_build.get()   and self.custom_build.get():
            cmd += ["--custom-build", self.custom_build.get()]
        if self.use_configure_args.get() and self.configure_args.get():
            cmd += ["--configure-args", self.configure_args.get()]
        if self.use_make_args.get()      and self.make_args.get():
            cmd += ["--make-args", self.make_args.get()]
        cmd += ["--input", input_dir, "--output", output_dir]
        if self.use_afl_args.get()       and self.afl_args_input.get():
            cmd += ["--afl-args"] + self.afl_args_input.get().split()
        cmd += ["--debug-ui"]
        if self.no_llm.get():
            cmd += ["--no-llm-seeds"]
        if self.num_seeds.get():
            cmd += ["--num-seeds", self.num_seeds.get() or "10"]
        if self.use_target_args.get()    and self.target_args_input.get():
            cmd += ["--target-args"] + self.target_args_input.get().split()

        print(f"Running command: {' '.join(cmd)}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line, end="")
            if "[*] Fuzzers are alive in tmux. Wrapper exiting." in line:
                break

        print("[*] Launching Tmux UI...")
        self._launch_terminal()

    def _launch_terminal(self):
        attach_cmd = "tmux attach-session -t vibefuzzer; tmux kill-session -t vibefuzzer 2>/dev/null"
        wsl_distro = os.environ.get("WSL_DISTRO_NAME")

        if wsl_distro:
            if shutil.which("wt.exe"):
                term_cmd = ["wt.exe", "new-tab", "wsl.exe", "-d", wsl_distro, "--", "bash", "-c", attach_cmd]
            else:
                term_cmd = ["cmd.exe", "/c", "start", "wsl.exe", "-d", wsl_distro, "--", "bash", "-c", attach_cmd]
        else:
            tp = os.environ.get("TERM_PROGRAM", "")
            if tp == "iTerm.app":
                term_cmd = ["osascript", "-e", f'tell app "iTerm" to create window with default profile command "{attach_cmd}"']
            elif tp == "Apple_Terminal":
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
        threading.Thread(target=self._monitor_tmux_session, daemon=True).start()

    # =========================================================================
    # TMUX MONITORING
    # =========================================================================

    def _monitor_tmux_session(self):
        while True:
            result = subprocess.run(
                ["tmux", "has-session", "-t", "vibefuzzer"],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                print("[*] Tmux session has ended. Showing results...")
                self.after(0, self.show_results)
                break
            time.sleep(1)

    def show_results(self):
        self.deiconify()
        self.build_final_coverage_screen()

    # =========================================================================
    # UTILITIES
    # =========================================================================

    def clear(self):
        for w in self.winfo_children():
            w.destroy()


if __name__ == "__main__":
    app = VibeFuzzerGUI()
    app.mainloop()
