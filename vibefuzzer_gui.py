import customtkinter as ctk
from tkinter import filedialog
from tkinter import messagebox
import subprocess
import threading
import time
import os
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

ctk.set_appearance_mode("dark")

# VALID_PROTOCOLS = ["", "FTP", "HTTP", "SMTP", "RTSP", "DNS", "SIP"]
VALID_PROTOCOLS = ["HTTP"]

class VibeFuzzerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Vibe Fuzzer")
        self.geometry("900x700")

        self.monitoring = False
        self.coverage_data = []

        self.build_config_screen()

    # =========================================================
    # CONFIG SCREEN
    # =========================================================
    def build_config_screen(self):
        self.clear()

        frame = ctk.CTkFrame(self)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Vibe Fuzzer", font=("Arial", 24)).pack(pady=10)

        # Target binary
        self.target_binary_path = self.clickable_file_entry(
            frame, "Select Target Binary", is_file=True
        )

        self.target_args = self.entry(frame, "Enter Target Args")

        # 🔥 Command preview
        ctk.CTkLabel(frame, text="Command to be Fuzzed").pack(pady=(10, 0))

        self.preview_box = ctk.CTkTextbox(frame, height=50)
        self.preview_box.pack(fill="x", padx=10, pady=5)

        self.input_dir = self.clickable_file_entry(
            frame, "Select Input Directory (default ./input)"
        )

        self.output_dir = self.clickable_file_entry(
            frame, "Select Output Directory (default ./output)"
        )

        self.protocol = ctk.CTkComboBox(frame, values=VALID_PROTOCOLS)
        self.protocol.pack(pady=5)

        # self.afl_args = self.entry(frame, "AFL Args")

        # LLM toggle
        self.no_llm = ctk.BooleanVar()
        self.no_llm_checkbox = ctk.CTkCheckBox(
            frame,
            text="Disable LLM Seeds",
            variable=self.no_llm,
            command=self.toggle_num_seeds
        )
        self.no_llm_checkbox.pack()

        # Num seeds (wrapped so we can hide/show)
        self.num_seeds_frame = ctk.CTkFrame(frame)
        self.num_seeds_frame.pack(fill="x", pady=5)

        self.num_seeds = ctk.CTkEntry(
            self.num_seeds_frame,
            placeholder_text="Num Seeds"
        )
        self.num_seeds.pack(fill="x")

        # Bind updates
        self.target_binary_path.bind("<KeyRelease>", self.update_preview)
        self.target_args.bind("<KeyRelease>", self.update_preview)

        # Also update after file picker click
        self.target_binary_path.bind("<FocusOut>", self.update_preview)

        self.start_button = ctk.CTkButton(frame, text="Start", command=self.start)
        self.start_button.pack(pady=20)

        self.update_preview()
    
    def clickable_file_entry(self, parent, placeholder, is_file=False):
        entry = ctk.CTkEntry(parent, placeholder_text=placeholder)
        entry.pack(pady=5, fill="x")

        def open_picker(event=None):
            if is_file:
                path = filedialog.askopenfilename()
            else:
                path = filedialog.askdirectory()

            if path:
                entry.delete(0, "end")
                entry.insert(0, path)

        entry.bind("<Button-1>", open_picker)

        return entry

    def entry(self, parent, placeholder):
        e = ctk.CTkEntry(parent, placeholder_text=placeholder)
        e.pack(pady=5, fill="x")
        return e

    def toggle_num_seeds(self):
        if self.no_llm.get():
            self.num_seeds_frame.pack_forget()
        else:
            # Repack ABOVE the Start button
            self.num_seeds_frame.pack(before=self.start_button, fill="x", pady=5)

    def update_preview(self, event=None):
        binary = self.target_binary_path.get()
        args = self.target_args.get()

        display = binary if binary else ""
        display += " " + args if args else ""

        self.preview_box.delete("1.0", "end")
        self.preview_box.insert("end", display)

    def is_dir_empty(self, path):
        return not any(Path(path).iterdir())    

    # =========================================================
    # START
    # =========================================================
    def start(self):
        input_dir = self.input_dir.get() or "./input"
        output_dir = self.output_dir.get() or "./output"

        os.makedirs(input_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)

        self.final_output_dir = output_dir  # Store for final screen

        # ❌ Block execution if empty       
        directory = Path(input_dir)
        if self.no_llm.get() and self.is_dir_empty(directory):
            messagebox.showerror("Error", "Input directory must contain at least one seed when LLM seeds are disabled.")
            return
            
        binary_path = self.target_binary_path.get()

        if not binary_path or not os.path.isfile(binary_path):
            return

        target_dir = str(Path(binary_path).parent)
        binary_name = Path(binary_path).name

        cmd = ["python3", "afl++wrapper.py",
            target_dir, binary_name]

        if self.protocol.get():
            cmd += ["--protocol", self.protocol.get()]

        cmd += ["--input", input_dir]
        cmd += ["--output", output_dir]

        if self.target_args.get():
            cmd += ["--target-args"] + self.target_args.get().split()

        # if self.afl_args.get():
        #     cmd += ["--afl-args"] + self.afl_args.get().split()

        if self.no_llm.get():
            cmd += ["--no-llm-seeds"]

        if self.num_seeds.get():
            cmd += ["--num-seeds", self.num_seeds.get()]

        # ✅ ALWAYS enable debug UI
        cmd += ["--debug-ui"]

        print(f"Running command: {' '.join(cmd)}")
        subprocess.Popen(cmd)
        # subprocess.Popen(["tmux", "new-session", "-s", "vibefuzzer", " ".join(cmd)])

        # Hide the GUI window and start monitoring the tmux session
        self.withdraw()
        threading.Thread(target=self.monitor_tmux_session, daemon=True).start()

    def monitor_tmux_session(self):
        """Monitor the tmux session and show the final coverage screen when it ends."""
        while True:
            result = subprocess.run(["tmux", "has-session", "-t", "vibefuzzer"], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                # Session no longer exists, show the final coverage screen
                self.after(0, self.build_final_coverage_screen)
                break
            time.sleep(1)  # Check every second

    def build_final_coverage_screen(self):
        """Build a screen showing final coverage data."""
        self.clear()

        frame = ctk.CTkFrame(self)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Final Coverage Report", font=("Arial", 24)).pack(pady=10)

        # Read stats from output directory
        stats_text = self.get_final_stats()
        
        stats_box = ctk.CTkTextbox(frame, wrap="word")
        stats_box.pack(fill="both", expand=True, padx=10, pady=10)
        stats_box.insert("end", stats_text)
        stats_box.configure(state="disabled")

        # Button to return to config
        button_frame = ctk.CTkFrame(frame)
        button_frame.pack(pady=10)
        ctk.CTkButton(button_frame, text="Download PDF", command=self.download_pdf).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Back to Config", command=self.build_config_screen).pack(side="left", padx=5)

    def get_final_stats(self):
        """Parse and return final stats from AFL++ output."""
        sync_dir = Path(self.final_output_dir) / "sync"
        if not sync_dir.exists():
            return "No sync directory found. Fuzzing may not have completed."

        stats = []
        for fuzzer_dir in sync_dir.iterdir():
            if fuzzer_dir.is_dir() and fuzzer_dir.name.startswith("fuzzer"):
                stats_file = fuzzer_dir / "fuzzer_stats"
                if stats_file.exists():
                    stats.append(f"=== {fuzzer_dir.name.upper()} STATS ===")
                    try:
                        with open(stats_file, 'r') as f:
                            content = f.read()
                            # Extract key lines
                            lines = content.split('\n')
                            for line in lines:
                                if any(key in line for key in ['paths_total', 'unique_crashes', 'unique_hangs', 'execs_done', 'cycles_done']):
                                    stats.append(line.strip())
                    except Exception as e:
                        stats.append(f"Error reading stats: {e}")
                    stats.append("")

        if not stats:
            return "No stats files found."

        return '\n'.join(stats)

    def download_pdf(self):
        """Generate and save a PDF of the final stats."""
        stats_text = self.get_final_stats()
        if not stats_text or stats_text.startswith("No"):
            messagebox.showerror("Error", "No stats available to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            title="Save Fuzzing Results PDF"
        )
        if not file_path:
            return

        try:
            c = canvas.Canvas(file_path, pagesize=letter)
            width, height = letter
            y = height - 50  # Start near top

            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, y, "VibeFuzzer Final Coverage Report")
            y -= 30

            c.setFont("Helvetica", 12)
            for line in stats_text.split('\n'):
                if y < 50:  # New page if near bottom
                    c.showPage()
                    y = height - 50
                c.drawString(50, y, line)
                y -= 15

            c.save()
            messagebox.showinfo("Success", f"PDF saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save PDF: {e}")

    # =========================================================
    # MONITOR SCREEN
    # =========================================================
    def build_monitor_screen(self):
        self.clear()

        self.monitoring = True

        main = ctk.CTkFrame(self)
        main.pack(fill="both", expand=True)

        top = ctk.CTkFrame(main)
        top.pack(fill="x")

        self.primary_stats = self.stats_panel(top, "Primary")
        self.secondary_stats = self.stats_panel(top, "Secondary")

        # Graph
        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=main)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        # Crash viewer
        bottom = ctk.CTkFrame(main)
        bottom.pack(fill="x")

        self.crash_list = ctk.CTkTextbox(bottom, height=100)
        self.crash_list.pack(fill="x")

        ctk.CTkButton(main, text="Stop", fg_color="red",
                      command=self.stop).pack(pady=10)

        threading.Thread(target=self.monitor_loop, daemon=True).start()

    def stats_panel(self, parent, title):
        frame = ctk.CTkFrame(parent)
        frame.pack(side="left", expand=True, fill="both", padx=10, pady=10)

        ctk.CTkLabel(frame, text=title).pack()

        stats = {}
        for k in ["execs", "execs_per_sec", "crashes", "hangs", "paths"]:
            var = ctk.StringVar(value="0")
            ctk.CTkLabel(frame, textvariable=var).pack()
            stats[k] = var

        return stats

    # =========================================================
    # MONITOR LOOP
    # =========================================================
    def monitor_loop(self):
        while self.monitoring:
            try:
                out = self.output_dir.get()

                self.update_instance(out, "primary", self.primary_stats)
                self.update_instance(out, "secondary", self.secondary_stats)

                self.update_graph(out)
                self.update_crashes(out)

            except Exception:
                pass

            time.sleep(2)

    def parse_stats(self, path):
        d = {}
        with open(path) as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    d[k.strip()] = v.strip()
        return d

    def update_instance(self, base, name, stats):
        path = Path(base) / name / "fuzzer_stats"
        if not path.exists():
            return

        s = self.parse_stats(path)

        stats["execs"].set(f"Execs: {s.get('execs_done', 0)}")
        stats["execs_per_sec"].set(f"Exec/s: {s.get('execs_per_sec', 0)}")
        stats["crashes"].set(f"Crashes: {s.get('unique_crashes', 0)}")
        stats["hangs"].set(f"Hangs: {s.get('unique_hangs', 0)}")
        stats["paths"].set(f"Paths: {s.get('paths_total', 0)}")

    # =========================================================
    # GRAPH
    # =========================================================
    def update_graph(self, base):
        stats_file = Path(base) / "primary" / "fuzzer_stats"
        if not stats_file.exists():
            return

        s = self.parse_stats(stats_file)
        paths = int(s.get("paths_total", 0))

        self.coverage_data.append(paths)

        self.ax.clear()
        self.ax.plot(self.coverage_data)
        self.ax.set_title("Coverage Over Time")

        self.canvas.draw()

    # =========================================================
    # CRASH VIEWER
    # =========================================================
    def update_crashes(self, base):
        crashes = list(Path(base).rglob("crashes/id*"))

        text = "\n".join([str(c) for c in crashes[:10]])

        self.crash_list.delete("1.0", "end")
        self.crash_list.insert("end", text)

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

        ctk.CTkButton(frame, text="Generate Report",
                      command=self.generate_pdf).pack(pady=10)

        ctk.CTkButton(frame, text="Run Again",
                      command=self.build_config_screen).pack(pady=10)

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