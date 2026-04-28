# vibefuzzer.py
# ============================================================================
# IMPORTS 
# ============================================================================
import time
import shutil
import sys
import os
import subprocess
import argparse
import traceback

import tmux_ui
import seed_gen

from pathlib import Path
from typing import Optional, Union, Tuple

# ============================================================================
# MONOREPO STRUCTURE CONSTANTS
# ============================================================================

# SCRIPT_DIR is the VibeFuzzer/ directory where this python file lives.
SCRIPT_DIR   = Path(__file__).parent.resolve()

# All external dependencies are built natively inside the repo by setup.sh
AFL_PATH     = SCRIPT_DIR / "AFLplusplus"
LIBDESOCK_SO = SCRIPT_DIR / "libdesock" / "build" / "libdesock.so"

# The Custom LLM Mutator
MUTATOR_SO   = SCRIPT_DIR / "mutator" / "libllmmutator.so" 

# Ollama API Configurations
OLLAMA_BASE_URL = 'http://localhost:11434'
OLLAMA_MODEL    = 'afl-mutator'

# TODO: add more protocols as needed
# valid_protocols = ['FTP', 'HTTP', 'SMTP', 'RTSP', 'DNS', 'SIP']
valid_protocols = ['HTTP']

# ============================================================================
# PREFLIGHT CHECKS
# ============================================================================
def preflight_checks() -> None:
    """
    Verifies that all monorepo dependencies exist before attempting to fuzz.
    Raises SystemExit with helpful messages if anything critical is missing.
    """
    errors = []
 
    # Check for AFL++, libdesock, the mutator, and Ollama model availability.
    if not AFL_PATH.exists():
        errors.append(f"  AFL++ not found at:      {AFL_PATH}")
    if not LIBDESOCK_SO.exists():
        errors.append(f"  libdesock not found at:  {LIBDESOCK_SO}")
    if not MUTATOR_SO.exists():
        errors.append(f"  LLM mutator not found at: {MUTATOR_SO}")

    # Check if Ollama is installed and the model is available by running 'ollama list'
    try:
        ollama_check = subprocess.run(["ollama", "list"], capture_output=True, text=True, check=True)
        if "afl-mutator" not in ollama_check.stdout:
            errors.append("  Ollama model 'afl-mutator' not found.")
    except FileNotFoundError:
        errors.append("  Ollama is not installed or not in PATH.")
    except subprocess.CalledProcessError:
        errors.append("  Ollama daemon is not responding.")
 
    # If any critical dependencies are missing, print all errors and exit.
    if errors:
        print("[!] Monorepo dependencies missing. Did you run setup.sh?")
        for e in errors:
            print(e)
        sys.exit(1)
    
    # All checks passed
    print("[*] Preflight checks passed.")
    print(f"    AFL++:     {AFL_PATH}")
    print(f"    libdesock: {LIBDESOCK_SO}")
    print(f"    Ollama:    reachable at {OLLAMA_BASE_URL} with model '{OLLAMA_MODEL}'")
    print(f"    mutator:   {MUTATOR_SO}")
    print()

# ============================================================================
# ENVIRONMENT SETUP (AFL++)
# ============================================================================
def setup_aflpp_env() -> dict:
    """
    Does NOT mutate os.environ globally — env is passed directly to subprocess.Popen so the parent process stays clean.
    """
    print("[*] Configuring base AFL++ environment variables...")
 
    # Set up environment variables
    env = os.environ.copy()
    env.update({
        "CC":                                    str(AFL_PATH / "afl-clang-fast"),
        "CXX":                                   str(AFL_PATH / "afl-clang-fast++"),
        "AFL_PATH":                              str(AFL_PATH),
        "AFL_PRELOAD":                           str(LIBDESOCK_SO),
        "AFL_TMPDIR":                            "/tmp",
        "AFL_SKIP_CPUFREQ":                      "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        "ASAN_OPTIONS":                          "abort_on_error=1:detect_leaks=0:symbolize=0",
    })
 
    return env
 
# ============================================================================
# BUILD TARGET
# ============================================================================
def build_target(
    source_dir: str,
    binary_name: Optional[str] = None,
    configure_args: Optional[str] = None,
    make_args: Optional[str] = None,
    custom_build_cmd: Optional[str] = None,
) -> Path:
    
    """
    Instruments and builds the fuzz target with afl-clang-fast. 
    Auto-detects CMake, Meson, Autotools, or standard Make.
    """

    # First check if the binary already exists and is instrumented — if so, we can skip the build entirely.
    source_path = Path(source_dir).resolve()
    if not source_path.exists():
        raise FileNotFoundError(f"Target source not found: {source_path}")

    # Common locations to check for the built binary
    search_paths = [
        source_path / binary_name,
        source_path / "objs"  / binary_name,
        source_path / "src"   / binary_name,
        source_path / "bin"   / binary_name,
        source_path / "build" / binary_name,
    ] if binary_name else []

    # Return early if already instrumented
    for path in search_paths:
        if path.is_file() and _verify_instrumentation(path, fatal=False):
            print(f"[*] Existing instrumented binary found: {path}")
            return path.resolve()

    print(f"[*] Building target in: {source_path}")
    os.chdir(source_path)

    # Format the arguments once to save space
    cfg_args = f" {configure_args}" if configure_args else ""
    bld_args = f" {make_args}" if make_args else ""
    stale_clean = "make clean" if any(p.is_file() for p in search_paths) else None
    
    # Standardize our compiler injection
    compilers = "CC=afl-clang-fast CXX=afl-clang-fast++"
    cmds = []

    # Map the detected build system to its setup and build commands
    if custom_build_cmd:
        print("[*] Using custom build command.")
        cmds = [f"{compilers} {custom_build_cmd}"]
    elif Path("CMakeLists.txt").exists():
        print("[*] Detected CMake build system.")
        cmds = [f"{compilers} cmake -B build{cfg_args}", f"cmake --build build{bld_args}"]
    elif Path("meson.build").exists():
        print("[*] Detected Meson build system.")
        cmds = [f"{compilers} meson setup build{cfg_args}", f"ninja -C build{bld_args}"]
    elif Path("./configure").exists():
        print("[*] Detected Autotools ./configure script.")
        cmds = [f"{compilers} ./configure{cfg_args}", stale_clean, f"make{bld_args}"]
    else:
        print("[*] Falling back to standard Make.")
        cmds = [stale_clean, f"make{bld_args}"]

    # Execute the queued commands
    for cmd in cmds:
        if cmd:  # Ignores 'None' values like stale_clean when unneeded
            subprocess.run(cmd, shell=True, check=True)

    # Verify build success
    # After build: check known paths first
    for path in search_paths:
        if path.is_file() and _verify_instrumentation(path, fatal=False):
            print(f"[*] Binary ready: {path.resolve()}")
            return path.resolve()

    # Fall back to auto-scan if --binary wasn't specified (or wasn't found)
    return _auto_detect_binary(source_path)

def _verify_instrumentation(binary_path: Path, fatal: bool = True) -> bool:
    """
    Checks for AFL++ __AFL_SHM_ID instrumentation marker via strings.
    """
    # This is a heuristic check — it looks for the presence of the __AFL_SHM_ID symbol in the binary
    # which is a strong indicator that AFL++ instrumentation is present.
    result = subprocess.run(
        ["strings", str(binary_path)], capture_output=True, text=True
    )

    # If the symbol is found, we assume instrumentation is correct. 
    # If not, we can either raise an error (if fatal=True) or just return False.
    if "__AFL_SHM_ID" in result.stdout:
        print("[*] AFL++ instrumentation verified.")
        return True
    if fatal:
        raise RuntimeError(
            f"Binary not instrumented: {binary_path}\n"
            "Rebuild with CC=afl-clang-fast CXX=afl-clang-fast++"
        )
    return False

def _auto_detect_binary(source_path: Path) -> Path:
    """
    Scans source_path for instrumented ELF executables after a build.
    Succeeds if exactly one is found, otherwise raises with helpful output.
    """
    candidates = [
        p for p in source_path.rglob("*")
        if p.is_file()
        and os.access(p, os.X_OK)
        and _verify_instrumentation(p, fatal=False)
    ]

    if len(candidates) == 1:
        print(f"[*] Auto-detected binary: {candidates[0]}")
        return candidates[0]

    if len(candidates) == 0:
        raise FileNotFoundError(
            "No instrumented binaries found after build.\n"
            "Try specifying it explicitly with --binary <relative/path>"
        )

    # Multiple candidates — list them and bail
    listing = "\n".join(f"  {p.relative_to(source_path)}" for p in candidates)
    raise RuntimeError(
        f"Multiple instrumented binaries found — specify one with --binary:\n{listing}"
    )


# ============================================================================
# AFL++ 
# ============================================================================
def build_aflpp_cmd(
    binary: str,
    input_dir: str,
    output_dir: str,
    env: dict,
    instance_name: str = "primary",
    mutator_so: Optional[str] = None,
    extra_afl_args: Optional[list] = None,
    target_args: Optional[list] = None,
    debug_ui: bool = False, 
) -> Tuple[list, dict]:
    """
    Launches an afl-fuzz instance. 
    Can act as the primary node or a secondary sync node depending on instance_name.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    run_env = env.copy()

    # ISOLATED RAM DISK: Prevent instance collisions
    instance_tmp_dir = f"/tmp/afl_tmp_{instance_name}"
    if os.path.exists(instance_tmp_dir):
        shutil.rmtree(instance_tmp_dir, ignore_errors=True)
    os.makedirs(instance_tmp_dir, exist_ok=True)
    run_env["AFL_TMPDIR"] = instance_tmp_dir

    # For the secondary instance, we inject the custom mutator and related configurations via environment variables.
    if mutator_so:
        mutator_resolved = Path(mutator_so).resolve()

        # 1. Load the custom library
        run_env["AFL_CUSTOM_MUTATOR_LIBRARY"] = str(mutator_resolved)
        
        # 2. Force this node to ONLY use the custom LLM mutator, and skip trimming
        run_env["AFL_CUSTOM_MUTATOR_ONLY"]    = "1"
        run_env["AFL_DISABLE_TRIM"]           = "1"
        
        # 3. Pass API configurations down to the C code (ollama.c)
        run_env["OLLAMA_URL"]   = OLLAMA_BASE_URL
        run_env["OLLAMA_MODEL"] = "afl-mutator"

        # 4. Disable AFL++'s built-in UI 
        # Else we want to see it when doing tmux debugging
        if not debug_ui:
            run_env["AFL_NO_UI"] = "1"
        
        print(f"[*] Injecting mutator env for {instance_name}: {mutator_resolved.name}")

    # Build AFL++ command
    aflpp_cmd = [str(AFL_PATH / "afl-fuzz")]

    # build primary vs secondary command based on instance_name
    is_primary = (instance_name == "primary")
    aflpp_cmd  = [str(AFL_PATH / "afl-fuzz")]
    aflpp_cmd += ["-M" if is_primary else "-S", instance_name]
    aflpp_cmd += ["-i", input_dir]
    aflpp_cmd += ["-o", output_dir, "-m", "none", "-t", "5000+"]

    # Add AFL++ args BEFORE the -- separator
    if extra_afl_args:
        aflpp_cmd += extra_afl_args

    # The target binary and its arguments go after the -- separator. 
    # For network services, we typically just specify the binary and let libdesock handle the I/O redirection.
    aflpp_cmd += ["--", binary]

    # Then binary and target args AFTER --
    if target_args:
        aflpp_cmd += target_args

    # Pretty print the AFL++ command
    print(f"\n{'─' * 60}")
    print(f"  AFL++ {instance_name.upper()} INSTANCE")
    print(f"{'─' * 60}")
    print(f"  {'Binary':<18} {binary}")
    print(f"  {'Input':<18} {input_dir}")
    print(f"  {'Output':<18} {output_dir}")
    print(f"  {'Mutator':<18} {Path(mutator_so).name if mutator_so else 'AFL++ built-in (havoc/splice)'}")
    print(f"  {'Mode':<18} {'tmux (debug)' if debug_ui else 'terminal' if instance_name == 'primary' else 'silent → log'}")
    print(f"{'─' * 60}")
    print(f"  CMD: {' '.join(aflpp_cmd)}")
    print(f"{'─' * 60}\n")

    # we just return the command and environment.
    return aflpp_cmd, run_env


# ============================================================================
# PDF REPORT GENERATION (standalone, mirrors the GUI export)
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
    Returns (merged_dict, [per_instance_dicts]) — same shape as the GUI method.
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
        "start_time":     instances[0].get("start_time",  ""),
        "last_update":    instances[0].get("last_update", ""),
        "afl_banner":     instances[0].get("afl_banner",  ""),
        "command_line":   instances[0].get("command_line",""),
        "target_mode":    instances[0].get("target_mode", ""),
        "stability":      instances[0].get("stability",   ""),
        "bitmap_cvg":     instances[0].get("bitmap_cvg",  ""),
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


def _render_charts_image(merged: dict, instances: list):
    """
    Render the five-panel performance chart to an in-memory PNG buffer.
    Uses the same dark-blue palette as the GUI.
    """
    import io
    import numpy as np
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # ── palette (mirrors vibefuzzer_gui.py) ───────────────────────────────
    BG_ROOT  = "#06090f"
    BG_CARD  = "#0f1829"
    BORDER   = "#1e3a5f"
    ACCENT2  = "#60a5fa"
    ACCENT   = "#3b82f6"
    A_PURP   = "#a78bfa"
    A_WARN   = "#f59e0b"
    A_GREEN  = "#22d3ee"
    A_HANG   = "#f97316"
    A_ERR    = "#ef4444"
    TEXT_BR  = "#e2e8f0"
    TEXT_DIM = "#64748b"
    TEXT_SUB = "#94a3b8"

    CHART_COLORS = [ACCENT2, ACCENT, A_PURP, A_WARN, A_GREEN, A_HANG]

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

    fig = plt.figure(figsize=(16, 10), facecolor=BG_ROOT)
    gs  = fig.add_gridspec(3, 2, height_ratios=[1.2, 1, 1], hspace=0.55, wspace=0.3)

    ax_paths   = fig.add_subplot(gs[0, :])
    ax_eps     = fig.add_subplot(gs[1, 0])
    ax_crashes = fig.add_subplot(gs[1, 1])
    ax_corpus  = fig.add_subplot(gs[2, 0])
    ax_depth   = fig.add_subplot(gs[2, 1])

    def style_ax(ax, title):
        ax.set_facecolor(BG_CARD)
        ax.set_title(title, color=TEXT_BR,  fontsize=12, pad=10, weight="bold")
        ax.tick_params(colors=TEXT_SUB, labelsize=9)
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
            f"{val:,}", va="center", ha="left", color=TEXT_SUB, fontsize=10,
        )
    ax_paths.set_xlabel("Total Paths Discovered", color=TEXT_DIM, fontsize=10)

    style_ax(ax_eps, "Execution Throughput (exec/sec)")
    ax_eps.bar(x, eps_vals, color=bar_colors, edgecolor=BORDER)
    ax_eps.set_xticks(x); ax_eps.set_xticklabels(labels, rotation=30, ha="right")
    ax_eps.set_ylabel("exec/sec", color=TEXT_DIM, fontsize=10)

    style_ax(ax_crashes, "Stability (Crashes & Hangs)")
    w = 0.4
    ax_crashes.bar(x - w/2, crash_vals, w, label="Crashes", color=A_ERR,  edgecolor=BORDER)
    ax_crashes.bar(x + w/2, hang_vals,  w, label="Hangs",   color=A_HANG, edgecolor=BORDER)
    ax_crashes.set_xticks(x); ax_crashes.set_xticklabels(labels, rotation=30, ha="right")
    ax_crashes.legend(frameon=False, fontsize=9, labelcolor=TEXT_SUB)
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


def generate_pdf_report(output_dir: str, pdf_path: str) -> None:
    """
    Read fuzzer_stats from output_dir and write a PDF report to pdf_path.
    Identical output to the GUI's Export PDF button.
    """
    import io
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

    # ── palette (mirrors vibefuzzer_gui.py) ───────────────────────────────
    BG_ROOT      = "#06090f"
    BG_CARD      = "#0f1829"
    BG_ROW_A     = "#111d35"
    BG_ROW_B     = "#0e1730"
    BG_HEADER    = "#0d1526"
    BG_TOTALS    = "#13203d"
    BG_CRASH_BOX = "#110d1a"
    BG_META_BOX  = "#0b1120"
    ACCENT2      = "#60a5fa"
    ACCENT       = "#3b82f6"
    A_WARN       = "#f59e0b"
    A_ERR        = "#ef4444"
    A_HANG       = "#f97316"
    A_PURP       = "#a78bfa"
    A_GREEN      = "#22d3ee"
    TEXT_BRIGHT  = "#e2e8f0"
    TEXT_DIM     = "#64748b"
    TEXT_MAIN    = "#cbd5e1"
    BORDER       = "#1e3a5f"

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
    story.append(Paragraph("AFL++ Fuzzing Report",
                            sty("title", size=20, color=C(ACCENT2), bold=True,
                                space_before=2, space_after=2)))
    story.append(Paragraph(
        f"{len(instances)} instance(s) combined  ·  Output: {output_dir}",
        sty("subtitle", size=10, color=C(TEXT_DIM), space_after=8),
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=C(ACCENT2), spaceAfter=10))

    # ── Summary cards ─────────────────────────────────────────────────────
    story.append(Paragraph("SUMMARY",
                            sty("section", size=12, color=C(ACCENT2), bold=True,
                                space_before=14, space_after=4)))

    cards = [
        ("EXECUTIONS",     f"{merged['execs_done']:,}",        C(ACCENT2)),
        ("EXEC / SEC",     f"{merged['execs_per_sec']:,.1f}",  C(ACCENT)),
        ("PATHS FOUND",    f"{merged['paths_total']:,}",       C(A_WARN)),
        ("UNIQUE CRASHES", f"{merged['unique_crashes']:,}",    C(A_ERR)  if merged['unique_crashes'] > 0 else C(TEXT_DIM)),
        ("UNIQUE HANGS",   f"{merged['unique_hangs']:,}",      C(A_HANG) if merged['unique_hangs']   > 0 else C(TEXT_DIM)),
        ("CYCLES DONE",    f"{merged['cycles_done']:,}",       C(A_PURP)),
        ("RUN TIME",       run_time,                           C(A_GREEN)),
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
    story.append(Paragraph("COVERAGE &amp; PERFORMANCE",
                            sty("section", size=12, color=C(ACCENT2), bold=True,
                                space_before=14, space_after=4)))
    chart_buf = _render_charts_image(merged, instances)
    if chart_buf:
        img = Image(chart_buf, width=W - MARGIN * 2, height=(W - MARGIN * 2) * 0.6)
        story.append(img)
        story.append(Spacer(1, 6))

    # ── Per-instance table ────────────────────────────────────────────────
    story.append(Paragraph("PER-INSTANCE BREAKDOWN",
                            sty("section", size=12, color=C(ACCENT2), bold=True,
                                space_before=14, space_after=4)))

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
            cell_p(f"{ival(inst,'unique_crashes'):,}", C(A_ERR)  if ival(inst,'unique_crashes') > 0 else None),
            cell_p(f"{ival(inst,'unique_hangs'):,}",  C(A_HANG) if ival(inst,'unique_hangs')   > 0 else None),
            cell_p(f"{ival(inst,'cycles_done'):,}"),
            cell_p(f"{ival(inst,'corpus_count'):,}"),
            cell_p(f"{ival(inst,'max_depth'):,}"),
            cell_p(inst.get("stability", "n/a")),
            cell_p(inst.get("bitmap_cvg", "n/a")),
        ])

    table_data.append([
        cell_p("COMBINED",                            C(A_WARN)),
        cell_p(f"{merged['execs_done']:,}",           C(A_WARN)),
        cell_p(f"{merged['execs_per_sec']:,.1f}",     C(A_WARN)),
        cell_p(f"{merged['paths_total']:,}",          C(A_WARN)),
        cell_p(f"{merged['unique_crashes']:,}",       C(A_WARN)),
        cell_p(f"{merged['unique_hangs']:,}",         C(A_WARN)),
        cell_p(f"{merged['cycles_done']:,}",          C(A_WARN)),
        cell_p(f"{merged['corpus_count']:,}",         C(A_WARN)),
        cell_p(f"{merged['max_depth']:,}",            C(A_WARN)),
        cell_p("—",                                   C(A_WARN)),
        cell_p("—",                                   C(A_WARN)),
    ])

    n_inst = len(instances)
    row_styles = [
        ("BACKGROUND",    (0, 0),         (-1, 0),         C(BG_HEADER)),
        ("BACKGROUND",    (0, n_inst+1),  (-1, n_inst+1),  C(BG_TOTALS)),
        ("GRID",          (0, 0),         (-1, -1),         0.4, C(BORDER)),
        ("TOPPADDING",    (0, 0),         (-1, -1),         4),
        ("BOTTOMPADDING", (0, 0),         (-1, -1),         4),
        ("VALIGN",        (0, 0),         (-1, -1),         "MIDDLE"),
    ]
    for i in range(1, n_inst + 1):
        bg = C(BG_ROW_A) if i % 2 == 1 else C(BG_ROW_B)
        row_styles.append(("BACKGROUND", (0, i), (-1, i), bg))

    tbl = Table(table_data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle(row_styles))
    story.append(tbl)

    # ── Crash / hang file listing ─────────────────────────────────────────
    if crash_files or hang_files:
        story.append(Paragraph(
            "CRASH &amp; HANG FILES",
            sty("cs", size=12, color=C(A_ERR), bold=True, space_before=14, space_after=4),
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

    # ── Run metadata ──────────────────────────────────────────────────────
    story.append(Paragraph("RUN METADATA",
                            sty("section", size=12, color=C(ACCENT2), bold=True,
                                space_before=14, space_after=4)))
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
        [Paragraph(k, sty("mk", size=9, color=C(ACCENT),     bold=True)),
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


# ============================================================================
# ARGUMENT PARSING
# ============================================================================
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="VibeFuzzer ---------- an AFL++ + libdesock + C based LLM mutator fuzzing wrapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
            # Standard run (mutator built by setup.sh)
            python3 vibefuzzer.py ~/targets/nginx objs/nginx \\
                --protocol HTTP --no-llm-seeds \\
                --input ~/targets/nginx/corpus \\
                --output ~/targets/nginx/findings \\
                --target-args -c ~/targets/nginx/fuzz.conf

            # Generate a PDF report from a completed fuzzing run
            python3 vibefuzzer.py --report --data ~/targets/nginx/findings
        
            # Debug UI — both instances side-by-side in tmux
            python3 vibefuzzer.py ~/targets/nginx objs/nginx \\
                --protocol HTTP --no-llm-seeds \\
                --input ~/targets/nginx/corpus \\
                --output ~/targets/nginx/findings \\
                --debug-ui \\
                --target-args -c ~/targets/nginx/fuzz.conf
                """,
    )

    # ── Report-only mode ──────────────────────────────────────────────────
    report_group = parser.add_argument_group(
        "Report Generation",
        "Pass --report --data <dir> to generate a PDF from a completed fuzzing "
        "output directory without starting a fuzzing session.",
    )
    report_group.add_argument(
        "--report",
        action="store_true",
        help="Generate a PDF report from --data and exit (no fuzzing).",
    )
    report_group.add_argument(
        "--data",
        default=None,
        metavar="DIR",
        help="AFL++ output directory to read fuzzer_stats from (required with --report).",
    )
    report_group.add_argument(
        "--report-out",
        default=None,
        metavar="DIR",
        help="Directory to write the PDF report to (default: current working directory).",
    )

    # ── Target / positional ───────────────────────────────────────────────
    target_group = parser.add_argument_group("Target Configuration")
    target_group.add_argument(
        "target_dir", nargs="?", default=None,
        help="Target server source directory (not required with --report)",
    )
    target_group.add_argument("--binary",   default=None,
                              help="Expected binary path relative to target dir. Auto-detected if omitted.")
    target_group.add_argument("--protocol", default=None, choices=valid_protocols,
                              help="Protocol the target speaks")

    # ── Build Options ─────────────────────────────────────────────────────
    build_group = parser.add_argument_group("Build Options")
    build_group.add_argument("--custom-build",   default=None,
                             help="Custom build command string (overrides auto-detect)")
    build_group.add_argument("--configure-args", default=None,
                             help="Args for the setup phase (./configure, cmake -B, meson setup)")
    build_group.add_argument("--make-args",      default=None,
                             help="Args for the compile phase (make, cmake --build, ninja)")
    build_group.add_argument("--target-args",    nargs=argparse.REMAINDER, default=[],
                             help="Args passed to the target binary after --")

    # ── AFL++ Fuzzing Options ─────────────────────────────────────────────
    fuzz_group = parser.add_argument_group("Fuzzing Configuration")
    fuzz_group.add_argument("--input",    default="./fuzzing_inputs",
                            help="Seed corpus directory (default: ./fuzzing_inputs)")
    fuzz_group.add_argument("--output",   default="./fuzzing_output",
                            help="Findings output directory (default: ./fuzzing_output)")
    fuzz_group.add_argument("--afl-args", nargs='*', default=[],
                            help="Extra flags for afl-fuzz itself (e.g. -p fast)")
    fuzz_group.add_argument("--debug-ui", action="store_true",
                            help="Launch both instances side-by-side in tmux")

    # ── LLM Mutator Options ───────────────────────────────────────────────
    llm_group = parser.add_argument_group("LLM Mutator Configuration")
    llm_group.add_argument("--no-llm-seeds", action="store_true",
                           help="Skip LLM seed generation — use existing seeds or fallback")
    llm_group.add_argument("--num-seeds", type=int, default=10,
                           help="Number of LLM-generated seeds (default: 10)")

    return parser.parse_args()

# ============================================================================
# MAIN
# ============================================================================
def main() -> int:
    """
    Main entry point for AFL++ fuzzing
    """
    args = parse_args()

    # ── Report-only shortcut ──────────────────────────────────────────────
    if args.report:
        if not args.data:
            print("[!] --data <directory> is required with --report.")
            print("    Example: python3 vibefuzzer.py --report --data ./fuzzing_output")
            return 1
        data_dir = args.data
        if not Path(data_dir).is_dir():
            print(f"[!] Data directory not found: {data_dir}")
            return 1
        from datetime import datetime
        timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = Path(args.report_out).resolve() if args.report_out else Path.cwd()
        report_dir.mkdir(parents=True, exist_ok=True)
        pdf_path   = str(report_dir / f"vibefuzzer_report_{timestamp}.pdf")
        try:
            generate_pdf_report(data_dir, pdf_path)
        except Exception as e:
            print(f"[!] Failed to generate report: {e}")
            traceback.print_exc()
            return 1
        return 0

    # ── Normal fuzzing mode ───────────────────────────────────────────────
    if not args.target_dir:
        print("[!] target_dir is required unless --report is specified.")
        print("    Run with --help for usage.")
        return 1

    print("[*] VibeFuzzer")
    print("[*] Configuration:")
    for k, v in vars(args).items():
        print(f"    {k}: {v}")
    print()

    # Main fuzzing workflow
    try:
        # 0. Preflight — verify repo structure built by setup.sh ===============
        print("\n=== STAGE: Preflight Checks ===")
        preflight_checks()

        # 1. Preparation & Compilation ==========================================
        print("\n=== STAGE: Preparation & Compilation ===")
        
        # Build instrumented target (automatically skips if already built)
        binary_path = str(build_target(
            source_dir=args.target_dir,
            binary_name=args.binary,  
            configure_args=args.configure_args,
            make_args=args.make_args,
            custom_build_cmd=args.custom_build,
        ))
 
        # Build base environment from monorepo constants
        base_env = setup_aflpp_env()

        # 2. Pre Fuzzing Seed Generation ==========================================
        # Generate initial seeds via LLM (or skip with --no-llm-seeds)
        if args.no_llm_seeds:
            print("[*] Skipping LLM seed generation (--no-llm-seeds)")
            Path(args.input).mkdir(parents=True, exist_ok=True)
            if not list(Path(args.input).iterdir()):
                fallback = Path(args.input) / "seed_fallback"
                fallback.write_text("HELP\r\n")
                print("[*] Wrote minimal fallback seed")
        else:
            print("\n=== STAGE: Seed Generation ===")
            seed_gen.generate_llm_seeds(
                input_dir=args.input,
                binary_name=args.binary,
                protocol=args.protocol,
                num_seeds=args.num_seeds,
            )

        # 3. Build AFL++ Commands ===================================================
        # Build primary command
        p_cmd, p_env = build_aflpp_cmd(
            binary=binary_path, input_dir=args.input, output_dir=args.output,
            env=base_env, instance_name="primary",
            extra_afl_args=args.afl_args or None, target_args=args.target_args or None,
            debug_ui=args.debug_ui,
        )

        # Build secondary command
        s_cmd, s_env = build_aflpp_cmd(
            binary=binary_path, input_dir=args.input, output_dir=args.output,
            env=base_env, instance_name="secondary", mutator_so=str(MUTATOR_SO), 
            extra_afl_args=args.afl_args or None, target_args=args.target_args or None,
            debug_ui=args.debug_ui,
        )

        # 4. Execute AFL++ ==========================================================
        primary_handle = None
        secondary_handle = None

        if args.debug_ui:
            tmux_ui.launch_in_tmux("vibefuzzer", p_cmd, p_env, s_cmd, s_env)
            print("[*] Fuzzers are alive in tmux. Wrapper exiting.")
            return 0
        
        else:
            print("\n=== STAGE: Launching Primary (CPU) ===")
            # Execute the primary instance 
            primary_handle = subprocess.Popen(p_cmd, env=p_env, text=True, start_new_session=True)
            print(f"[*] Primary PID: {primary_handle.pid}")

            print("\n=== STAGE: Launching Secondary (GPU) ===")
            print("[*] Waiting 5s for primary to initialise queue...")
            time.sleep(5)
            
            out_dest = open(f"{args.output}/secondary.log", "w")
            # Execute the secondary instance
            # redirect secondary output to a log file
            secondary_handle = subprocess.Popen( s_cmd, env=s_env, stdout=out_dest, stderr=out_dest, text=True, start_new_session=True)
            print(f"[*] Secondary PID: {secondary_handle.pid}")

            # TODO: After fuzzing completes, we can analyze results, generate reports, etc.
            # TODO: Add While loop for user intervention 
            # TODO: Implement GUI 

            # Wait and Cleanup ========================================== 
            print("\n[*] Fuzzing instances running. Press Ctrl+C to stop.")
            try:
                primary_handle.wait()
                secondary_handle.wait()
            except KeyboardInterrupt:
                print("\n[*] Fuzzing interrupted by user. Shutting down instances...")
            finally:
                # Kill the processes
                if primary_handle.poll() is None:
                    primary_handle.terminate()
                if secondary_handle and secondary_handle.poll() is None:
                    secondary_handle.terminate()
                
                if primary_handle: primary_handle.wait()
                if secondary_handle: secondary_handle.wait()
                
                # Wipe the temporary RAM disk folders
                print("[*] Cleaning up temporary RAM disk directories...")
                for instance in ["primary", "secondary"]:
                    tmp_path = f"/tmp/afl_tmp_{instance}"
                    if os.path.exists(tmp_path):
                        shutil.rmtree(tmp_path, ignore_errors=True)

                print("[*] All fuzzing instances cleanly terminated.")

    except Exception as e:
        print(f"\n[!] Error: {e}")
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":  
    main()