# vibefuzzer.py
# ============================================================================
# IMPORTS 
# ============================================================================
import time
import shutil
import sys
import os
import signal
import subprocess
import argparse
import traceback

# Helper modules 
from utils import tmux_ui
from utils import report_gen
from utils import seed_gen

from datetime import datetime
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
        for arg in extra_afl_args:
            aflpp_cmd += arg.split()

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
    build_group.add_argument("--target-args", nargs=argparse.REMAINDER, default=[],
                            help="Args passed to the target binary after --")


    # ── AFL++ Fuzzing Options ─────────────────────────────────────────────
    fuzz_group = parser.add_argument_group("Fuzzing Configuration")
    fuzz_group.add_argument("--input",    default="./fuzzing_inputs",
                            help="Seed corpus directory (default: ./fuzzing_inputs)")
    fuzz_group.add_argument("--output",   default="./fuzzing_output",
                            help="Findings output directory (default: ./fuzzing_output)")
    fuzz_group.add_argument("--afl-args", nargs='*', default=[],
                            help="Extra flags for afl-fuzz (e.g. --afl-args=\"-V 86400\" \"-p fast\")")
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

    # Report-only mode
    if args.report:
        if not args.data:
            print("[!] --data <directory> is required with --report.")
            print("    Example: python3 vibefuzzer.py --report --data ./fuzzing_output")
            return 1
        data_dir = args.data
        if not Path(data_dir).is_dir():
            print(f"[!] Data directory not found: {data_dir}")
            return 1
        timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = Path(args.report_out).resolve() if args.report_out else Path.cwd()
        report_dir.mkdir(parents=True, exist_ok=True)
        pdf_path   = str(report_dir / f"vibefuzzer_report_{timestamp}.pdf")
        try:
            report_gen.generate_pdf_report(data_dir, pdf_path)
        except Exception as e:
            print(f"[!] Failed to generate report: {e}")
            traceback.print_exc()
            return 1
        return 0

    # Normal fuzzing mode 
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
                binary_name=binary_path,
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
            
            # Give AFL++ a moment to start (or fail)
            print("[*] Waiting 3s to verify AFL++ instances started...")
            time.sleep(3)

            # Check if the tmux session is still alive
            result = subprocess.run(
                ["tmux", "has-session", "-t", "vibefuzzer"],
                capture_output=True
            )
            if result.returncode != 0:
                print("[!] tmux session died immediately — AFL++ likely failed to start. Check your binary, input dir, and AFL++ installation.")
                return 1

            # Check if any panes exited with an error
            pane_check = subprocess.run(
                ["tmux", "list-panes", "-t", "vibefuzzer", "-F", "#{pane_dead}"],
                capture_output=True, text=True
            )
            if "1" in pane_check.stdout:
                print("[!] One or more AFL++ panes exited — check tmux for errors.")
                return 1

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
                print("\n[*] Shutting down fuzzing instances...")
                for handle, name in [(primary_handle, "primary"), (secondary_handle, "secondary")]:
                    if handle and handle.poll() is None:
                        try:
                            os.killpg(os.getpgid(handle.pid), signal.SIGTERM)
                            print(f"[*] Sent SIGTERM to {name} (PID {handle.pid})")
                        except ProcessLookupError:
                            pass

                for handle in [primary_handle, secondary_handle]:
                    if handle:
                        try:
                            handle.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            os.killpg(os.getpgid(handle.pid), signal.SIGKILL)
                            handle.wait()

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
