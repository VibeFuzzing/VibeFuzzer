import time
import shutil
import sys
import os
import subprocess
import argparse
from pathlib import Path
from typing import Optional, Union, Tuple
import tmux_ui
import seed_gen

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
valid_protocols = ['FTP', 'HTTP', 'SMTP', 'RTSP', 'DNS', 'SIP']

# ============================================================================
# PREFLIGHT CHECKS
# ============================================================================
def preflight_checks() -> None:
    """
    Verifies that all monorepo dependencies exist before attempting to fuzz.
    Raises SystemExit with helpful messages if anything critical is missing.
    """
    errors = []
 
    if not AFL_PATH.exists():
        errors.append(f"  AFL++ not found at:      {AFL_PATH}")
    if not LIBDESOCK_SO.exists():
        errors.append(f"  libdesock not found at:  {LIBDESOCK_SO}")
    if not MUTATOR_SO.exists():
        errors.append(f"  LLM mutator not found at: {MUTATOR_SO}")

    try:
        ollama_check = subprocess.run(["ollama", "list"], capture_output=True, text=True, check=True)
        if "afl-mutator" not in ollama_check.stdout:
            errors.append("  Ollama model 'afl-mutator' not found.")
    except FileNotFoundError:
        errors.append("  Ollama is not installed or not in PATH.")
    except subprocess.CalledProcessError:
        errors.append("  Ollama daemon is not responding.")
 
    if errors:
        print("[!] Monorepo dependencies missing. Did you run setup.sh?")
        for e in errors:
            print(e)
        sys.exit(1)
 
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
    binary_name: str,
    configure_args: Optional[str] = None,
    make_args: Optional[str] = None,
) -> Path:
    """
    Instruments and builds the fuzz target with afl-clang-fast. Returns the path to the instrumented binary.
    """

    # Check source directory exists
    source_path = Path(source_dir).resolve()
    if not source_path.exists():
        raise FileNotFoundError(f"Target source not found: {source_path}")

    # Common binary locations to check after build (some projects put binaries in src/ or bin/)
    search_paths = [
        source_path / binary_name,
        source_path / "src" / binary_name,
        source_path / "bin" / binary_name,
    ]

    # Reuse if already instrumented
    for path in search_paths:
        if path.is_file() and verify_instrumentation(path, fatal=False):
            print(f"[*] Existing instrumented binary found: {path}")
            return path.resolve()

    # Otherwise, build from source
    print(f"[*] Building target in: {source_path}")
    os.chdir(source_path)

    # Assumes a standard build system with ./configure && make
    # TODO: Add support for CMake, Meson, or custom build systems if needed
    # TODO: -- flag for passing custom build commands or scripts
    if Path("./configure").exists():
        cfg = "CC=afl-clang-fast CXX=afl-clang-fast++ ./configure"
        if configure_args:
            cfg += f" {configure_args}"
        subprocess.run(cfg, shell=True, check=True)

    # Clean before build to ensure no stale binaries. 
    # TODO: could be optimized to only clean if we detect an existing binary that isn't instrumented.
    subprocess.run("make clean", shell=True, check=True)
    subprocess.run("make" + (f" {make_args}" if make_args else ""), shell=True, check=True)

    for path in search_paths:
        if path.is_file() and verify_instrumentation(path, fatal=True):
            print(f"[*] Binary ready: {path.resolve()}")
            return path.resolve()

    raise FileNotFoundError(f"Binary '{binary_name}' not found after build.")

def verify_instrumentation(binary_path: Path, fatal: bool = True) -> bool:
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


# ============================================================================
# RUN AFL++ 
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

    # If we have a custom mutator .so, set up the environment for it.
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

    # Note: We don't actually launch the process here — we just return the command and environment.
    return aflpp_cmd, run_env

# ============================================================================
# ARGUMENT PARSING
# ============================================================================
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="WibeFuzzer ---------- an AFL++ + libdesock + C based LLM mutator fuzzing wrapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
            # Standard run (mutator built by setup.sh)
            python3 wrapper.py ~/targets/nginx objs/nginx \\
                --no-build --protocol HTTP --no-llm-seeds \\
                --input ~/targets/nginx/corpus \\
                --output ~/targets/nginx/findings \\
                --target-args -c ~/targets/nginx/fuzz.conf
        
            # Debug UI — both instances side-by-side in tmux
            python3 wrapper.py ~/targets/nginx objs/nginx \\
                --no-build --protocol HTTP --no-llm-seeds \\
                --input ~/targets/nginx/corpus \\
                --output ~/targets/nginx/findings \\
                --debug-ui \\
                --target-args -c ~/targets/nginx/fuzz.conf
                """,
    )

    # Positional / Target
    target_group = parser.add_argument_group("Target Configuration")
    target_group.add_argument("target_dir",             help="Target server source directory")
    target_group.add_argument("binary",                 help="Binary name to fuzz")
    target_group.add_argument("--protocol",             default=None, choices=valid_protocols,
                                                        help="Protocol the target speaks (improves LLM seed quality)")

    # Build Options
    build_group = parser.add_argument_group("Build Options")
    build_group.add_argument("--no-build",              action="store_true",
                                                        help="Skip build — binary must already be instrumented")
    build_group.add_argument("--configure-dir",         default=None,
                                                        help="Directory containing ./configure if not in target_dir")
    build_group.add_argument("--configure-args",        default=None, help="Extra args for ./configure")
    build_group.add_argument("--make-args",             default=None, help="Extra args for make")
    build_group.add_argument("--target-args",           nargs=argparse.REMAINDER, default=[],
                                                        help="Args passed to the target binary after --")

    # AFL++ Fuzzing Options
    fuzz_group = parser.add_argument_group("Fuzzing Configuration")
    fuzz_group.add_argument("--input",                  default="./fuzzing_inputs",
                                                        help="Seed corpus directory (default: ./fuzzing_inputs)")
    fuzz_group.add_argument("--output",                 default="./fuzzing_output", 
                                                        help="Findings output directory (default: ./fuzzing_output)")
    fuzz_group.add_argument("--afl-args",               nargs='*', default=[],
                                                        help="Extra flags for afl-fuzz itself (e.g. -p fast)")
    fuzz_group.add_argument("--debug-ui",               action="store_true",
                                                        help="Launch both instances side-by-side in tmux"))

    # LLM Mutator Options
    llm_group = parser.add_argument_group("LLM Mutator Configuration")
    llm_group.add_argument("--no-llm-seeds",            action="store_true",
                                                        help="Skip LLM seed generation — use existing seeds or fallback")
    llm_group.add_argument("--num-seeds",               type=int, default=10,
                                                        help="Number of LLM-generated seeds (default: 10)")

    return parser.parse_args()

# ============================================================================
# MAIN
# ============================================================================
def main() -> int:
    """
    Main entry point for AFL++ fuzzing
    """
    # setup arguments and configuration
    args = parse_args()

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
        
        # Build instrumented target
        # If skipping build, we assume the user has already built the target binary with AFL++ instrumentation.
        # We just need to verify it exists and is instrumented.
        if args.no_build:
            binary_path = Path(args.target_dir) / args.binary
            if not binary_path.exists():
                raise FileNotFoundError(f"Binary not found: {binary_path}")
            verify_instrumentation(binary_path, fatal=True)
            binary_path = str(binary_path)
        else:
            binary_path = str(build_target(
                source_dir=args.target_dir,
                binary_name=args.binary,
                configure_dir=args.configure_dir,
                configure_args=args.configure_args,
                make_args=args.make_args,
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
            env=base_env, instance_name="secondary", mutator_so=MUTATOR_SO,
            extra_afl_args=args.afl_args or None, target_args=args.target_args or None,
            debug_ui=args.debug_ui,
        )

        # 4. Execute AFL++ ==========================================================
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
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":  
    main()