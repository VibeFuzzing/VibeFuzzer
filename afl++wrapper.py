import shutil
import sys
import os
import subprocess
import argparse
from pathlib import Path
from typing import Optional


# import ollama
# MODEL = 'llama3:latest'

# TODO: add more protocols as needed
valid_protocols = ['FTP', 'HTTP', 'SMTP', 'RTSP', 'DNS', 'SIP']

# ============================================================================
# COMPILE MUTATOR
# ============================================================================
def build_c_mutator(source_dir: str) -> str:
    """
    Runs `make` inside mutator directory.
    Returns path to compiled .so.
    """

    source_path = Path(source_dir).resolve()
    if not source_path.exists():
        raise FileNotFoundError(f"Mutator directory not found: {source_path}")

    print(f"[*] Building mutator using Makefile in {source_path}")

    subprocess.run(["make"], cwd=source_path, check=True)

    # Find produced .so
    so_files = list(source_path.glob("*.so"))
    if not so_files:
        raise RuntimeError("No .so file produced by make.")

    mutator_so = so_files[0].resolve()
    print(f"[*] Mutator built: {mutator_so}")

    return str(mutator_so)

# ============================================================================
# ENVIRONMENT SETUP (AFL++)
# ============================================================================
def setup_aflpp_env(mutator_path: str, libdesock_path: str):
    """
    Does NOT mutate os.environ globally — env is passed directly to subprocess.Popen so the parent process stays clean.
    """
    print("[*] Configuring AFL++ and libdesock environment...")

    # Verify afl-fuzz exists
    afl_fuzz_path = shutil.which("afl-fuzz")
    if not afl_fuzz_path:
        raise FileNotFoundError("afl-fuzz not found in PATH.")
    afl_path = str(Path(afl_fuzz_path).resolve().parent)
    print(f"[*] afl-fuzz found at: {afl_fuzz_path}")

    # Verify libdesock exists
    libdesock_resolved = Path(libdesock_path).resolve()
    if not libdesock_resolved.exists():
        raise FileNotFoundError(f"libdesock not found at: {libdesock_resolved}")
    print(f"[*] libdesock will be LD_PRELOADed: {libdesock_resolved}")

    # Verify mutator .so exists (built before this is called)
    mutator_resolved = Path(mutator_path).resolve()
    if not mutator_resolved.exists():
        raise FileNotFoundError(f"LLM mutator .so not found at: {mutator_resolved}")
    print(f"[*] LLM mutator .so found at: {mutator_resolved}")

    # Set environment variables for AFL++ and libdesock. 
    env = os.environ.copy()
    # This env dict will be passed to subprocess.Popen when launching afl-fuzz, so it only affects the child process.
    env.update({
        # Use AFL++ compilers that support instrumentation
        "CC":                                    "afl-clang-fast",
        "CXX":                                   "afl-clang-fast++",
        "AFL_PATH":                              afl_path,
        # Preload libdesock to intercept network calls -> redirect to stdin/stdout
        "LD_PRELOAD":                            str(libdesock_resolved),
        # Load C mutator — afl_custom_fuzz() is called IN ADDITION to AFL++ built-ins
        "AFL_CUSTOM_MUTATOR_LIBRARY":            str(mutator_resolved),
        "AFL_CUSTOM_MUTATOR_ONLY":               "0",   # keep AFL++ built-in mutations ON
        "AFL_SKIP_CPUFREQ":                      "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",  # needed in Docker/WSL
        "ASAN_OPTIONS":                          "abort_on_error=1:detect_leaks=0",
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
    # TODO??: Add support for CMake, Meson, or custom build systems if needed
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
# LLM SEED GENERATION 
# ============================================================================

# TODO: implement LLM initial seed generation

# ============================================================================
# RUN AFL++ WITH LIBDESOCK + CUSTOM MUTATOR
# ============================================================================

def run_aflpp(
    binary: str,
    input_dir: str,
    output_dir: str,
    env: dict,
    extra_afl_args: Optional[list] = None,
) -> subprocess.Popen:
    """
    Launches afl-fuzz. LD_PRELOAD (libdesock) and AFL_CUSTOM_MUTATOR_LIBRARY (.so) are in `env`
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Build AFLNet command
    aflpp_cmd = [
        "afl-fuzz",
        "-i", input_dir,
        "-o", output_dir,
        "-m", "none",    # no memory cap — ASAN handles OOM
        "-t", "5000+",   # 5s timeout; '+' = lenient on slow starts
    ]

    # Add any extra AFL++ args from the command line (e.g. -d for deterministic mode, -x for dictionary, etc.)
    if extra_afl_args:
        aflpp_cmd += extra_afl_args

    # The target binary and its arguments go after the -- separator. 
    # For network services, we typically just specify the binary and let libdesock handle the I/O redirection.
    aflpp_cmd += ["--", binary]

    print("[*] AFL++ Command:")
    print("    " + " ".join(aflpp_cmd))
    print()

    # Run AFLNet
    print("[*] Starting AFL++ fuzzing...")
    try:
        # use subprocess.Popen to run afl-fuzz and have a handler to manage it (e.g. for concurrent LLM loop)
        return subprocess.Popen(
            aflpp_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env
        )
    except FileNotFoundError:
        print("Error: AFL++ not found. Please install it first.")
        print("Install: sudo apt-get install afl++ (or build from source)")
        sys.exit(1)
# ============================================================================
# ARGUMENT PARSING
# ============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AFL++ + libdesock + C based LLM mutator fuzzing wrapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=
        """
        Examples:
        python3 fuzz.py ../proftpd proftpd FTP \\
            --mutator-src ./llm_mutator.c \\
            --libdesock   ./libdesock.so

        python3 fuzz.py ../nginx nginx HTTP \\
            --mutator-src ./llm_mutator.c \\
            --libdesock   ./libdesock.so \\
            --no-build --output ./out
        """,
        )

    parser.add_argument("target_dir",           help="Target server source directory")
    parser.add_argument("binary",               help="Binary name to fuzz")
    # TODO: Unused for now 
    # parser.add_argument("protocol",           help="Protocol", choices=valid_protocols)  

    parser.add_argument("--mutator-src",        required=True, help="Path to llm_mutator.c")
    parser.add_argument("--libdesock",          required=True, help="Path to libdesock.so")

    parser.add_argument("--afl-include",        default="/usr/local/include/afl",
                                                help="AFL++ headers dir for gcc compile")
    parser.add_argument("--input",              default="./fuzzing_inputs")
    parser.add_argument("--output",             default="./fuzzing_output")
    parser.add_argument("--configure-args",     default=None, help="Extra args for ./configure")
    parser.add_argument("--make-args",          default=None, help="Extra args for make")
    parser.add_argument("--no-build",           action="store_true",
                                                help="Skip target build — binary must already be instrumented")
    parser.add_argument("--afl-args",           nargs=argparse.REMAINDER, default=[],
                                                help="Extra flags forwarded to afl-fuzz (place last)")

    return parser.parse_args()


# ============================================================================
# MAIN
# ============================================================================
def main() -> int:
    """
    Main entry point for AFLNet fuzzing
    """
    # setup arguments and configuration
    args = parse_args()

    # print configuration for user visibility
    print("[*] Configuration:")
    for k, v in vars(args).items():
        print(f"    {k}: {v}")
    print()

    # Main fuzzing workflow
    try:
        # 1. Compile llm_mutator.c -> llm_mutator.so
        mutator_so = build_c_mutator(
            source_file=args.mutator_src,
            afl_include_dir=args.afl_include,
        )

        # 2. Validate all paths, build child-process environment dict
        env = setup_aflpp_env(
            mutator_path=mutator_so,
            libdesock_path=args.libdesock,
        )

        # 3. Build instrumented target (skippable with --no-build)
        if args.no_build:
            # If skipping build, we assume the user has already built the target binary with AFL++ instrumentation.
            # We just need to verify it exists and is instrumented.
            binary_path = Path(args.target_dir) / args.binary
            if not binary_path.exists():
                raise FileNotFoundError(f"Binary not found: {binary_path}")
            verify_instrumentation(
                binary_path, 
                fatal=True
            )
        else:
            # This will build the target binary with AFL++ instrumentation using afl-clang-fast. 
            # It assumes a standard build system (configure/make) but can be extended to support CMake, Meson, etc. if needed.
            binary_path = build_target(
                source_dir=args.target_dir,
                binary_name=args.binary,
                configure_args=args.configure_args,
                make_args=args.make_args,
            )

        # 4. Generate initial seeds 
        # TODO: replace with LLM initial seed generation 
        # (args.protocol can be used to condition the LLM)
        Path(args.input).mkdir(parents=True, exist_ok=True)
        seed = Path(args.input) / "default_seed"
        if not seed.exists():
            seed.write_text("HELP\n")

        # 5. Run afl-fuzz with libdesock + custom mutator
        # The AFL++ process will run concurrently
        # We can implement an LLM loop in the main process that monitors AFL++'s progress.
        aflpp_handle = run_aflpp(
            binary=str(binary_path),
            input_dir=args.input,
            output_dir=args.output,
            env=env,
            extra_afl_args=args.afl_args or None,
        )

        # TODO: run LLM in concurrent loop (for now we just run AFL++ on its own)
        aflpp_handle.wait()

        # TODO: After fuzzing completes, we can analyze results, generate reports, etc.
        # TODO: Process cleanup 
        # TODO: Add While loop for user intervention 
        # TODO: Implement GUI 

    # Exception handling
    except KeyboardInterrupt:
        print("\n[*] Fuzzing interrupted")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    main()