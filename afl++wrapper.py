import time
import shutil
import sys
import os
import subprocess
import argparse
from pathlib import Path
from typing import Optional

import ollama

MODEL = 'llama3.1:8b'
OLLAMA_BASE_URL = 'http://localhost:11434'

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
def setup_aflpp_env(libdesock_path: str, mutator_path: Optional[str] = None) -> dict:
    """
    Does NOT mutate os.environ globally — env is passed directly to subprocess.Popen so the parent process stays clean.
    """
    print("[*] Configuring base AFL++ environment variables...")

    # Verify afl-fuzz exists
    afl_fuzz_path = shutil.which("afl-fuzz")
    
    if not afl_fuzz_path:
        raise FileNotFoundError("afl-fuzz not found in PATH.")

    afl_path = str(Path(afl_fuzz_path).resolve().parent)
    print(f"[*] afl-fuzz found at: {afl_fuzz_path}")

    env = os.environ.copy()
    env.update({
        "CC":                                    "afl-clang-fast",
        "CXX":                                   "afl-clang-fast++",
        "AFL_PATH":                              afl_path,
        "AFL_PRELOAD":                           str(libdesock_path),
        "AFL_TMPDIR":                            "/tmp",
        "AFL_SKIP_CPUFREQ":                      "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        "ASAN_OPTIONS":                          "abort_on_error=1:detect_leaks=0:symbolize=0",
    })

    return env

def verify_libdesock(lib_path: str) -> str:
    """
    Verifies the provided libdesock.so exists.
    """
    
    libdesock_resolved = Path(lib_path).resolve()

    if not libdesock_resolved.exists():
        raise FileNotFoundError(f"libdesock not found at: {libdesock_resolved}")
    print(f"[*] libdesock verified at: {libdesock_resolved}")
    
    return str(libdesock_resolved)

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

# Protocol-specific hints that help the LLM generate better seeds.
# Each entry provides example messages and structural notes for the LLM prompt.
# Add new protocols here as needed — the LLM will use these as context.
PROTOCOL_HINTS = {
    'FTP': {
        'description': 'File Transfer Protocol — command/response text protocol over TCP',
        'example_session': (
            'USER anonymous\r\n'
            'PASS guest@\r\n'
            'SYST\r\n'
            'PWD\r\n'
            'LIST\r\n'
            'QUIT\r\n'
        ),
        'notes': 'Commands are uppercase 3-4 chars followed by optional args. Lines end with \\r\\n.',
    },
    'HTTP': {
        'description': 'Hypertext Transfer Protocol — request/response text protocol over TCP',
        'example_session': (
            'GET / HTTP/1.1\r\n'
            'Host: localhost\r\n'
            'User-Agent: fuzzer/1.0\r\n'
            'Accept: */*\r\n'
            '\r\n'
        ),
        'notes': 'Request line + headers + blank line + optional body. Methods: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH. All lines MUST end with \\r\\n, including the blank line separating headers from body.',
    },
    'SMTP': {
        'description': 'Simple Mail Transfer Protocol — email delivery over TCP',
        'example_session': (
            'EHLO localhost\r\n'
            'MAIL FROM:<test@test.com>\r\n'
            'RCPT TO:<user@localhost>\r\n'
            'DATA\r\n'
            'Subject: test\r\n\r\nHello\r\n.\r\n'
            'QUIT\r\n'
        ),
        'notes': 'Command-based. EHLO/HELO starts session. DATA terminates with lone dot on a line.',
    },
    'RTSP': {
        'description': 'Real Time Streaming Protocol — media control protocol similar to HTTP',
        'example_session': (
            'OPTIONS rtsp://localhost/stream RTSP/1.0\r\n'
            'CSeq: 1\r\n'
            '\r\n'
        ),
        'notes': 'HTTP-like syntax with RTSP methods: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN.',
    },
    'DNS': {
        'description': 'Domain Name System — binary query/response protocol over UDP/TCP',
        'example_session': None,  # DNS is binary, not text-based
        'notes': 'Binary protocol. 12-byte header + question section + answer sections. Seeds should be raw bytes.',
    },
    'SIP': {
        'description': 'Session Initiation Protocol — signaling protocol for VoIP',
        'example_session': (
            'INVITE sip:user@localhost SIP/2.0\r\n'
            'Via: SIP/2.0/UDP 127.0.0.1:5060\r\n'
            'From: <sip:caller@localhost>;tag=1234\r\n'
            'To: <sip:user@localhost>\r\n'
            'Call-ID: abcd@localhost\r\n'
            'CSeq: 1 INVITE\r\n'
            'Content-Length: 0\r\n'
            '\r\n'
        ),
        'notes': 'HTTP-like syntax. Methods: INVITE, ACK, BYE, CANCEL, REGISTER, OPTIONS.',
    },
}


def build_seed_prompt(protocol: Optional[str], binary_name: str, seed_index: int, total_seeds: int) -> str:
    """
    Builds a prompt for the LLM to generate a single fuzz seed.
    If protocol is provided (and known), includes protocol-specific context.
    Otherwise, asks the LLM to infer from the binary name.
    """

    # Base system context — tells the LLM its role and output constraints
    prompt_parts = [
        "You are a network protocol fuzzing expert. Your job is to generate test inputs "
        "that will be used as initial seeds for AFL++ fuzzing of a network server.\n\n"
        "You are generating CLIENT REQUESTS that will be sent TO the server. "
        "Do NOT generate server responses (e.g. do NOT output lines like 'HTTP/1.1 200 OK' "
        "or '220 Welcome' or any response status lines). The server will never receive its "
        "own responses as input — only client requests.\n\n"
        "CRITICAL OUTPUT RULES:\n"
        "- Output ONLY the raw seed content. No explanation, no markdown, no code blocks.\n"
        "- Do not wrap output in quotes or backticks.\n"
        "- The output will be written directly to a file and fed to the target binary.\n"
        "- Generate ONLY a single client request per seed.\n\n"
    ]

    # If we have protocol-specific hints, include them
    if protocol and protocol.upper() in PROTOCOL_HINTS:
        hints = PROTOCOL_HINTS[protocol.upper()]
        prompt_parts.append(f"Target protocol: {hints['description']}\n")
        if hints['example_session']:
            prompt_parts.append(f"Example valid session:\n{hints['example_session']}\n")
        prompt_parts.append(f"Protocol notes: {hints['notes']}\n\n")
    else:
        # No protocol specified — let the LLM infer from binary name
        prompt_parts.append(
            f"The target binary is '{binary_name}'. Based on this name, infer what protocol "
            f"or input format this server likely expects and generate an appropriate test input.\n\n"
        )

    # Seed variation instructions — each seed should be different
    prompt_parts.append(
        f"Generate seed {seed_index + 1} of {total_seeds}. Each seed should test something different.\n"
        "Vary across these strategies:\n"
        "- Valid, well-formed messages (baseline coverage)\n"
        "- Messages with boundary-length fields (empty strings, very long values)\n"
        "- Messages with unusual but syntactically valid options or parameters\n"
        "- Slightly malformed messages (wrong line endings, missing required fields)\n"
        "- Messages that exercise different commands/methods/verbs of the protocol\n"
        "- Messages with special characters, null bytes, or encoding edge cases\n\n"
        f"This is seed {seed_index + 1} — make it meaningfully different from the others.\n"
    )

    return "".join(prompt_parts)


def verify_ollama_connection(base_url: str = OLLAMA_BASE_URL) -> bool:
    """
    Checks that Ollama is running and the target model is available.
    Returns True if ready, raises RuntimeError if not.
    """
    try:
        models = ollama.list()
        model_names = [m.model for m in models.models]
        if not any(MODEL in name for name in model_names):
            available = ", ".join(model_names) if model_names else "none"
            raise RuntimeError(
                f"Model '{MODEL}' not found in Ollama. Available models: {available}\n"
                f"Pull it with: ollama pull {MODEL}"
            )
        print(f"[*] Ollama connected. Model '{MODEL}' is available.")
        return True
    except ConnectionError:
        raise RuntimeError(
            f"Cannot connect to Ollama at {base_url}. "
            "Is it running? Start with: ollama serve"
        )


def clean_llm_output(raw: str) -> str:
    """
    Strips LLM commentary and artifacts from generated seed content.
    The LLM sometimes adds explanatory notes, markdown formatting, or
    other text that would corrupt the seed if written to disk.
    Also converts literal escape sequences (e.g. the text \r\n) into
    actual bytes, since the LLM often reproduces escape sequences as text.
    """
    lines = raw.split('\n')
    cleaned = []
    for line in lines:
        stripped = line.strip()
        # Skip lines that are clearly LLM commentary, not protocol data
        if stripped.startswith('(') and stripped.endswith(')'):
            continue  # e.g. "(Note: I've left out the User-Agent value...)"
        if stripped.startswith('```'):
            continue  # markdown code fences
        if stripped.startswith('Note:') or stripped.startswith('NOTE:'):
            continue
        if stripped.startswith('#') and not stripped.startswith('##'):
            # Skip markdown headers but keep things like HTTP fragments
            # that might start with # in edge cases
            if any(word in stripped.lower() for word in ['explanation', 'note', 'comment', 'output']):
                continue
        cleaned.append(line)

    result = '\n'.join(cleaned).strip()

    # Convert literal escape sequences the LLM writes as text into actual bytes.
    # The LLM sees \r\n in the prompt examples and often outputs the literal characters
    # \ r \ n instead of actual carriage return + newline.
    result = result.replace('\\r\\n', '\r\n')
    result = result.replace('\\n', '\n')
    result = result.replace('\\r', '\r')
    result = result.replace('\\t', '\t')
    result = result.replace('\\x00', '\x00')
    result = result.replace('\\0', '\x00')

    return result


def generate_llm_seeds(
    input_dir: str,
    binary_name: str,
    protocol: Optional[str] = None,
    num_seeds: int = 10,
    keep_existing: bool = True,
) -> int:
    """
    Uses Llama 3.1 via Ollama to generate initial seed inputs for AFL++.
    Seeds are written to input_dir, one file per seed.

    Args:
        input_dir:      Path to AFL++ input directory (will be created if needed)
        binary_name:    Name of the target binary (used in prompts if protocol is unknown)
        protocol:       Optional protocol name (FTP, HTTP, etc.) for targeted generation
        num_seeds:      Number of seeds to generate (default: 10)
        keep_existing:  If True, don't overwrite seeds that already exist

    Returns:
        Number of seeds successfully generated
    """

    input_path = Path(input_dir)
    input_path.mkdir(parents=True, exist_ok=True)

    # Check if seeds already exist and user wants to keep them
    existing_seeds = list(input_path.glob("seed_*"))
    if keep_existing and existing_seeds:
        print(f"[*] {len(existing_seeds)} existing seeds found in {input_path}, keeping them.")
        print(f"[*] Generating {num_seeds} additional LLM seeds...")
        # Offset seed numbering so we don't overwrite
        start_index = len(existing_seeds)
    else:
        start_index = 0

    # Verify Ollama is reachable before starting
    verify_ollama_connection()

    generated = 0
    print(f"[*] Generating {num_seeds} seeds with {MODEL}...")
    if protocol:
        print(f"[*] Protocol hint: {protocol}")
    else:
        print(f"[*] No protocol specified — LLM will infer from binary name '{binary_name}'")

    for i in range(num_seeds):
        seed_num = start_index + i
        seed_file = input_path / f"seed_llm_{seed_num:04d}"

        # Skip if file exists and we're keeping existing seeds
        if keep_existing and seed_file.exists():
            print(f"    [skip] {seed_file.name} already exists")
            continue

        prompt = build_seed_prompt(
            protocol=protocol,
            binary_name=binary_name,
            seed_index=i,
            total_seeds=num_seeds,
        )

        try:
            response = ollama.generate(
                model=MODEL,
                prompt=prompt,
                options={
                    'temperature': 0.9,      # high temp for diversity across seeds
                    'num_predict': 512,       # seeds don't need to be huge
                    'top_p': 0.95,
                },
            )

            seed_content = response['response'].strip()
            seed_content = clean_llm_output(seed_content)

            # Basic validation — don't write empty seeds
            if not seed_content:
                print(f"    [warn] Seed {seed_num} was empty, skipping")
                continue

            # Write seed to file as bytes (some protocols need raw bytes)
            seed_file.write_text(seed_content)
            generated += 1
            # Print a truncated preview so the user can sanity-check
            preview = seed_content[:80].replace('\n', '\\n').replace('\r', '\\r')
            print(f"    [ok] {seed_file.name} ({len(seed_content)} bytes): {preview}...")

        except Exception as e:
            print(f"    [err] Seed {seed_num} failed: {e}")
            continue

    # Always ensure at least one fallback seed exists so AFL++ can start
    # even if every LLM call failed
    all_seeds = list(input_path.glob("seed_*"))
    if not all_seeds:
        fallback = input_path / "seed_fallback"
        fallback.write_text("HELP\r\n")
        print(f"    [fallback] No LLM seeds generated — wrote minimal fallback seed")
        generated = 1

    print(f"[*] Seed generation complete: {generated}/{num_seeds} seeds written to {input_path}")
    return generated

# ============================================================================
# RUN AFL++ 
# ============================================================================
def run_aflpp(
    binary: str,
    input_dir: str,
    output_dir: str,
    env: dict,
    instance_name: str = "primary",
    mutator_so: Optional[str] = None,
    extra_afl_args: Optional[list] = None,
    target_args: Optional[list] = None,
) -> subprocess.Popen:
    """
    Launches an afl-fuzz instance. 
    Can act as the primary node or a secondary sync node depending on instance_name.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    run_env = env.copy()

    # TODO: update based on new mutator design and configuration options. For example,
    # we may want to pass additional config via env vars (e.g. for mutator behavior, LLM options, etc.)
    # Only load custom mutator if one is provided
    if mutator_so:
        mutator_resolved = Path(mutator_so).resolve()
        if not mutator_resolved.exists():
            raise FileNotFoundError(f"Mutator .so not found at: {mutator_resolved}")

        # 1. Load the custom library
        run_env["AFL_CUSTOM_MUTATOR_LIBRARY"] = mutator_so
        
        # 2. Force this node to ONLY use the custom LLM mutator, and skip trimming
        run_env["AFL_CUSTOM_MUTATOR_ONLY"]    = "1"
        run_env["AFL_DISABLE_TRIM"]           = "1"
        
        # 3. Pass API configurations down to the C code (ollama.c)
        run_env["OLLAMA_URL"]   = OLLAMA_BASE_URL
        run_env["OLLAMA_MODEL"] = "afl-mutator"
        
        print(f"[*] Injecting custom LLM mutator environment for {instance_name}: {mutator_so}")

    # Build AFL++ command
    aflpp_cmd = ["afl-fuzz"]

    # build primary vs secondary command based on instance_name
    if instance_name == "primary":
        # Primary node: starts with the seed corpus and does the main fuzzing work.
        aflpp_cmd += ["-M", "primary", "-i", input_dir]
        out_dest = None  # primary owns the terminal UI

    else:
        # Secondary node: syncs with primary and focuses on mutating inputs from the queue.
        aflpp_cmd += ["-S", instance_name, "-i", input_dir]
        run_env["AFL_NO_UI"] = "1"
        run_env["DUMMY_MUTATOR_DELAY"] = "60"
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        out_dest = open(f"{output_dir}/{instance_name}.log", "w")  # capture, don't discard


    aflpp_cmd += [
        "-o", output_dir,
        "-m", "none",    # no memory cap — ASAN handles OOM
        "-t", "5000+",   # 5s timeout; '+' = lenient on slow starts
    ]

    # Add AFL++ args BEFORE the -- separator
    if extra_afl_args:
        aflpp_cmd += extra_afl_args

    # The target binary and its arguments go after the -- separator. 
    # For network services, we typically just specify the binary and let libdesock handle the I/O redirection.
    aflpp_cmd += ["--", binary]

    # Then binary and target args AFTER --
    if target_args:
        aflpp_cmd += target_args

    # Run AFL++
    # Pretty print the AFL++ command
    print(f"\n{'─' * 60}")
    print(f"  AFL++ {instance_name.upper()} INSTANCE")
    print(f"{'─' * 60}")
    print(f"  {'Binary':<18} {binary}")
    print(f"  {'Input':<18} {input_dir if instance_name == 'primary' else '- (sync from primary)'}")
    print(f"  {'Output':<18} {output_dir}")
    print(f"  {'Mutator':<18} {mutator_so if mutator_so else 'AFL++ built-in (havoc/splice)'}")
    if target_args:
        print(f"  {'Target Args':<18} {' '.join(target_args)}")
    print(f"{'─' * 60}")
    print(f"  CMD: afl-fuzz {' '.join(aflpp_cmd[1:])}")
    print(f"{'─' * 60}\n")
    try:
        # use subprocess.Popen to run afl-fuzz and have a handler 
        # TODO: we may want to capture stdout/stderr for GUI
        return subprocess.Popen(
            aflpp_cmd,
            stdout=out_dest,
            stderr=out_dest,
            text=True,
            env=run_env,
        )
    except FileNotFoundError:
        print("[!] afl-fuzz not found.")
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
        python3 afl++wrapper.py ../nginx nginx \\
            --protocol HTTP \\
            --llm-mutator ./llm-mutator \\
            --libdesock   ./libdesock.so
        """,
    )

    # Positional / Target
    target_group = parser.add_argument_group("Target Configuration")
    target_group.add_argument("target_dir",             help="Target server source directory")
    target_group.add_argument("binary",                 help="Binary name to fuzz")
    target_group.add_argument("--protocol",             default=None, choices=valid_protocols,
                                                        help="Protocol the target speaks (improves LLM seed quality)")

    # Core Dependencies
    deps_group = parser.add_argument_group("Core Dependencies")
    deps_group.add_argument("--libdesock",              required=True, help="Path to libdesock.so")
    deps_group.add_argument("--afl-include",            default="/usr/local/include/afl",
                                                        help="AFL++ headers dir for gcc compile")

    # Build Options
    build_group = parser.add_argument_group("Build Options")
    build_group.add_argument("--no-build",              action="store_true",
                                                        help="Skip target build — binary must already be instrumented")
    build_group.add_argument("--configure-args",        default=None, help="Extra args for ./configure")
    build_group.add_argument("--make-args",             default=None, help="Extra args for make")
    build_group.add_argument("--target-args",           nargs=argparse.REMAINDER, default=[],
                                                        help="Args passed to the target binary after --")

    # AFL++ Fuzzing Options
    fuzz_group = parser.add_argument_group("AFL++ Configuration")
    fuzz_group.add_argument("--input",                  default="./fuzzing_inputs", help="Directory for seeds")
    fuzz_group.add_argument("--output",                 default="./fuzzing_output", help="Directory for fuzzing findings")
    fuzz_group.add_argument("--afl-args",               nargs='*', default=[],
                                                        help="Extra flags for afl-fuzz itself (e.g. -p fast)")

    # LLM Mutator Options
    llm_group = parser.add_argument_group("LLM Mutator Configuration")
    llm_group.add_argument("--llm-mutator",             default=None, 
                                                        help="Path to LLM mutator directory (optional, triggers secondary GPU node)")
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

    print("[*] Configuration:")
    for k, v in vars(args).items():
        print(f"    {k}: {v}")
    print()

    # Main fuzzing workflow
    try:
        # 0. Preparation & Compilation ==========================================
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
                configure_args=args.configure_args,
                make_args=args.make_args,
            ))

        # Verify libdesock exists and is a .so file
        libdesock_so = verify_libdesock(args.libdesock)
        
        # Build LLM mutator.so if specified
        llm_mutator_so = None
        if args.llm_mutator:
            llm_mutator_so = build_c_mutator(source_dir=args.llm_mutator)

        # Build environment
        base_env = setup_aflpp_env(libdesock_path=libdesock_so)

        # 1. Pre Fuzzing Seed Generation ==========================================
        # Generate initial seeds via LLM (or skip with --no-llm-seeds)
        if args.no_llm_seeds:
            print("[*] Skipping LLM seed generation (--no-llm-seeds)")
            Path(args.input).mkdir(parents=True, exist_ok=True)
            # Ensure at least one seed exists so AFL++ can start
            fallback = Path(args.input) / "seed_fallback"
            if not list(Path(args.input).iterdir()):
                fallback.write_text("HELP\r\n")
                print("[*] Wrote minimal fallback seed")
        else:
            print("\n=== STAGE: Seed Generation ===")
            generate_llm_seeds(
                input_dir=args.input,
                binary_name=args.binary,
                protocol=args.protocol,
                num_seeds=args.num_seeds,
            )

        
        # 2. Standard Mutator Launch (CPU) ==========================================
        print("\n=== STAGE: Launching Primary (CPU) ===")
        primary_handle = run_aflpp(
            binary=binary_path,
            input_dir=args.input,
            output_dir=args.output,
            env=base_env,
            instance_name="primary",
            mutator_so=None, # Standard AFL++ mutator only
            extra_afl_args=args.afl_args or None,
            target_args=args.target_args or None,
        )
        print(f"[*] Primary PID: {primary_handle.pid}")

        # 3. Secondary Mutator Launch (GPU) ==========================================
        secondary_handle = None
        if llm_mutator_so:
            print("\n=== STAGE: Launching Secondary (GPU) ===")
            print("[*] Waiting 5s for primary to initialise queue...")
            time.sleep(5)
            
            # Run afl-fuzz with libdesock + custom mutator
            secondary_handle = run_aflpp(
                binary=binary_path,
                input_dir=args.input, 
                output_dir=args.output,
                env=base_env,
                instance_name="secondary",
                mutator_so=llm_mutator_so,
                extra_afl_args=args.afl_args or None,
                target_args=args.target_args or None,
            )
            print(f"[*] Secondary PID: {secondary_handle.pid}")

        # TODO: After fuzzing completes, we can analyze results, generate reports, etc.
        # TODO: Process cleanup 
        # TODO: Add While loop for user intervention 
        # TODO: Implement GUI 

        # Wait and Cleanup ========================================== 
        print("\n[*] Fuzzing instances running. Press Ctrl+C to stop.")
        try:
            primary_handle.wait()
            if secondary_handle:
                secondary_handle.wait()
        except KeyboardInterrupt:
            print("\n[*] Fuzzing interrupted by user. Shutting down instances...")
        finally:
            if primary_handle.poll() is None:
                primary_handle.terminate()
            if secondary_handle and secondary_handle.poll() is None:
                secondary_handle.terminate()
            
            primary_handle.wait()
            if secondary_handle:
                secondary_handle.wait()
            print("[*] All fuzzing instances cleanly terminated.")

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":  
    main()