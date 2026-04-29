# palette.py
# ============================================================================
# Single source of truth for all colours, accent tokens, and protocol lists.
# Import from here instead of defining hex strings in multiple files.
# ============================================================================

# ── Background layers ────────────────────────────────────────────────────────
BG_ROOT      = "#06090f"   # near-black navy — window background
BG_FRAME     = "#0b1120"   # deep navy — main frame
BG_CARD      = "#0f1829"   # card / panel background
BG_HEADER    = "#0d1526"   # title bars
BG_ROW_A     = "#111d35"   # table row A
BG_ROW_B     = "#0e1730"   # table row B
BG_TOTALS    = "#13203d"   # totals row
BG_CRASH_BOX = "#110d1a"   # crash textbox (slight purple tint)
BG_META_BOX  = "#0b1120"   # metadata textbox

# ── Accent / semantic colours ────────────────────────────────────────────────
ACCENT       = "#3b82f6"   # vivid blue — primary accent
ACCENT_HOVER = "#2563eb"   # darker blue hover
ACCENT2      = "#60a5fa"   # sky blue — secondary accent
ACCENT_GREEN = "#22d3ee"   # cyan-teal for key numbers
ACCENT_WARN  = "#f59e0b"   # amber — warnings / combined row
ACCENT_ERR   = "#ef4444"   # red — crashes
ACCENT_HANG  = "#f97316"   # orange — hangs
ACCENT_PURP  = "#a78bfa"   # purple — misc stats

# ── Text colours ─────────────────────────────────────────────────────────────
TEXT_MAIN    = "#cbd5e1"   # primary text
TEXT_DIM     = "#64748b"   # dimmed / labels
TEXT_BRIGHT  = "#e2e8f0"   # bright text
TEXT_SUBTLE  = "#94a3b8"   # subtle text

# ── Borders ──────────────────────────────────────────────────────────────────
BORDER       = "#1e3a5f"   # subtle border colour

# ── Chart colour cycle ───────────────────────────────────────────────────────
CHART_COLORS = [ACCENT2, ACCENT, ACCENT_PURP, ACCENT_WARN, ACCENT_GREEN, ACCENT_HANG]

# ── App-level constants ───────────────────────────────────────────────────────
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
