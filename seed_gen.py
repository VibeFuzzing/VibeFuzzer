# seed_gen.py
# ============================================================================
# LLM SEED GENERATION
# ============================================================================

# Handles all pre-fuzzing seed generation via Ollama.
# Called once per fuzzing session before AFL++ is launched.

# The wrapper calls generate_llm_seeds() and treats this file as a black box.
# To add a new protocol, add an entry to PROTOCOL_HINTS — nothing else changes.

from pathlib import Path
from typing import Optional

import ollama

OLLAMA_BASE_URL = 'http://localhost:11434'
SEED_MODEL      = 'afl-mutator'

# ============================================================================
# PROTOCOL HINTS
# ============================================================================

# Protocol-specific context that helps the LLM generate better seeds.
# Each entry provides an example session and structural notes for the prompt.
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


# ============================================================================
# INTERNAL HELPERS
# ============================================================================

def _verify_ollama_connection() -> None:
    """
    Checks that Ollama is running and SEED_MODEL is available.
    Raises RuntimeError with a helpful message if not.
    """
    try:
        models = ollama.list()
        model_names = [m.model for m in models.models]
        if not any(SEED_MODEL in name for name in model_names):
            available = ", ".join(model_names) if model_names else "none"
            raise RuntimeError(
                f"Model '{SEED_MODEL}' not found in Ollama.\n"
                f"Available: {available}\n"
                f"Pull it with: ollama pull {SEED_MODEL}"
            )
        print(f"[*] Ollama connected. Model '{SEED_MODEL}' available.")
    except Exception as e:
        raise RuntimeError(
            f"Cannot connect to Ollama at {OLLAMA_BASE_URL}. "
            "Is it running? Start with: ollama serve"
        )


def _build_seed_prompt(protocol: Optional[str], binary_name: str, seed_index: int, total_seeds: int) -> str:
    """
    Builds a prompt for the LLM to generate a single fuzz seed.
    If protocol is provided (and known), includes protocol-specific context.
    Otherwise, asks the LLM to infer from the binary name.
    """
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


def __clean_llm_output(raw: str) -> str:
    """
    Strips LLM commentary and artifacts from generated seed content.
    The LLM sometimes adds explanatory notes, markdown formatting, or
    other text that would corrupt the seed if written to disk.
    Also converts literal escape sequences (e.g. the text \r\n) into
    actual bytes, since the LLM often reproduces escape sequences as text.
    """
    lines   = raw.split('\n')
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
    result = result.replace('\\n',    '\n')
    result = result.replace('\\r',    '\r')
    result = result.replace('\\t',    '\t')
    result = result.replace('\\x00',  '\x00')
    result = result.replace('\\0',    '\x00')

    return result


# ============================================================================
# PUBLIC API
# ============================================================================

def generate_llm_seeds(
    input_dir: str,
    binary_name: str,
    protocol: Optional[str] = None,
    num_seeds: int = 10,
    keep_existing: bool = True,
) -> int:
    """
    Generates initial seed inputs for AFL++ using Llama via Ollama.
    Seeds are written to input_dir as individual files.

    Args:
        input_dir:      AFL++ seed corpus directory (created if needed)
        binary_name:    Target binary name — used in prompt if protocol is unknown
        protocol:       Optional protocol hint (FTP, HTTP, SMTP, etc.)
        num_seeds:      How many seeds to generate
        keep_existing:  If True, skip generation if seeds already exist

    Returns:
        Number of seeds successfully written
    """
    input_path = Path(input_dir)
    input_path.mkdir(parents=True, exist_ok=True)

    existing = list(input_path.glob("seed_*"))
    if keep_existing and existing:
        print(f"[*] {len(existing)} existing seeds found, keeping them.")
        print(f"[*] Generating {num_seeds} additional seeds...")
        start_index = len(existing)
    else:
        start_index = 0

    _verify_ollama_connection()

    print(f"[*] Generating {num_seeds} seeds with {SEED_MODEL}...")
    if protocol:
        print(f"[*] Protocol hint: {protocol}")
    else:
        print(f"[*] No protocol specified — inferring from binary name '{binary_name}'")

    generated = 0

    for i in range(num_seeds):
        seed_num  = start_index + i
        seed_file = input_path / f"seed_llm_{seed_num:04d}"

        if keep_existing and seed_file.exists():
            print(f"    [skip] {seed_file.name} already exists")
            continue

        prompt = _build_seed_prompt(
            protocol=protocol,
            binary_name=binary_name,
            seed_index=i,
            total_seeds=num_seeds,
        )

        print(f"[*] Generating seed {seed_num}... (waiting for LLM response)")

        try:
            response = ollama.generate(
                model=SEED_MODEL,
                prompt=prompt,
                options={'temperature': 0.9, 'num_predict': 512, 'top_p': 0.95},
            )
            seed_content = __clean_llm_output(response.response.strip())

            if not seed_content:
                print(f"    [warn] Seed {seed_num} was empty, skipping")
                continue

            # latin-1 encoding preserves raw bytes including null bytes
            seed_file.write_bytes(seed_content.encode('latin-1'))
            generated += 1

            preview = seed_content[:80].replace('\n', '\\n').replace('\r', '\\r')
            print(f"    [ok] {seed_file.name} ({len(seed_content)} bytes): {preview}...")

        except Exception as e:
            print(f"    [err] Seed {seed_num} failed: {e}")
            continue

    # Fallback: ensure AFL++ always has at least one seed to start from
    if not list(input_path.glob("seed_*")):
        fallback = input_path / "seed_fallback"
        fallback.write_text("HELP\r\n")
        print(f"    [fallback] No seeds generated — wrote minimal fallback seed")
        generated = 1

    print(f"[*] Seed generation complete: {generated}/{num_seeds} seeds → {input_path}")
    return generated