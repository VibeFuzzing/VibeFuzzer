# seed_gen.py
# ============================================================================
# LLM SEED GENERATION
# ============================================================================

# Handles all pre-fuzzing seed generation via Ollama.
# Called once per fuzzing session before AFL++ is launched.
#
# Uses the fine-tuned afl-mutator model for both initial seed generation
# and mutation. For initial seeds, we feed the model a protocol example
# formatted as an ancestry chain — the model produces creative mutations
# of that example, giving AFL++ diverse starting seeds.
#
# The wrapper calls generate_llm_seeds() and treats this file as a black box.
# To add a new protocol, add an entry to PROTOCOL_HINTS — nothing else changes.

from pathlib import Path
from typing import Optional, List
import re

import ollama

OLLAMA_BASE_URL = 'http://localhost:11434'
SEED_MODEL      = 'afl-mutator'

# ============================================================================
# PROTOCOL HINTS
# ============================================================================

# Protocol-specific seed templates that get fed to the fine-tuned model
# as ancestry chain inputs. The model mutates these to produce diverse seeds.
# Add new protocols here as needed.
PROTOCOL_HINTS = {
    'FTP': {
        'seeds': [
            'USER anonymous\\r\\nPASS guest@\\r\\nSYST\\r\\nQUIT\\r\\n',
            'USER admin\\r\\nPASS admin\\r\\nPWD\\r\\nLIST\\r\\nQUIT\\r\\n',
            'EHLO localhost\\r\\nHELP\\r\\nSTAT\\r\\nQUIT\\r\\n',
        ],
    },
    'HTTP': {
        'seeds': [
            'GET / HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n',
            'POST /index.html HTTP/1.1\\r\\nHost: localhost\\r\\nContent-Length: 5\\r\\n\\r\\nhello',
            'HEAD / HTTP/1.0\\r\\n\\r\\n',
            'OPTIONS * HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n',
        ],
    },
    'SMTP': {
        'seeds': [
            'EHLO localhost\\r\\nMAIL FROM:<test@test.com>\\r\\nRCPT TO:<user@localhost>\\r\\nDATA\\r\\nSubject: test\\r\\n\\r\\nHello\\r\\n.\\r\\nQUIT\\r\\n',
            'HELO localhost\\r\\nVRFY root\\r\\nQUIT\\r\\n',
        ],
    },
    'RTSP': {
        'seeds': [
            'OPTIONS rtsp://localhost/stream RTSP/1.0\\r\\nCSeq: 1\\r\\n\\r\\n',
            'DESCRIBE rtsp://localhost/stream RTSP/1.0\\r\\nCSeq: 2\\r\\nAccept: application/sdp\\r\\n\\r\\n',
        ],
    },
    'DNS': {
        'seeds': [
            # DNS is binary — provide a minimal query as hex escapes
            '\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01',
        ],
    },
    'SIP': {
        'seeds': [
            'INVITE sip:user@localhost SIP/2.0\\r\\nVia: SIP/2.0/UDP 127.0.0.1:5060\\r\\nFrom: <sip:caller@localhost>;tag=1234\\r\\nTo: <sip:user@localhost>\\r\\nCall-ID: abcd@localhost\\r\\nCSeq: 1 INVITE\\r\\nContent-Length: 0\\r\\n\\r\\n',
            'REGISTER sip:localhost SIP/2.0\\r\\nVia: SIP/2.0/UDP 127.0.0.1:5060\\r\\nTo: <sip:user@localhost>\\r\\nFrom: <sip:user@localhost>;tag=5678\\r\\nCall-ID: reg@localhost\\r\\nCSeq: 1 REGISTER\\r\\n\\r\\n',
        ],
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
                f"Create it with: ollama create {SEED_MODEL} -f Modelfile"
            )
        print(f"[*] Ollama connected. Model '{SEED_MODEL}' available.")
    except ConnectionError:
        raise RuntimeError(
            f"Cannot connect to Ollama at {OLLAMA_BASE_URL}. "
            "Is it running? Start with: ollama serve"
        )


def _build_mutator_prompt(seed_texts: List[str]) -> str:
    """
    Builds a prompt in the format the fine-tuned model was trained on.
    Takes a list of seed texts and formats them as an ancestry chain
    with metadata tags, separated by --- delimiters.
    """
    input_parts = []
    for i, seed_text in enumerate(seed_texts):
        meta = (
            f"[id:{i} "
            f"depth:{i + 1} "
            f"bitmap:{400 + i * 15} "
            f"favored:True "
            f"new_cov:True]"
        )
        input_parts.append(f"{meta}\n{seed_text}")

    return "\n---\n".join(input_parts)


def _clean_mutator_output(raw: str) -> str:
    """
    Cleans output from the fine-tuned mutator model.
    Strips trailing prompt artifacts and converts escape sequences
    back to actual bytes.
    """
    # Strip any trailing prompt artifacts the model generates
    for stop in ['### Input', '#### Input', '<|endoftext|>', '<|endoftext', '---']:
        idx = raw.find(stop)
        if idx != -1:
            raw = raw[:idx]

    result = raw.strip()

    # Convert escape sequences to actual bytes
    result = result.replace('\\r\\n', '\r\n')
    result = result.replace('\\n',    '\n')
    result = result.replace('\\r',    '\r')
    result = result.replace('\\t',    '\t')

    # Convert \xNN hex escapes
    result = re.sub(
        r'\\x([0-9a-fA-F]{2})',
        lambda m: chr(int(m.group(1), 16)),
        result,
    )

    return result


def _get_protocol_seeds(protocol: Optional[str], binary_name: str) -> List[str]:
    """
    Returns seed templates for the given protocol.
    If no protocol is specified, tries to infer from the binary name.
    Falls back to a generic HTTP seed.
    """
    if protocol and protocol.upper() in PROTOCOL_HINTS:
        return PROTOCOL_HINTS[protocol.upper()]['seeds']

    # Try to infer protocol from binary name
    name_lower = binary_name.lower()
    for proto, hints in PROTOCOL_HINTS.items():
        # Match common server binary names to protocols
        if proto.lower() in name_lower:
            print(f"[*] Inferred protocol {proto} from binary name '{binary_name}'")
            return hints['seeds']

    # Common binary name patterns
    http_names = ['nginx', 'apache', 'httpd', 'lighttpd', 'caddy', 'haproxy']
    ftp_names  = ['proftpd', 'vsftpd', 'pureftpd', 'ftpd']
    smtp_names = ['postfix', 'sendmail', 'exim', 'dovecot']

    for name in http_names:
        if name in name_lower:
            print(f"[*] Inferred protocol HTTP from binary name '{binary_name}'")
            return PROTOCOL_HINTS['HTTP']['seeds']
    for name in ftp_names:
        if name in name_lower:
            print(f"[*] Inferred protocol FTP from binary name '{binary_name}'")
            return PROTOCOL_HINTS['FTP']['seeds']
    for name in smtp_names:
        if name in name_lower:
            print(f"[*] Inferred protocol SMTP from binary name '{binary_name}'")
            return PROTOCOL_HINTS['SMTP']['seeds']

    # Default fallback
    print(f"[*] Could not infer protocol from '{binary_name}' — using generic HTTP seeds")
    return PROTOCOL_HINTS['HTTP']['seeds']


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
    Generates initial seed inputs for AFL++ using the fine-tuned afl-mutator model.

    Takes protocol-specific seed templates, feeds them to the model as
    ancestry chains, and collects the mutated outputs as initial seeds.
    This gives AFL++ a diverse starting corpus without requiring a
    separate base model.

    The first few seeds are the raw protocol templates themselves (valid
    baseline seeds), and the rest are LLM-generated mutations of those
    templates.

    Args:
        input_dir:      AFL++ seed corpus directory (created if needed)
        binary_name:    Target binary name — used to infer protocol if not specified
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

    # Get protocol-specific seed templates
    template_seeds = _get_protocol_seeds(protocol, binary_name)
    print(f"[*] Using {len(template_seeds)} protocol template(s) as base seeds")

    generated = 0
    seed_num = start_index

    # ── Write template seeds first (guaranteed valid baselines) ─────────
    print(f"\n[*] Writing {len(template_seeds)} baseline template seeds...")
    for template in template_seeds:
        seed_file = input_path / f"seed_base_{seed_num:04d}"

        if keep_existing and seed_file.exists():
            print(f"    [skip] {seed_file.name} already exists")
            seed_num += 1
            continue

        # Convert escape sequences in template to actual bytes
        content = _clean_mutator_output(template)
        seed_file.write_bytes(content.encode('latin-1', errors='replace'))
        generated += 1

        preview = content[:80].replace('\n', '\\n').replace('\r', '\\r')
        print(f"    [ok] {seed_file.name} ({len(content)} bytes): {preview}...")
        seed_num += 1

    # ── Generate mutations via fine-tuned model ────────────────────────
    mutation_count = max(0, num_seeds - len(template_seeds))
    if mutation_count > 0:
        print(f"\n[*] Generating {mutation_count} mutated seeds with {SEED_MODEL}...")

        for i in range(mutation_count):
            seed_file = input_path / f"seed_mut_{seed_num:04d}"

            if keep_existing and seed_file.exists():
                print(f"    [skip] {seed_file.name} already exists")
                seed_num += 1
                continue

            # Build ancestry chain prompt from template seeds
            prompt = _build_mutator_prompt(template_seeds)

            try:
                # Retry up to 3 times if output is too short
                seed_content = None
                for attempt in range(3):
                    response = ollama.generate(
                        model=SEED_MODEL,
                        prompt=prompt,
                        options={
                            'temperature': 1.0 + (attempt * 0.15),
                            'num_predict': 512,
                            'stop': [
                                '<|endoftext|>',
                                '<|endoftext',
                                '### Input',
                                '#### Input',
                            ],
                        },
                    )
                    candidate = _clean_mutator_output(response.response)

                    if candidate and len(candidate) >= 10:
                        seed_content = candidate
                        break

                if not seed_content:
                    print(f"    [warn] Mutation {seed_num} too short after retries, skipping")
                    seed_num += 1
                    continue

                seed_file.write_bytes(seed_content.encode('latin-1', errors='replace'))
                generated += 1

                preview = seed_content[:80].replace('\n', '\\n').replace('\r', '\\r')
                print(f"    [ok] {seed_file.name} ({len(seed_content)} bytes): {preview}...")

            except Exception as e:
                print(f"    [err] Mutation {seed_num} failed: {e}")

            seed_num += 1

    # Fallback: ensure AFL++ always has at least one seed
    if not list(input_path.glob("seed_*")):
        fallback = input_path / "seed_fallback"
        fallback.write_text("HELP\r\n")
        print(f"    [fallback] No seeds generated — wrote minimal fallback seed")
        generated = 1

    print(f"\n[*] Seed generation complete: {generated} seeds → {input_path}")
    return generated