import shutil
import socket 
import sys
import os
import subprocess
from pathlib import Path
from typing import Optional

import ollama


MODEL = 'llama3:latest'


''' NOTE TO SELF:

* run AFLNet with "afl-fuzz"

* enable core dumping in WSL: 
* ulimit -c unlimited
* echo core | sudo tee /proc/sys/kernel/core_pattern

* could create a target struct that contains all the data from the arguments
* could use argparse for command line arguments

* working command:
* python3 fuzz.py ../proftpd proftpd FTP 21 127.0.0.1 none ./fuzzing_inputs ./fuzzing_output

'''

# ============================================================================
# TARGET BUILDING
# ============================================================================

def setup_environment():
    """
    Prepare compiler and environment for white-box server-side fuzzing
    Ensures AFLNet-capable afl-fuzz is available
    """
    print("[*] Setting up AFL environment variables...")

    # ------------------------------------------------------------------
    # Verify afl-fuzz exists (AFLNet runs via afl-fuzz)
    # ------------------------------------------------------------------
    afl_fuzz_path = shutil.which("afl-fuzz")
    if afl_fuzz_path is None:
        raise EnvironmentError("afl-fuzz not found in PATH.")

    print(f"[*] Found afl-fuzz at: {afl_fuzz_path}")

    # ------------------------------------------------------------------
    # Set AFL / AFLNet environment variables
    # ------------------------------------------------------------------
    env_vars = {
        "CC": "afl-clang-fast",
        "CXX": "afl-clang-fast++",
        "CFLAGS": "-O0 -g",
        "AFLNET": "1",
        "AFL_SKIP_CPUFREQ": "1",
        "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=0"
    }

    for key, value in env_vars.items():
        os.environ[key] = value
        print(f"    {key}={value}")


def build_target(
        source_dir: str, 
        binary_name: str,
        configure_args: Optional[str] = None,
        make_args: Optional[str] = None
    ) -> Path:
    """
    Compile the website/server backend with AFL instrumentation
    Returns the path to the instrumented binary
    """
    
    source_path = Path(source_dir).resolve()

    if not source_path.exists():
        raise FileNotFoundError(f"Source directory not found: {source_path}")
    
    search_paths = [
        source_path / binary_name,
        source_path / "src" / binary_name,
        source_path / "bin" / binary_name,
    ]

    for path in search_paths:
        if path.exists() and path.is_file():
            if verify_instrumentation(path, fatal=False):
                print("[*] Found existing AFL-instrumented binary, skipping build")
                return path.resolve()

    print(f"[*] No existing instrumented binary found, building target...")

    print(f"[*] Building target in {source_path}")
    os.chdir(source_path)

    # Configure
    if Path("./configure").exists():
        print("[*] Running configure...")
        if configure_args:
            cmd = f"./configure {configure_args}"
        else:
            cmd = "./configure"
        subprocess.run(cmd, shell=True, check=True)

    # Clean and build
    print("[*] Cleaning previous build...")
    subprocess.run("make clean", shell=True, check=True)

    print("[*] Compiling with AFL instrumentation...")
    if make_args:
        subprocess.run(f"make {make_args}", shell=True, check=True)
    else:
        subprocess.run("make", shell=True, check=True)

    
    verify_instrumentation(source_path, fatal=True)

    print(f"[*] Binary located at: {source_path}")

    return source_path

def verify_instrumentation(binary_path: Path, fatal: bool = True) -> bool:
    """
    Verify AFL instrumentation
    """
    print("[*] Verifying AFL instrumentation...")
        
    # Check if binary exists
    if not binary_path.exists():
        if fatal:
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        return False

    # Check for AFL instrumentation string
    result = subprocess.run(
        ["strings", str(binary_path)],
        capture_output=True,
        text=True
    )

    # Check output for AFL instrumentation
    if "__AFL_SHM_ID" in result.stdout:
        print("[*] AFL instrumentation verified!")
        return True

    if fatal:
        raise Exception(
            "Binary not instrumented with AFL!\n"
            "Make sure CC and CXX are set to afl-clang-fast before building."
        )

    return False

def check_server_alive(ip: str, port: int, timeout=2):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False

# ============================================================================
# SEED GENERATION
# ============================================================================

def generate_seeds():
    # TODO
    return 

# ============================================================================
# FUZZING ENGINE
# ============================================================================

def run_aflnet(config: str, binary: str, input_dir: str, output_dir: str, protocol: str, ip: str, port: int):
    # Build AFLNet command
    afl_cmd = [
        "afl-fuzz",
        "-E",           # Enable state-aware fuzzing
        "-i", input_dir,
        "-o", output_dir,
        "-N", f"tcp://{ip}/{port}",
        "-P", protocol,
        "-D", "10000",  # Timeout in ms
        "-m", "none",   # No memory limit
        "-t", "10000+", # Execution timeout
        "--",
        binary,
        "-n"
    ]

    # Only add config if provided
    if config is not None:
        afl_cmd.extend(["-c", config])

    print("[*] AFLNet command:")
    print(" ".join(afl_cmd))

    # Run AFLNet
    print("[*] Starting AFLNet fuzzing...")
    try:
        subprocess.run(afl_cmd, check=True)
    except FileNotFoundError:
        print("Error: AFLnet not found. Please install it first.")
        print("Install: sudo apt-get install afl-net (or build from source)")
    except subprocess.CalledProcessError as e:
        print(f"Error running AFLNet: {e}")
        sys.exit(1)

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================


def main():
    """
    Main entry point for AFLNet fuzzing
    """

    # Check minimum arguments
    if len(sys.argv) < 5:
        print("""Usage:
        python3 fuzz.py <target_dir> <binary> <protocol> <port> [config] [input_dir] [output_dir]

        Positional Arguments:
            target_dir   - Path to target server source directory
            binary       - Name of the binary to fuzz
            protocol     - Protocol to fuzz (FTP, HTTP, SMTP, RTSP, DNS, SIP)
            port         - Port number the server runs on
            config       - (Optional) Path to server configuration file
            input_dir    - (Optional) Input seeds directory (default: ./fuzzing_inputs)
            output_dir   - (Optional) Output directory (default: ./fuzzing_output)""")
        sys.exit(1)
    
    # positional args 
    target_dir = sys.argv[1]
    binary_name = sys.argv[2]
    protocol = sys.argv[3]
    port = int(sys.argv[4])
    
    # Optional arguments with defaults
    ip_addr = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] != 'none' else "127.0.0.1"
    config_file = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] != 'none' else None
    input_dir = sys.argv[7] if len(sys.argv) > 7 else './fuzzing_inputs'
    output_dir = sys.argv[8] if len(sys.argv) > 8 else './fuzzing_output'
    
    # Validate protocol
    valid_protocols = ['FTP', 'HTTP', 'SMTP', 'RTSP', 'DNS', 'SIP']
    if protocol.upper() not in valid_protocols:
        print(f"[!] Error: Invalid protocol '{protocol}'")
        print(f"    Valid protocols: {', '.join(valid_protocols)}")
        sys.exit(1)
    
    # Print configuration
    print("[*] Configuration:")
    print(f"    Target directory: {target_dir}")
    print(f"    Binary: {binary_name}")
    print(f"    Protocol: {protocol}")
    print(f"    IP address: {ip_addr}")
    print(f"    Port: {port}")
    print(f"    Config: {config_file if config_file else 'None'}")
    print(f"    Input directory: {input_dir}")
    print(f"    Output directory: {output_dir}")
    print()

    # Main fuzzing workflow
    try:
        if not check_server_alive(ip_addr, port):
            raise RuntimeError(
                f"Target server is not reachable at {ip_addr}:{port}.\n"
                "Start the server before running AFLNet."
            )

        setup_environment() # Setup environment
        binary_path = build_target( # Build target
            source_dir=target_dir,
            binary_name=binary_name,
            configure_args=None,
            make_args=None
        )
 
        # Create initial seed inputs
        Path(input_dir).mkdir(parents=True, exist_ok=True)
        seed_file = Path(input_dir) / 'seed.txt'
        if not seed_file.exists():
            seed_file.write_text('aa %c%c')

        # Start AFLNet fuzzing
        run_aflnet(
            config=config_file,
            binary=str(binary_path),
            input_dir=input_dir,
            output_dir=output_dir,
            protocol=protocol,
            ip=ip_addr,
            port=port
        )

    # Exception handling
    except KeyboardInterrupt:
        print("\n[*] Fuzzing interrupted")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    main()