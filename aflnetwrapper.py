import shutil
import socket 
import sys
import os
import subprocess
from pathlib import Path
from typing import Optional

# import ollama


# MODEL = 'llama3:latest'


''' NOTE TO SELF:

* run AFLNet with "afl-fuzz"

* enable core dumping in WSL: 
* ulimit -c unlimited
* echo core | sudo tee /proc/sys/kernel/core_pattern

* TODO could create a target @dataclass and/or @struct that contains all the data from the arguments

* working command:
* python3 fuzz.py ../proftpd proftpd FTP 2121 127.0.0.1 /home/mkotlarz/sd/proftpd/fuzz.conf ./fuzzing_inputs ./fuzzing_output

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

    # Verify afl-fuzz exists (AFLNet runs via afl-fuzz)
    afl_fuzz_path = shutil.which("afl-fuzz")
    if afl_fuzz_path is None:
        raise EnvironmentError("afl-fuzz not found in PATH.")

    print(f"[*] Found afl-fuzz at: {afl_fuzz_path}")

    # Derive AFL installation path from afl-fuzz location and set AFL_PATH
    afl_dir = str(Path(afl_fuzz_path).resolve().parent)

    # Set AFL / AFLNet environment variables
    env_vars = {
        "CC": "afl-clang-fast",
        "CXX": "afl-clang-fast++",
        "CFLAGS": "-O0 -g",
        "AFLNET": "1",
        "AFL_SKIP_CPUFREQ": "1",
        "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=0",
        "AFL_PATH": afl_dir,
    }

    # Export environment variables
    for key, value in env_vars.items():
        os.environ[key] = value
        print(f"    {key}={value}")

    print(f"[*] Set AFL_PATH to: {afl_dir} (helps afl-clang-fast find runtime files)")


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

    # Check source directory exists
    source_path = Path(source_dir).resolve()

    if not source_path.exists():
        raise FileNotFoundError(f"Source directory not found: {source_path}")
    
    # Possible binary locations
    search_paths = [
        source_path / binary_name,
        source_path / "src" / binary_name,
        source_path / "bin" / binary_name,
    ]

    # Check for existing instrumented binary
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
            subprocess.run(f"./configure CC=afl-clang-fast CXX=afl-clang-fast++ {configure_args}", shell=True, check=True)
        else:
            subprocess.run("./configure CC=afl-clang-fast CXX=afl-clang-fast++", shell=True, check=True)

    # Clean and build
    print("[*] Cleaning previous build...")
    subprocess.run("make clean", shell=True, check=True)

    # Build with AFL instrumentation
    print("[*] Compiling with AFL instrumentation...")
    if make_args:
        subprocess.run(f"make {make_args}", shell=True, check=True)
    else:
        subprocess.run("make", shell=True, check=True)

    # Possible binary locations
    search_paths = [
        source_path / binary_name,
        source_path / "src" / binary_name,
        source_path / "bin" / binary_name,
    ]

    # Check for existing instrumented binary
    for path in search_paths:
        if path.exists() and path.is_file():
            if verify_instrumentation(path):
                source_path = path.resolve()
                break
                
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
    # TODO: Check if port is open

    # Check if the server is reachable
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False

# ============================================================================
# LLM INTERACTION
# ============================================================================

def generate_seeds():
    # TODO
    return 

# ============================================================================
# FUZZING ENGINE
# ============================================================================

def run_aflnet(config: str, binary: str, input_dir: str, output_dir: str, protocol: str, ip: str, port: int) -> subprocess.Popen:
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
        "-n"            # TODO: do we need this?
    ]

    # Only add config if provided
    if config is not None:
        afl_cmd.extend(["-c", config])
 
    print("[*] AFLNet command:")
    print(" ".join(afl_cmd))

    # Run AFLNet
    print("[*] Starting AFLNet fuzzing...")
    try:
        # use subprocess.Popen to run afl-fuzz and have a handler to manage it (e.g. for concurrent LLM loop)
        return subprocess.Popen(
            afl_cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
            )
    except FileNotFoundError:
        print("Error: AFLnet not found. Please install it first.")
        print("Install: sudo apt-get install afl-net (or build from source)")
        sys.exit(1)

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================


def main():
    """
    Main entry point for AFLNet fuzzing
    """

    # TODO could use argparse for command line arguments
    # Check minimum arguments
    if len(sys.argv) < 5:
        print("""Usage:
        python3 fuzz.py <target_dir> <binary> <protocol> <port> <ip_addr> [config] [input_dir] [output_dir]

        Positional Arguments:
            target_dir   - Path to target server source directory
            binary       - Name of the binary to fuzz
            protocol     - Protocol to fuzz (FTP, HTTP, SMTP, RTSP, DNS, SIP)
            port         - Port number the server runs on
            ip_addr      - (Optional) IP address of the server (default:
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
    # TODO add optional arguments to configure and make for more complex builds
    # TODO check if config file is valid
    # TODO check if input and output directories are valid (or create them)
    
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
            # TODO add optional arguments to configure and make for more complex builds
            configure_args=None,
            make_args=None
        )
 
        # Create initial seed inputs
        # TODO generate seeds 
        Path(input_dir).mkdir(parents=True, exist_ok=True)
        seed_file = Path(input_dir) / 'seed.txt'
        if not seed_file.exists():
            seed_file.write_text('aa %c%c')

        # Start AFLNet fuzzing
        aflnet_handle = run_aflnet(
            config=config_file,
            binary=str(binary_path),
            input_dir=input_dir,
            output_dir=output_dir,
            protocol=protocol,
            ip=ip_addr,
            port=port
        )

        # TODO: run LLM in concurrent loop (for now we just run AFLNet on its own)
        aflnet_handle.wait()

        # TODO: After fuzzing completes, we can analyze results, generate reports, etc.
        # TODO: Process cleanup 
        # TODO: Add While loop for user intervention 

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