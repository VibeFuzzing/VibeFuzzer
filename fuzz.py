import sys
import ollama
import os
import subprocess
from pathlib import Path
import shutil
import json

MODEL = 'llama3:latest'

# run AFLNet with "afl-fuzz"

# enable core dumping in WSL: 
# ulimit -c unlimited
# echo core | sudo tee /proc/sys/kernel/core_pattern

# almost working command: ./afl-fuzz -d -i seeds -o out -N tcp://127.0.0.1/9999 -P FTP -D 10000 -q 3 -s 3 -E -- ../vulnserver/vulnserver.exe








def compile_target(target_dir: Path, target_name: str) -> Path:
    target_exe = target_dir / target_name

    if not target_exe.exists():
        subprocess.run(
            [
                "gcc", "-o", str(target_exe), str(target_dir / (target_name + ".c")), "-fsanitize=address,fuzzer",
            ],
            check=True
        )
    return target_exe


def run_aflnet(target_binary: str, input_dir: str, output_dir: str):
    cmd = [
        'afl-fuzz',
        '-i', input_dir,      # input corpus directory
        '-o', output_dir,     # output directory
        '-P', 'POC',          # protocol (POC for generic, or LDP, DNS, SMTP, etc.)
        '-D', '5000',         # durations in ms (optional)
        target_binary         # target binary
    ]

    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print("Error: AFLnet not found. Please install it first.")
        print("Install: sudo apt-get install afl-net (or build from source)")
    except subprocess.CalledProcessError as e:
        print(f"Error running AFLNet: {e}")
        sys.exit(1)


def main():
    
    if len(sys.argv) < 2:
        print("Usage: python fuzz.py [target]")
        sys.exit(1)

    target = sys.argv[1]

    target_exe = compile_target(Path('.'), target)

    # Create input and output directories
    input_dir = Path('corpus')
    output_dir = Path('fuzzing_results')
    
    input_dir.mkdir(exist_ok=True)
    output_dir.mkdir(exist_ok=True)
    
    # Create initial seed inputs
    seed_file = input_dir / 'seed.txt'
    if not seed_file.exists():
        seed_file.write_text('aa %c%c')
    
    # Run AFLnet
    run_aflnet(str(target_exe), str(input_dir), str(output_dir))



if __name__ == '__main__':
    main()