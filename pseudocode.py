#AFLnet ProFTPd Website Fuzzing – pseudocode



""" Prepare Target """"



def setup_environment():
    """
    Prepare compiler and environment for white-box server-side fuzzing
    """
    set_env("CC", "afl-clang-fast")
    set_env("CXX", "afl-clang-fast++")
    set_env("CFLAGS", "-O0 -g")
    set_env("AFLNET", "1")
    set_env("AFL_SKIP_CPUFREQ", "1")
    set_env("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0")

def build_target(source_dir, configure_args):
    """
    Compile the website/server backend with AFL instrumentation
    """
    cd(source_dir)
    run(f"./configure {configure_args}")
    run("make clean")
    run("make")

    binary = locate_server_binary(source_dir)
    verify_instrumentation(binary)

    return binary

def verify_instrumentation(binary: str):
    """
    Ensure AFL instrumentation exists in the binary
    """
    output = run(f"strings {binary}")
    if "__AFL_SHM_ID" not in output:
        raise Exception("Binary not instrumented – would require QEMU mode")

def start_target(binary: str, config_path: str):
    """
    Launch the instrumented website/backend server
    """
    run([
        binary,
        "-n",
        "-c",
        config_path
    ])



""" Start Fuzzing """"



def run_aflnet(protocol, port, binary: str, config_path: str, input_dir: str, output_dir: str):
    """
    Start AFLNet in server-side fuzzing mode
    """
    afl_fuzz(
        input_dir=input_dir,
        output_dir=output_dir,
        protocol=protocol,
        target_address=f"tcp://127.0.0.1/{port}",
        timeout_ms=10000,
        state_aware=True,
        memory_limit="none",
        target_cmd=[
            binary,
            "-n",
            "-c",
            config_path
        ]
    )

def monitor_fuzzing():
    """
    Observe crashes, coverage, and protocol state transitions
    """
    while afl_running():
        stats = read_afl_stats("output/fuzzer_stats")

        if stats.new_crash_found:
            crash_file = stats.latest_crash
            analyze_crash(crash_file)

def analyze_crash(crash_file):
    """
    Reproduce and triage crashes in the server
    """
    run(f"replay_input_over_network {crash_file}")
    run("gdb ./server_binary")
    classify_bug()

def main(target):
    """
    Generic AFLNet workflow for any website or network service
    """

    check_usage()

    setup_environment()

    binary = build_target(
        source_dir=target.source_dir,
        configure_args=target.configure_args
    )

    prepare_fuzzing_inputs(target.protocol)

    run_aflnet(
        protocol=target.protocol,
        port=target.port,
        binary=binary,
        config_path=target.config_path
    )

if __name__ == '__main__':
    main()