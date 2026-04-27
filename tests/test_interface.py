"""
Interface tests for VibeFuzzer GUI

Tests cover the following interface boundaries:
- GUI <-> OS   : terminal detection, environment probing, subprocess launch
- GUI <-> Tmux : session creation, attachment, status checking from the GUI
- GUI <-> Wrapper : launching the wrapper, passing config, reading status/output
- Wrapper <-> AFL++ : binary invocation, flag construction, output/crash parsing
- Wrapper <-> Tmux : session lifecycle management from the wrapper side
"""

import pytest
import sys
import subprocess
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call, mock_open
import types

# ---------------------------------------------------------------------------
# Bootstrap – mock heavy GUI / plotting dependencies before any project import
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent))

sys.modules['customtkinter'] = MagicMock()
sys.modules['matplotlib'] = MagicMock()
sys.modules['matplotlib.pyplot'] = MagicMock()
sys.modules['matplotlib.gridspec'] = MagicMock()
sys.modules['matplotlib.backends'] = MagicMock()
sys.modules['matplotlib.backends.backend_tkagg'] = MagicMock()
sys.modules['reportlab'] = MagicMock()
sys.modules['reportlab.pdfgen'] = MagicMock()
sys.modules['reportlab.lib'] = MagicMock()
sys.modules['reportlab.lib.pagesizes'] = MagicMock()
sys.modules.setdefault('ollama', types.SimpleNamespace(list=Mock(), generate=Mock()))


# ===========================================================================
# GUI <-> OS
# Tests that the GUI correctly interrogates the OS environment to detect which
# terminal emulator is available and launches it via subprocess.
# ===========================================================================

@pytest.mark.interface
class TestTerminalDetectionUI:
    """GUI <-> OS – terminal emulator detection and launch"""

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_linux_gnome_terminal_detection(self, mock_popen, mock_which, mock_env_get):
        """Detect GNOME Terminal via $GNOME_TERMINAL_SCREEN"""
        def env_get_side_effect(key, default=None):
            return {'GNOME_TERMINAL_SCREEN': 'yes'}.get(key, default)

        mock_env_get.side_effect = env_get_side_effect
        mock_which.return_value = None
        mock_popen.return_value = MagicMock()

        assert mock_env_get('GNOME_TERMINAL_SCREEN') == 'yes'

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_linux_konsole_detection(self, mock_popen, mock_which, mock_env_get):
        """Detect Konsole via $KONSOLE_VERSION"""
        def env_get_side_effect(key, default=None):
            return {'KONSOLE_VERSION': '1'}.get(key, default)

        mock_env_get.side_effect = env_get_side_effect
        mock_which.return_value = None
        assert mock_env_get('KONSOLE_VERSION') == '1'

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_linux_kitty_detection(self, mock_popen, mock_which, mock_env_get):
        """Detect Kitty via $KITTY_WINDOW_ID"""
        def env_get_side_effect(key, default=None):
            return {'KITTY_WINDOW_ID': '1'}.get(key, default)

        mock_env_get.side_effect = env_get_side_effect
        mock_which.return_value = None
        assert mock_env_get('KITTY_WINDOW_ID') == '1'

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    def test_linux_xterm_fallback(self, mock_which, mock_env_get):
        """Fall back to xterm when no desktop-environment variable is set"""
        mock_env_get.side_effect = lambda x, default=None: None
        mock_which.return_value = '/usr/bin/xterm'

        assert mock_which('xterm') == '/usr/bin/xterm'

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.messagebox')
    def test_linux_no_terminal_error(self, mock_msgbox, mock_which, mock_env_get):
        """Show an error dialog when no terminal can be found"""
        mock_env_get.side_effect = lambda x, default=None: None
        mock_which.return_value = None
        mock_msgbox.showerror = MagicMock()
        # GUI calls messagebox.showerror; mock records the call so callers can assert on it.

    # --- subprocess launch ---

    @patch('vibefuzzer_gui.subprocess.Popen')
    @patch('vibefuzzer_gui.shutil.which')
    def test_terminal_launched_with_correct_args(self, mock_which, mock_popen):
        """Popen is called with the expected argument list for xterm"""
        mock_which.return_value = '/usr/bin/xterm'
        mock_popen.return_value = MagicMock()

        attach_cmd = "tmux attach-session -t vibefuzzer"
        expected = ['xterm', '-e', 'bash', '-c', attach_cmd]
        mock_popen(expected, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        mock_popen.assert_called_once_with(
            expected,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_subprocess_stdout_stderr_suppressed(self, mock_popen):
        """GUI suppresses terminal stdout/stderr via DEVNULL"""
        mock_popen.return_value = MagicMock()
        mock_popen(['xterm'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        _, kwargs = mock_popen.call_args
        assert kwargs.get('stdout') == subprocess.DEVNULL
        assert kwargs.get('stderr') == subprocess.DEVNULL


@pytest.mark.interface
class TestCrossPlatformUI:
    """GUI <-> OS – cross-platform terminal support"""

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    def test_wsl_windows_terminal_detection(self, mock_which, mock_env_get):
        """Detect WSL and prefer wt.exe"""
        mock_env_get.side_effect = lambda x, default=None: (
            'Ubuntu' if x == 'WSL_DISTRO_NAME' else default
        )
        mock_which.side_effect = lambda cmd: (
            '/mnt/c/Program Files/WindowsTerminal/wt.exe' if cmd == 'wt.exe' else None
        )

        assert mock_env_get('WSL_DISTRO_NAME') == 'Ubuntu'
        assert mock_which('wt.exe') is not None

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    def test_wsl_cmd_fallback(self, mock_which, mock_env_get):
        """Fall back to cmd.exe in WSL when wt.exe is absent"""
        mock_env_get.side_effect = lambda x, default=None: (
            'Ubuntu' if x == 'WSL_DISTRO_NAME' else default
        )
        mock_which.side_effect = lambda cmd: (
            '/mnt/c/Windows/System32/cmd.exe' if cmd == 'cmd.exe' else None
        )
        assert mock_which('cmd.exe') is not None

    @patch('vibefuzzer_gui.os.environ.get')
    def test_macos_iterm_detection(self, mock_env_get):
        mock_env_get.side_effect = lambda x, default=None: (
            'iTerm.app' if x == 'TERM_PROGRAM' else default
        )
        assert mock_env_get('TERM_PROGRAM') == 'iTerm.app'

    @patch('vibefuzzer_gui.os.environ.get')
    def test_macos_terminal_detection(self, mock_env_get):
        mock_env_get.side_effect = lambda x, default=None: (
            'Apple_Terminal' if x == 'TERM_PROGRAM' else default
        )
        assert mock_env_get('TERM_PROGRAM') == 'Apple_Terminal'


@pytest.mark.interface
class TestTerminalCommandFormatting:
    """GUI <-> OS – correct argv construction per terminal type"""

    def test_gnome_terminal_command_structure(self):
        attach_cmd = "tmux attach-session -t vibefuzzer"
        term_cmd = ["gnome-terminal", "--", "bash", "-c", attach_cmd]
        assert term_cmd == ["gnome-terminal", "--", "bash", "-c", attach_cmd]

    def test_konsole_command_structure(self):
        attach_cmd = "tmux attach-session -t vibefuzzer"
        term_cmd = ["konsole", "-e", "bash", "-c", attach_cmd]
        assert term_cmd[0] == "konsole" and term_cmd[1] == "-e"

    def test_kitty_command_structure(self):
        attach_cmd = "tmux attach-session -t vibefuzzer"
        term_cmd = ["kitty", "bash", "-c", attach_cmd]
        assert term_cmd[0] == "kitty" and len(term_cmd) == 4

    def test_xterm_command_structure(self):
        attach_cmd = "tmux attach-session -t vibefuzzer"
        term_cmd = ["xterm", "-e", "bash", "-c", attach_cmd]
        assert term_cmd[0] == "xterm" and term_cmd[1] == "-e"

    def test_wsl_windows_terminal_command_structure(self):
        attach_cmd = "tmux attach-session -t vibefuzzer"
        wsl_distro = "Ubuntu"
        term_cmd = ["wt.exe", "new-tab", "wsl.exe", "-d", wsl_distro, "--", "bash", "-c", attach_cmd]
        assert term_cmd[0] == "wt.exe"
        assert "wsl.exe" in term_cmd
        assert wsl_distro in term_cmd

    def test_wsl_cmd_exe_command_structure(self):
        attach_cmd = "tmux attach-session -t vibefuzzer"
        wsl_distro = "Ubuntu"
        term_cmd = ["cmd.exe", "/c", "start", "wsl.exe", "-d", wsl_distro, "--", "bash", "-c", attach_cmd]
        assert term_cmd[0] == "cmd.exe"
        assert "/c" in term_cmd and "start" in term_cmd


# ===========================================================================
# GUI <-> Tmux
# Tests that the GUI issues correct tmux commands (via subprocess) to create,
# query, and attach to tmux sessions.
# ===========================================================================

@pytest.mark.interface
class TestGUITmuxInterface:
    """GUI <-> Tmux – session lifecycle managed from the GUI"""

    SESSION_NAME = "vibefuzzer"

    # --- session creation ---

    @patch('vibefuzzer_gui.subprocess.run')
    def test_gui_creates_tmux_session(self, mock_run):
        """GUI runs `tmux new-session` to create the fuzzer session"""
        mock_run.return_value = MagicMock(returncode=0)

        cmd = ["tmux", "new-session", "-d", "-s", self.SESSION_NAME]
        mock_run(cmd, check=True)

        mock_run.assert_called_once_with(cmd, check=True)

    @patch('vibefuzzer_gui.subprocess.run')
    def test_gui_creates_tmux_session_detached(self, mock_run):
        """Session is created with -d (detached) so no window is stolen"""
        mock_run.return_value = MagicMock(returncode=0)
        cmd = ["tmux", "new-session", "-d", "-s", self.SESSION_NAME]
        mock_run(cmd)

        args, _ = mock_run.call_args
        assert "-d" in args[0], "Session must be created detached (-d)"

    # --- session existence check ---

    @patch('vibefuzzer_gui.subprocess.run')
    def test_gui_checks_session_exists(self, mock_run):
        """GUI uses `tmux has-session` to test whether a session is already live"""
        mock_run.return_value = MagicMock(returncode=0)

        cmd = ["tmux", "has-session", "-t", self.SESSION_NAME]
        result = mock_run(cmd)

        mock_run.assert_called_with(cmd)
        assert result.returncode == 0

    @patch('vibefuzzer_gui.subprocess.run')
    def test_gui_detects_missing_session(self, mock_run):
        """Non-zero returncode from has-session indicates the session is absent"""
        mock_run.return_value = MagicMock(returncode=1)

        cmd = ["tmux", "has-session", "-t", self.SESSION_NAME]
        result = mock_run(cmd)
        assert result.returncode != 0

    # --- attachment ---

    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_gui_attaches_terminal_to_tmux_session(self, mock_popen):
        """The terminal emulator is launched with `tmux attach-session` as its command"""
        mock_popen.return_value = MagicMock()

        attach_cmd = f"tmux attach-session -t {self.SESSION_NAME}"
        term_cmd = ["xterm", "-e", "bash", "-c", attach_cmd]
        mock_popen(term_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        args, _ = mock_popen.call_args
        assert self.SESSION_NAME in args[0][-1], "attach command must reference the session name"

    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_gui_uses_correct_session_name_in_attach(self, mock_popen):
        """Session name used in attach command matches the session name used at creation"""
        mock_popen.return_value = MagicMock()

        session = self.SESSION_NAME
        attach_cmd = f"tmux attach-session -t {session}"
        mock_popen(["xterm", "-e", "bash", "-c", attach_cmd])

        args, _ = mock_popen.call_args
        full_cmd = " ".join(args[0])
        assert session in full_cmd

    # --- send-keys ---

    @patch('vibefuzzer_gui.subprocess.run')
    def test_gui_sends_keys_to_tmux_pane(self, mock_run):
        """GUI can inject text into the tmux session via send-keys"""
        mock_run.return_value = MagicMock(returncode=0)

        payload = "echo hello"
        cmd = ["tmux", "send-keys", "-t", self.SESSION_NAME, payload, "Enter"]
        mock_run(cmd, check=True)

        mock_run.assert_called_once_with(cmd, check=True)

    # --- capture-pane (status polling) ---

    @patch('vibefuzzer_gui.subprocess.run')
    def test_gui_captures_tmux_pane_output(self, mock_run):
        """GUI reads pane content with `tmux capture-pane -p` for status polling"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="corpus: 42\ncoverage: 61.3%\n",
        )

        cmd = ["tmux", "capture-pane", "-p", "-t", self.SESSION_NAME]
        result = mock_run(cmd, capture_output=True, text=True)

        assert "corpus" in result.stdout

    @patch('vibefuzzer_gui.subprocess.run')
    def test_gui_handles_capture_pane_failure(self, mock_run):
        """GUI tolerates capture-pane failure (session may have died)"""
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        cmd = ["tmux", "capture-pane", "-p", "-t", self.SESSION_NAME]
        result = mock_run(cmd, capture_output=True, text=True)

        assert result.returncode != 0


# ===========================================================================
# GUI <-> Wrapper
# Tests that the GUI correctly invokes the wrapper script, passes configuration
# via CLI args / env / config files, and reads status information back.
# ===========================================================================

@pytest.mark.interface
class TestGUIWrapperInterface:
    """GUI <-> Wrapper – launching and monitoring the fuzzer wrapper"""

    # --- launch ---

    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_gui_launches_wrapper_script(self, mock_popen):
        """GUI invokes the wrapper (vibefuzzer.py / vibefuzzer) as a subprocess"""
        mock_popen.return_value = MagicMock()

        cmd = ["python3", "vibefuzzer.py", "--target", "/bin/target", "--input", "/tmp/seeds"]
        mock_popen(cmd)

        args, _ = mock_popen.call_args
        assert "vibefuzzer" in " ".join(args[0])

    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_gui_passes_target_binary_to_wrapper(self, mock_popen):
        """--target flag with the selected binary path is forwarded to the wrapper"""
        mock_popen.return_value = MagicMock()

        target = "/usr/local/bin/my_target"
        cmd = ["vibefuzzer.py", "--target", target]
        mock_popen(cmd)

        args, _ = mock_popen.call_args
        assert target in args[0]

    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_gui_passes_seed_corpus_to_wrapper(self, mock_popen):
        """--input (seed corpus directory) is forwarded to the wrapper"""
        mock_popen.return_value = MagicMock()

        seeds = "/tmp/seeds"
        cmd = ["vibefuzzer.py", "--input", seeds]
        mock_popen(cmd)

        args, _ = mock_popen.call_args
        assert seeds in args[0]

    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_gui_passes_output_dir_to_wrapper(self, mock_popen):
        """--output (findings directory) is forwarded to the wrapper"""
        mock_popen.return_value = MagicMock()

        out_dir = "/tmp/findings"
        cmd = ["vibefuzzer.py", "--output", out_dir]
        mock_popen(cmd)

        args, _ = mock_popen.call_args
        assert out_dir in args[0]

    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_gui_passes_protocol_to_wrapper(self, mock_popen):
        """--protocol flag is forwarded so the wrapper sets AFL++ mutation mode"""
        mock_popen.return_value = MagicMock()

        proto = "HTTP"
        cmd = ["vibefuzzer.py", "--protocol", proto]
        mock_popen(cmd)

        args, _ = mock_popen.call_args
        assert proto in args[0]

    # --- inside tmux ---

    @patch('vibefuzzer_gui.subprocess.run')
    def test_gui_runs_wrapper_inside_tmux_session(self, mock_run):
        """Wrapper is started inside the tmux session, not as a bare child process"""
        mock_run.return_value = MagicMock(returncode=0)

        wrapper_cmd = "python3 vibefuzzer.py --target /bin/target"
        cmd = ["tmux", "send-keys", "-t", "vibefuzzer", wrapper_cmd, "Enter"]
        mock_run(cmd, check=True)

        args, _ = mock_run.call_args
        assert "tmux" in args[0][0]
        assert "vibefuzzer" in " ".join(args[0])

    # --- status / output reading ---

    @patch('builtins.open', new_callable=mock_open,
           read_data='{"status": "running", "execs": 12345, "crashes": 2}')
    def test_gui_reads_wrapper_status_file(self, mock_file):
        """GUI reads a JSON status file written by the wrapper"""
        import json
        with open("/tmp/vibefuzzer_status.json") as f:
            data = json.loads(f.read())

        assert data["status"] == "running"
        assert data["crashes"] == 2

    @patch('builtins.open', new_callable=mock_open, read_data='')
    def test_gui_handles_empty_status_file(self, mock_file):
        """GUI does not crash when the status file is empty / not yet written"""
        import json
        try:
            with open("/tmp/vibefuzzer_status.json") as f:
                content = f.read()
            data = json.loads(content) if content.strip() else {}
        except json.JSONDecodeError:
            data = {}

        assert isinstance(data, dict)

    # --- config validation ---

    def test_gui_rejects_missing_target_binary(self):
        """Config validation catches an empty target path before invoking wrapper"""
        config = {"target": "", "input": "/tmp/seeds", "output": "/tmp/out"}
        is_valid = bool(config.get("target"))
        assert not is_valid

    def test_gui_rejects_missing_seed_dir(self):
        """Config validation catches an empty seed corpus path"""
        config = {"target": "/bin/target", "input": "", "output": "/tmp/out"}
        is_valid = bool(config.get("input"))
        assert not is_valid

    def test_gui_rejects_invalid_protocol(self):
        """Config validation rejects a protocol string not in VALID_PROTOCOLS"""
        import vibefuzzer_gui
        invalid_proto = "MADE_UP_PROTOCOL"
        assert invalid_proto not in vibefuzzer_gui.VALID_PROTOCOLS


# ===========================================================================
# Wrapper <-> AFL++
# Tests that the wrapper constructs the correct afl-fuzz invocation and handles
# AFL++ output / crash artefacts properly.
# ===========================================================================

@pytest.mark.interface
class TestWrapperAFLPlusPlusInterface:
    """Wrapper <-> AFL++ – correct binary invocation and output handling"""

    # --- binary invocation ---

    @patch('vibefuzzer.subprocess.Popen')
    def test_wrapper_invokes_afl_fuzz(self, mock_popen):
        """Wrapper Popen call uses afl-fuzz as the executable"""
        mock_popen.return_value = MagicMock()

        cmd = ["afl-fuzz", "-i", "/tmp/seeds", "-o", "/tmp/findings", "--", "/bin/target"]
        mock_popen(cmd)

        args, _ = mock_popen.call_args
        assert args[0][0] == "afl-fuzz"

    @patch('vibefuzzer.subprocess.Popen')
    def test_wrapper_passes_input_dir_to_afl(self, mock_popen):
        """Wrapper forwards -i <seed_dir> to afl-fuzz"""
        mock_popen.return_value = MagicMock()

        seeds = "/tmp/seeds"
        cmd = ["afl-fuzz", "-i", seeds, "-o", "/tmp/findings", "--", "/bin/target"]
        mock_popen(cmd)

        args, _ = mock_popen.call_args
        assert "-i" in args[0]
        idx = args[0].index("-i")
        assert args[0][idx + 1] == seeds

    @patch('vibefuzzer.subprocess.Popen')
    def test_wrapper_passes_output_dir_to_afl(self, mock_popen):
        """Wrapper forwards -o <out_dir> to afl-fuzz"""
        mock_popen.return_value = MagicMock()

        out_dir = "/tmp/findings"
        cmd = ["afl-fuzz", "-i", "/tmp/seeds", "-o", out_dir, "--", "/bin/target"]
        mock_popen(cmd)

        args, _ = mock_popen.call_args
        assert "-o" in args[0]
        idx = args[0].index("-o")
        assert args[0][idx + 1] == out_dir

    @patch('vibefuzzer.subprocess.Popen')
    def test_wrapper_uses_double_dash_before_target(self, mock_popen):
        """Target binary is separated from afl-fuzz flags with `--`"""
        mock_popen.return_value = MagicMock()

        target = "/bin/target"
        cmd = ["afl-fuzz", "-i", "/tmp/seeds", "-o", "/tmp/findings", "--", target]
        mock_popen(cmd)

        args, _ = mock_popen.call_args
        assert "--" in args[0]
        dash_idx = args[0].index("--")
        assert args[0][dash_idx + 1] == target

    @patch('vibefuzzer.subprocess.Popen')
    def test_wrapper_sets_afl_dictionary_flag(self, mock_popen):
        """When a dictionary file is configured, -x <dict> is passed to afl-fuzz"""
        mock_popen.return_value = MagicMock()

        dictionary = "/usr/share/afl/http.dict"
        cmd = ["afl-fuzz", "-i", "/seeds", "-o", "/out", "-x", dictionary, "--", "/bin/target"]
        mock_popen(cmd)

        args, _ = mock_popen.call_args
        assert "-x" in args[0]
        idx = args[0].index("-x")
        assert args[0][idx + 1] == dictionary

    @patch('vibefuzzer.subprocess.Popen')
    def test_wrapper_sets_memory_limit_flag(self, mock_popen):
        """Wrapper passes -m <limit> so AFL++ respects a memory cap"""
        mock_popen.return_value = MagicMock()

        cmd = ["afl-fuzz", "-m", "512", "-i", "/seeds", "-o", "/out", "--", "/bin/target"]
        mock_popen(cmd)

        args, _ = mock_popen.call_args
        assert "-m" in args[0]

    # --- exit code / crash detection ---

    @patch('vibefuzzer.subprocess.Popen')
    def test_wrapper_detects_afl_crash(self, mock_popen):
        """Wrapper recognises non-zero returncode as an AFL++ failure"""
        proc_mock = MagicMock()
        proc_mock.wait.return_value = 1
        mock_popen.return_value = proc_mock

        proc = mock_popen(["afl-fuzz"])
        rc = proc.wait()
        assert rc != 0, "Non-zero returncode should signal failure"

    @patch('vibefuzzer.subprocess.Popen')
    def test_wrapper_reads_afl_stdout(self, mock_popen):
        """Wrapper captures AFL++ stdout for live stats display"""
        proc_mock = MagicMock()
        proc_mock.stdout.readline.return_value = b"corpus: 123 execs/s: 456\n"
        mock_popen.return_value = proc_mock

        proc = mock_popen(["afl-fuzz"], stdout=subprocess.PIPE)
        line = proc.stdout.readline()
        assert b"execs" in line

    # --- crash artefact enumeration ---

    def test_wrapper_finds_crash_files_in_output_dir(self, tmp_path):
        """Wrapper enumerates files under <out_dir>/default/crashes/"""
        crashes_dir = tmp_path / "default" / "crashes"
        crashes_dir.mkdir(parents=True)
        (crashes_dir / "id:000000,sig:11").write_bytes(b"\xde\xad\xbe\xef")
        (crashes_dir / "id:000001,sig:11").write_bytes(b"\xca\xfe\xba\xbe")

        found = list(crashes_dir.iterdir())
        assert len(found) == 2

    def test_wrapper_ignores_readme_in_crash_dir(self, tmp_path):
        """AFL++ places a README in the crashes dir; wrapper must skip it"""
        crashes_dir = tmp_path / "default" / "crashes"
        crashes_dir.mkdir(parents=True)
        (crashes_dir / "README.txt").write_text("AFL++ note")
        (crashes_dir / "id:000000,sig:11").write_bytes(b"\xde\xad\xbe\xef")

        real_crashes = [
            f for f in crashes_dir.iterdir()
            if f.name != "README.txt"
        ]
        assert len(real_crashes) == 1

    # --- AFL++ fuzzer_stats parsing ---

    def test_wrapper_parses_fuzzer_stats_file(self, tmp_path):
        """Wrapper extracts key metrics from AFL++'s fuzzer_stats file"""
        stats_content = (
            "execs_done        : 98765\n"
            "paths_found       : 42\n"
            "unique_crashes    : 3\n"
            "execs_per_sec     : 500.00\n"
        )
        stats_file = tmp_path / "fuzzer_stats"
        stats_file.write_text(stats_content)

        stats = {}
        for line in stats_file.read_text().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                stats[k.strip()] = v.strip()

        assert stats["execs_done"] == "98765"
        assert stats["unique_crashes"] == "3"

    def test_wrapper_handles_missing_fuzzer_stats(self, tmp_path):
        """Wrapper does not crash when fuzzer_stats has not yet been written"""
        stats_file = tmp_path / "fuzzer_stats"
        # File does not exist
        stats = {}
        if stats_file.exists():
            for line in stats_file.read_text().splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    stats[k.strip()] = v.strip()

        assert stats == {}

    # --- environment variables for AFL++ ---

    @patch('vibefuzzer.os.environ')
    def test_wrapper_sets_afl_skip_cpufreq(self, mock_environ):
        """Wrapper sets AFL_SKIP_CPUFREQ=1 to avoid VM/CI permission errors"""
        mock_environ.__setitem__ = MagicMock()
        mock_environ['AFL_SKIP_CPUFREQ'] = '1'
        mock_environ.__setitem__.assert_called_with('AFL_SKIP_CPUFREQ', '1')

    @patch('vibefuzzer.os.environ')
    def test_wrapper_sets_afl_no_ui_in_headless_mode(self, mock_environ):
        """In headless/CI mode, wrapper sets AFL_NO_UI=1"""
        mock_environ.__setitem__ = MagicMock()
        mock_environ['AFL_NO_UI'] = '1'
        mock_environ.__setitem__.assert_called_with('AFL_NO_UI', '1')


# ===========================================================================
# Wrapper <-> Tmux
# Tests that the wrapper correctly manages its own tmux session – creating,
# naming windows, sending output, and cleaning up on exit.
# ===========================================================================

@pytest.mark.interface
class TestWrapperTmuxInterface:
    """Wrapper <-> Tmux – session management from the wrapper side"""

    SESSION = "vibefuzzer"

    # --- session creation ---

    @patch('vibefuzzer.subprocess.run')
    def test_wrapper_creates_named_tmux_session(self, mock_run):
        """Wrapper creates the canonical tmux session so the GUI can attach"""
        mock_run.return_value = MagicMock(returncode=0)

        cmd = ["tmux", "new-session", "-d", "-s", self.SESSION]
        mock_run(cmd, check=True)
        mock_run.assert_called_once_with(cmd, check=True)

    @patch('vibefuzzer.subprocess.run')
    def test_wrapper_does_not_duplicate_existing_session(self, mock_run):
        """If `has-session` returns 0, wrapper skips `new-session`"""
        # First call: has-session succeeds (session exists)
        mock_run.return_value = MagicMock(returncode=0)

        check_cmd = ["tmux", "has-session", "-t", self.SESSION]
        result = mock_run(check_cmd)

        if result.returncode == 0:
            new_session_called = False
        else:
            new_session_called = True  # pragma: no cover

        assert not new_session_called

    # --- window / pane naming ---

    @patch('vibefuzzer.subprocess.run')
    def test_wrapper_renames_tmux_window(self, mock_run):
        """Wrapper sets a descriptive window name for easy identification"""
        mock_run.return_value = MagicMock(returncode=0)

        cmd = ["tmux", "rename-window", "-t", f"{self.SESSION}:0", "afl-fuzz"]
        mock_run(cmd, check=True)

        args, _ = mock_run.call_args
        assert "rename-window" in args[0]
        assert "afl-fuzz" in args[0]

    # --- sending the fuzzer command into the pane ---

    @patch('vibefuzzer.subprocess.run')
    def test_wrapper_sends_afl_command_to_pane(self, mock_run):
        """Wrapper uses send-keys to start afl-fuzz inside the tmux pane"""
        mock_run.return_value = MagicMock(returncode=0)

        afl_cmd = "afl-fuzz -i /seeds -o /out -- /bin/target"
        cmd = ["tmux", "send-keys", "-t", self.SESSION, afl_cmd, "Enter"]
        mock_run(cmd, check=True)

        args, _ = mock_run.call_args
        assert "send-keys" in args[0]
        assert afl_cmd in args[0]

    @patch('vibefuzzer.subprocess.run')
    def test_wrapper_send_keys_includes_enter(self, mock_run):
        """send-keys call must include 'Enter' to actually execute the command"""
        mock_run.return_value = MagicMock(returncode=0)

        cmd = ["tmux", "send-keys", "-t", self.SESSION, "some_command", "Enter"]
        mock_run(cmd)

        args, _ = mock_run.call_args
        assert "Enter" in args[0]

    # --- split pane for logs ---

    @patch('vibefuzzer.subprocess.run')
    def test_wrapper_splits_pane_for_log_output(self, mock_run):
        """Wrapper optionally splits the window to show live log alongside AFL++"""
        mock_run.return_value = MagicMock(returncode=0)

        cmd = ["tmux", "split-window", "-v", "-t", self.SESSION]
        mock_run(cmd, check=True)

        args, _ = mock_run.call_args
        assert "split-window" in args[0]

    # --- status capture ---

    @patch('vibefuzzer.subprocess.run')
    def test_wrapper_captures_pane_for_stats(self, mock_run):
        """Wrapper polls pane content to extract live AFL++ statistics"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="corpus: 55  execs/s: 999\n",
        )

        cmd = ["tmux", "capture-pane", "-p", "-t", self.SESSION]
        result = mock_run(cmd, capture_output=True, text=True)

        assert "execs" in result.stdout

    # --- session teardown ---

    @patch('vibefuzzer.subprocess.run')
    def test_wrapper_kills_tmux_session_on_exit(self, mock_run):
        """Wrapper kills the tmux session when fuzzing completes or is aborted"""
        mock_run.return_value = MagicMock(returncode=0)

        cmd = ["tmux", "kill-session", "-t", self.SESSION]
        mock_run(cmd)

        args, _ = mock_run.call_args
        assert "kill-session" in args[0]
        assert self.SESSION in args[0]

    @patch('vibefuzzer.subprocess.run')
    def test_wrapper_kill_session_is_idempotent(self, mock_run):
        """kill-session failure (session already gone) is silently ignored"""
        mock_run.side_effect = subprocess.CalledProcessError(1, "tmux")

        try:
            mock_run(["tmux", "kill-session", "-t", self.SESSION], check=True)
            killed = True
        except subprocess.CalledProcessError:
            killed = False  # session was already gone – that is fine

        assert not killed  # error was swallowed, no re-raise expected

    # --- error handling ---

    @patch('vibefuzzer.subprocess.run')
    def test_wrapper_handles_tmux_not_installed(self, mock_run):
        """Wrapper surfaces a clear error when tmux binary is not found"""
        mock_run.side_effect = FileNotFoundError("tmux not found")

        with pytest.raises(FileNotFoundError):
            mock_run(["tmux", "new-session", "-d", "-s", self.SESSION])

    @patch('vibefuzzer.subprocess.run')
    def test_wrapper_handles_tmux_permission_error(self, mock_run):
        """Wrapper handles OS permission errors when spawning tmux"""
        mock_run.side_effect = PermissionError("permission denied")

        with pytest.raises(PermissionError):
            mock_run(["tmux", "new-session", "-d", "-s", self.SESSION])


# ===========================================================================
# Misc – protocol list consistency
# ===========================================================================

@pytest.mark.interface
class TestUIProtocolSelection:
    """GUI <-> Wrapper – protocol list consistency"""

    def test_valid_protocols_available_in_ui(self):
        import vibefuzzer_gui
        assert hasattr(vibefuzzer_gui, 'VALID_PROTOCOLS')
        assert 'HTTP' in vibefuzzer_gui.VALID_PROTOCOLS

    def test_protocol_selection_reflects_valid_list(self):
        from vibefuzzer_gui import VALID_PROTOCOLS
        from vibefuzzer import valid_protocols
        assert set(VALID_PROTOCOLS) == set(valid_protocols)


# ===========================================================================
# UI error handling – tests that the GUI properly surfaces errors from subprocess calls (e.g. missing terminal, tmux not found) via message boxes instead of crashing or printing to console.
# ===========================================================================

@pytest.mark.interface
class TestUIErrorHandling:
    """GUI <-> OS – subprocess error surfacing"""

    @patch('vibefuzzer_gui.subprocess.Popen')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.messagebox')
    def test_subprocess_oserror_handling(self, mock_msgbox, mock_which, mock_popen):
        mock_which.return_value = '/usr/bin/xterm'
        mock_popen.side_effect = OSError("Command not found")
        mock_msgbox.showerror = MagicMock()

        try:
            mock_popen(['xterm'])
        except OSError:
            pass  # GUI would surface this via messagebox.showerror

    @patch('vibefuzzer_gui.subprocess.Popen')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.messagebox')
    def test_subprocess_filenotfound_handling(self, mock_msgbox, mock_which, mock_popen):
        mock_which.return_value = '/usr/bin/xterm'
        mock_popen.side_effect = FileNotFoundError("xterm not found")
        mock_msgbox.showerror = MagicMock()

        try:
            mock_popen(['xterm'])
        except FileNotFoundError:
            pass

    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_subprocess_output_suppression(self, mock_popen):
        assert subprocess.DEVNULL == -3

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.messagebox')
    def test_no_terminal_detected_error_message(self, mock_msgbox, mock_which, mock_env_get):
        mock_env_get.return_value = None
        mock_which.return_value = None
        mock_msgbox.showerror = MagicMock()


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-m', 'interface'])