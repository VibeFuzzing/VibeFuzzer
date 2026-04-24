"""
Unit tests for vibefuzzer.py

Tests cover:
- Environment setup and verification
- File path handling and validation
- Binary building and instrumentation verification
- Argument parsing
- AFL++ command construction
- Utility functions
"""

import os
import sys
import pytest
import tempfile
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, mock_open, call
import argparse

# Add parent directory to path to import afl++wrapper
sys.path.insert(0, str(Path(__file__).parent.parent))

# Ensure tests can import afl++wrapper even if the `ollama` package is not installed.
# GitHub Actions does not provide this dependency by default.
import importlib.util
import types

sys.modules.setdefault('ollama', types.SimpleNamespace(list=Mock(), generate=Mock()))
sys.modules.setdefault('seed_gen', types.SimpleNamespace(generate_llm_seeds=Mock()))
sys.modules.setdefault('tmux_ui', types.SimpleNamespace(launch_in_tmux=Mock()))

# Import with workaround for ++ in filename
spec = importlib.util.spec_from_file_location("aflpp", Path(__file__).parent.parent / "vibefuzzer.py")
aflpp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aflpp)


class TestEnvironmentSetup:
    """Test AFL++ environment configuration"""

    @patch('builtins.print')
    def test_setup_aflpp_env_returns_dict(self, mock_print):
        """Test that setup_aflpp_env returns a dictionary"""
        env = aflpp.setup_aflpp_env()
        
        assert isinstance(env, dict)
        assert len(env) > 0

    @patch('builtins.print')
    def test_setup_aflpp_env_sets_required_vars(self, mock_print):
        """Test that required AFL++ environment variables are set"""
        env = aflpp.setup_aflpp_env()
        
        # Check for key AFL++ vars
        assert "CC" in env
        assert "CXX" in env
        assert "AFL_PATH" in env
        assert "AFL_PRELOAD" in env
        assert "AFL_TMPDIR" in env
        assert "AFL_SKIP_CPUFREQ" in env
        assert "ASAN_OPTIONS" in env

    @patch('builtins.print')
    def test_setup_aflpp_env_has_clang_compilers(self, mock_print):
        """Test that clang-fast compilers are configured"""
        env = aflpp.setup_aflpp_env()
        
        assert "afl-clang-fast" in env["CC"]
        assert "afl-clang-fast++" in env["CXX"]

    @patch('builtins.print')
    def test_setup_aflpp_env_doesnt_mutate_os_environ(self, mock_print):
        """Test that setup_aflpp_env doesn't mutate global os.environ"""
        original_env = os.environ.copy()
        env = aflpp.setup_aflpp_env()
        assert os.environ == original_env


class TestPreflightChecks:
    """Test preflight dependency verification"""

    @patch('subprocess.run')
    @patch('builtins.print')
    def test_preflight_checks_all_deps_exist(self, mock_print, mock_run):
        """Test preflight checks pass when all dependencies exist"""
        mock_run.return_value = MagicMock(stdout="afl-mutator\nother-model")
        
        # Mock the paths to exist
        with patch.object(Path, 'exists', return_value=True):
            # Should not raise
            aflpp.preflight_checks()

    @patch('subprocess.run')
    @patch('builtins.print')
    def test_preflight_checks_afl_missing(self, mock_print, mock_run):
        """Test preflight checks fail when AFL++ is missing"""
        with patch.object(Path, 'exists', return_value=False):
            with pytest.raises(SystemExit):
                aflpp.preflight_checks()

    @patch('subprocess.run')
    @patch('builtins.print')
    def test_preflight_checks_ollama_not_running(self, mock_print, mock_run):
        """Test preflight checks fail when Ollama is not running"""
        mock_run.side_effect = FileNotFoundError()
        
        with patch.object(Path, 'exists', return_value=True):
            with pytest.raises(SystemExit):
                aflpp.preflight_checks()


class TestInstrumentationVerification:
    """Test AFL++ instrumentation detection"""

    @patch('subprocess.run')
    def test_verify_instrumentation_found(self, mock_run):
        """Test detection of AFL++ instrumented binary"""
        mock_run.return_value.stdout = "some_text\n__AFL_SHM_ID\nmore_text"
        
        result = aflpp._verify_instrumentation(Path("/tmp/binary"), fatal=False)
        assert result is True

    @patch('subprocess.run')
    def test_verify_instrumentation_not_found_non_fatal(self, mock_run):
        """Test missing instrumentation returns False when non-fatal"""
        mock_run.return_value.stdout = "some_text\nno_instrumentation_marker"
        
        result = aflpp._verify_instrumentation(Path("/tmp/binary"), fatal=False)
        assert result is False

    @patch('subprocess.run')
    def test_verify_instrumentation_not_found_fatal(self, mock_run):
        """Test missing instrumentation raises error when fatal=True"""
        mock_run.return_value.stdout = "some_text\nno_instrumentation_marker"
        
        with pytest.raises(RuntimeError, match="not instrumented"):
            aflpp._verify_instrumentation(Path("/tmp/binary"), fatal=True)


class TestBuildTarget:
    """Test target building and compilation"""

    def test_build_target_nonexistent_source(self):
        """Test build fails when source directory doesn't exist"""
        with pytest.raises(FileNotFoundError, match="Target source not found"):
            aflpp.build_target("/nonexistent/path", "binary")

    @patch('subprocess.run')
    @patch('os.chdir')
    @patch('builtins.print')
    def test_build_target_returns_path(self, mock_print, mock_chdir, mock_run):
        """Test build target returns a Path object"""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir)
            (source_dir / "CMakeLists.txt").touch()
            
            with patch.object(Path, 'is_file', return_value=True):
                with patch.object(aflpp, '_verify_instrumentation', return_value=True):
                    result = aflpp.build_target(str(source_dir), "binary")
                    assert isinstance(result, Path)


class TestAutoDetectBinary:
    """Test automatic binary detection"""

    def test_auto_detect_binary_finds_executable(self):
        """Test auto-detection of compiled binary"""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir)
            binary = source_dir / "test_binary"
            binary.touch()
            binary.chmod(0o755)
            
            with patch.object(aflpp, '_verify_instrumentation', return_value=True):
                result = aflpp._auto_detect_binary(source_dir)
                assert result.name == "test_binary"


class TestBuildAFLppCmd:
    """Test AFL++ command construction"""

    def test_build_aflpp_cmd_returns_tuple(self):
        """Test that build_aflpp_cmd returns command and environment"""
        cmd, env = aflpp.build_aflpp_cmd(
            binary="/path/to/binary",
            input_dir="input",
            output_dir="output",
            env={},
            extra_afl_args=[],
            target_args=[],
            debug_ui=False
        )
        
        assert isinstance(cmd, list)
        assert isinstance(env, dict)

    def test_build_aflpp_cmd_includes_afl_fuzz(self):
        """Test that afl-fuzz is in the command"""
        cmd, env = aflpp.build_aflpp_cmd(
            binary="/path/to/binary",
            input_dir="input",
            output_dir="output",
            env={},
            extra_afl_args=[],
            target_args=[],
            debug_ui=False
        )
        
        assert "afl-fuzz" in cmd[0] or any("afl-fuzz" in str(c) for c in cmd)

    def test_build_aflpp_cmd_includes_input_output_dirs(self):
        """Test that input and output directories are in command"""
        cmd, env = aflpp.build_aflpp_cmd(
            binary="/path/to/binary",
            input_dir="input",
            output_dir="output",
            env={},
            extra_afl_args=[],
            target_args=[],
            debug_ui=False
        )
        
        cmd_str = " ".join(str(c) for c in cmd)
        assert "input" in cmd_str
        assert "output" in cmd_str

    def test_build_aflpp_cmd_with_extra_args(self):
        """Test that extra AFL args are included"""
        cmd, env = aflpp.build_aflpp_cmd(
            binary="/path/to/binary",
            input_dir="input",
            output_dir="output",
            env={},
            extra_afl_args=["-p", "fast"],
            target_args=["--config", "test.conf"],
            debug_ui=False
        )
        
        cmd_str = " ".join(str(c) for c in cmd)
        assert "-p" in cmd_str or "-p fast" in cmd_str
        assert "test.conf" in cmd_str


class TestParseArgs:
    """Test command-line argument parsing"""

    def test_parse_args_minimal(self):
        """Test parsing with minimal arguments"""
        with patch('sys.argv', ['wrapper.py', '/target/dir']):
            args = aflpp.parse_args()
            assert args.target_dir == '/target/dir'

    def test_parse_args_with_protocol(self):
        """Test parsing with protocol argument"""
        with patch('sys.argv', ['wrapper.py', '/target/dir', '--protocol', 'HTTP']):
            args = aflpp.parse_args()
            assert args.protocol == 'HTTP'

    def test_parse_args_with_custom_build(self):
        """Test parsing with custom build command"""
        with patch('sys.argv', ['wrapper.py', '/target/dir', '--custom-build', 'make build']):
            args = aflpp.parse_args()
            assert args.custom_build == 'make build'

    def test_parse_args_with_debug_ui(self):
        """Test parsing with debug UI flag"""
        with patch('sys.argv', ['wrapper.py', '/target/dir', '--debug-ui']):
            args = aflpp.parse_args()
            assert args.debug_ui is True

    def test_parse_args_with_no_llm_seeds(self):
        """Test parsing with no-llm-seeds flag"""
        with patch('sys.argv', ['wrapper.py', '/target/dir', '--no-llm-seeds']):
            args = aflpp.parse_args()
            assert args.no_llm_seeds is True

    def test_parse_args_with_num_seeds(self):
        """Test parsing with num-seeds argument"""
        with patch('sys.argv', ['wrapper.py', '/target/dir', '--num-seeds', '20']):
            args = aflpp.parse_args()
            assert args.num_seeds == 20

    def test_parse_args_with_input_output(self):
        """Test parsing with custom input/output directories"""
        with patch('sys.argv', ['wrapper.py', '/target/dir', '--input', 'seeds', '--output', 'crashes']):
            args = aflpp.parse_args()
            assert args.input == 'seeds'
            assert args.output == 'crashes'

    def test_parse_args_valid_protocols(self):
        """Test that valid protocols are accepted"""
        for proto in aflpp.valid_protocols:
            with patch('sys.argv', ['wrapper.py', '/target/dir', '--protocol', proto]):
                args = aflpp.parse_args()
                assert args.protocol == proto


class TestValidProtocols:
    """Test protocol validation constants"""

    def test_valid_protocols_defined(self):
        """Test that valid_protocols is defined"""
        assert hasattr(aflpp, 'valid_protocols')
        assert isinstance(aflpp.valid_protocols, list)
        assert len(aflpp.valid_protocols) > 0

    def test_valid_protocols_includes_common_protocols(self):
        """Test that common protocols are included"""
        assert 'HTTP' in aflpp.valid_protocols


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
