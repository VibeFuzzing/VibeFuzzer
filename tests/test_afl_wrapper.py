"""
Unit tests for afl++wrapper.py

Tests cover:
- Environment setup and verification
- File path handling and validation
- Seed prompt generation
- LLM output cleaning
- Command-line argument parsing
- Utility functions
"""

import os
import sys
import pytest
import tempfile
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, mock_open
import argparse

# Add parent directory to path to import afl++wrapper
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import with workaround for ++ in filename
import importlib.util
spec = importlib.util.spec_from_file_location("aflpp", Path(__file__).parent.parent / "afl++wrapper.py")
aflpp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aflpp)


class TestEnvironmentSetup:
    """Test AFL++ environment configuration"""

    def test_setup_aflpp_env_basic(self):
        """Test basic environment setup with valid inputs"""
        with tempfile.TemporaryDirectory() as tmpdir:
            libdesock = Path(tmpdir) / "libdesock.so"
            libdesock.touch()
            
            with patch('shutil.which', return_value='/usr/local/AFL/afl-fuzz'):
                env = aflpp.setup_aflpp_env(str(libdesock))
            
            assert env is not None
            assert isinstance(env, dict)
            assert env["AFL_PRELOAD"] == str(libdesock)
            assert "CC" in env and env["CC"] == "afl-clang-fast"
            assert "CXX" in env and env["CXX"] == "afl-clang-fast++"
            assert "AFL_PATH" in env
            assert "AFL_TMPDIR" in env

    def test_setup_aflpp_env_missing_afl_fuzz(self):
        """Test setup fails gracefully when afl-fuzz not in PATH"""
        with tempfile.TemporaryDirectory() as tmpdir:
            libdesock = Path(tmpdir) / "libdesock.so"
            libdesock.touch()
            
            with patch('shutil.which', return_value=None):
                with pytest.raises(FileNotFoundError, match="afl-fuzz not found"):
                    aflpp.setup_aflpp_env(str(libdesock))

    def test_setup_aflpp_env_preserves_os_environ(self):
        """Test that setup_aflpp_env doesn't mutate global os.environ"""
        original_env = os.environ.copy()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            libdesock = Path(tmpdir) / "libdesock.so"
            libdesock.touch()
            
            with patch('shutil.which', return_value='/usr/local/AFL/afl-fuzz'):
                env = aflpp.setup_aflpp_env(str(libdesock))
            
            # Verify os.environ wasn't modified
            assert os.environ == original_env


class TestLibdesockVerification:
    """Test libdesock.so verification"""

    def test_verify_libdesock_exists(self):
        """Test verification of existing libdesock"""
        with tempfile.TemporaryDirectory() as tmpdir:
            libdesock = Path(tmpdir) / "libdesock.so"
            libdesock.touch()
            
            result = aflpp.verify_libdesock(str(libdesock))
            assert result == str(libdesock.resolve())

    def test_verify_libdesock_not_found(self):
        """Test verification fails for missing libdesock"""
        with pytest.raises(FileNotFoundError, match="libdesock not found"):
            aflpp.verify_libdesock("/nonexistent/path/libdesock.so")

    def test_verify_libdesock_resolves_relative_path(self):
        """Test that relative paths are resolved correctly"""
        with tempfile.TemporaryDirectory() as tmpdir:
            libdesock = Path(tmpdir) / "libdesock.so"
            libdesock.touch()
            
            # Change to temp dir and use relative path
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = aflpp.verify_libdesock("./libdesock.so")
                assert result == str(libdesock.resolve())
            finally:
                os.chdir(original_cwd)


class TestInstrumentationVerification:
    """Test AFL++ instrumentation detection"""

    def test_verify_instrumentation_found(self):
        """Test detection of AFL++ instrumented binary"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.stdout = "some_text\n__AFL_SHM_ID\nmore_text"
            
            result = aflpp.verify_instrumentation(Path("/tmp/binary"), fatal=False)
            assert result is True

    def test_verify_instrumentation_not_found_non_fatal(self):
        """Test missing instrumentation returns False when non-fatal"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.stdout = "some_text\nno_instrumentation_marker"
            
            result = aflpp.verify_instrumentation(Path("/tmp/binary"), fatal=False)
            assert result is False

    def test_verify_instrumentation_not_found_fatal(self):
        """Test missing instrumentation raises error when fatal=True"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.stdout = "some_text\nno_instrumentation_marker"
            
            with pytest.raises(RuntimeError, match="Binary not instrumented"):
                aflpp.verify_instrumentation(Path("/tmp/binary"), fatal=True)


class TestSeedPromptGeneration:
    """Test LLM seed prompt generation"""

    def test_build_seed_prompt_with_protocol(self):
        """Test prompt generation with known protocol"""
        prompt = aflpp.build_seed_prompt(
            protocol="HTTP",
            binary_name="nginx",
            seed_index=0,
            total_seeds=10
        )
        
        assert isinstance(prompt, str)
        assert "HTTP" in prompt
        assert "Hypertext Transfer Protocol" in prompt
        assert "GET / HTTP/1.1" in prompt
        assert "seed 1 of 10" in prompt

    def test_build_seed_prompt_without_protocol(self):
        """Test prompt generation when protocol is not specified"""
        prompt = aflpp.build_seed_prompt(
            protocol=None,
            binary_name="nginx",
            seed_index=2,
            total_seeds=5
        )
        
        assert isinstance(prompt, str)
        assert "nginx" in prompt
        assert "seed 3 of 5" in prompt
        assert "infer" in prompt.lower()

    def test_build_seed_prompt_all_protocols(self):
        """Test prompt generation for all supported protocols"""
        for protocol in aflpp.valid_protocols:
            prompt = aflpp.build_seed_prompt(
                protocol=protocol,
                binary_name="test_server",
                seed_index=0,
                total_seeds=1
            )
            
            assert isinstance(prompt, str)
            assert len(prompt) > 100  # Prompt should have substantial content

    def test_build_seed_prompt_ftp_protocol(self):
        """Test FTP protocol-specific prompt content"""
        prompt = aflpp.build_seed_prompt(
            protocol="FTP",
            binary_name="vsftpd",
            seed_index=0,
            total_seeds=1
        )
        
        assert "File Transfer Protocol" in prompt
        assert "USER" in prompt
        assert "\\r\\n" in prompt

    def test_build_seed_prompt_dns_protocol(self):
        """Test DNS protocol prompt (binary protocol)"""
        prompt = aflpp.build_seed_prompt(
            protocol="DNS",
            binary_name="bind",
            seed_index=0,
            total_seeds=1
        )
        
        # Check that DNS-related content is in the prompt
        assert "Domain Name System" in prompt or "DNS" in prompt
        assert "binary" in prompt.lower()

    def test_build_seed_prompt_case_insensitive(self):
        """Test that protocol matching is case-insensitive"""
        prompt_upper = aflpp.build_seed_prompt(
            protocol="HTTP",
            binary_name="test",
            seed_index=0,
            total_seeds=1
        )
        
        prompt_lower = aflpp.build_seed_prompt(
            protocol="http",
            binary_name="test",
            seed_index=0,
            total_seeds=1
        )
        
        # Both should contain HTTP-specific content
        assert "Hypertext Transfer Protocol" in prompt_upper
        assert "Hypertext Transfer Protocol" in prompt_lower


class TestLLMOutputCleaning:
    """Test LLM output cleaning and escape sequence conversion"""

    def test_clean_llm_output_basic(self):
        """Test basic output cleaning removes commentary"""
        raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        cleaned = aflpp.clean_llm_output(raw)
        
        assert "GET / HTTP/1.1" in cleaned
        assert "\r\n" in cleaned

    def test_clean_llm_output_removes_parenthetical_notes(self):
        """Test that parenthetical comments are removed"""
        raw = "(This is a comment)\nGET / HTTP/1.1\r\n"
        cleaned = aflpp.clean_llm_output(raw)
        
        assert "(This is a comment)" not in cleaned
        assert "GET / HTTP/1.1" in cleaned

    def test_clean_llm_output_removes_markdown(self):
        """Test that markdown code fences are removed"""
        raw = "```\nGET / HTTP/1.1\r\n```\n"
        cleaned = aflpp.clean_llm_output(raw)
        
        assert "```" not in cleaned
        assert "GET / HTTP/1.1" in cleaned

    def test_clean_llm_output_converts_escape_sequences(self):
        """Test conversion of literal escape sequences to actual bytes"""
        raw = r"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        cleaned = aflpp.clean_llm_output(raw)
        
        assert "\r\n" in cleaned
        assert "\\r\\n" not in cleaned

    def test_clean_llm_output_removes_note_lines(self):
        """Test that Note: and NOTE: lines are removed"""
        raw = "Note: This is an explanation\nGET / HTTP/1.1\r\n\nNOTE: Another note"
        cleaned = aflpp.clean_llm_output(raw)
        
        assert "Note:" not in cleaned
        assert "NOTE:" not in cleaned
        assert "GET / HTTP/1.1" in cleaned

    def test_clean_llm_output_converts_all_escape_sequences(self):
        """Test conversion of various escape sequences"""
        raw = r"Data:\t\t\n\r\x00\0end"
        cleaned = aflpp.clean_llm_output(raw)
        
        assert "\t" in cleaned
        assert "\n" in cleaned
        assert "\x00" in cleaned
        assert "\\t" not in cleaned
        assert "\\n" not in cleaned

    def test_clean_llm_output_empty_string(self):
        """Test handling of empty input"""
        cleaned = aflpp.clean_llm_output("")
        assert cleaned == ""

    def test_clean_llm_output_whitespace_only(self):
        """Test handling of whitespace-only input"""
        cleaned = aflpp.clean_llm_output("   \n\n   \t  \n")
        assert cleaned.strip() == ""


class TestProtocolHints:
    """Test protocol hints are properly defined"""

    def test_protocol_hints_coverage(self):
        """Test that all valid protocols have hints defined"""
        for protocol in aflpp.valid_protocols:
            assert protocol in aflpp.PROTOCOL_HINTS
            hints = aflpp.PROTOCOL_HINTS[protocol]
            assert "description" in hints
            assert "notes" in hints

    def test_protocol_hints_http_structure(self):
        """Test HTTP protocol hints have correct structure"""
        http_hints = aflpp.PROTOCOL_HINTS["HTTP"]
        
        assert "example_session" in http_hints
        assert "Host:" in http_hints["example_session"]
        # Check for actual carriage return + newline bytes (not the literal \r\n text)
        assert "\r\n" in http_hints["example_session"]

    def test_protocol_hints_dns_binary(self):
        """Test DNS protocol hints note it's binary"""
        dns_hints = aflpp.PROTOCOL_HINTS["DNS"]
        
        assert "binary" in dns_hints["notes"].lower()
        assert dns_hints["example_session"] is None


class TestArgumentParsing:
    """Test command-line argument parsing"""

    def test_parse_args_required_arguments(self, capsys):
        """Test that required arguments are enforced"""
        with pytest.raises(SystemExit):
            # Missing required positional arguments should cause error
            with patch('sys.argv', ['afl++wrapper.py']):
                aflpp.parse_args()

    def test_parse_args_basic_valid(self):
        """Test parsing valid basic arguments"""
        with patch('sys.argv', [
            'afl++wrapper.py',
            '/path/to/target',
            'binary_name',
            '--libdesock', '/path/to/libdesock.so'
        ]):
            args = aflpp.parse_args()
            
            assert args.target_dir == '/path/to/target'
            assert args.binary == 'binary_name'
            assert args.libdesock == '/path/to/libdesock.so'

    def test_parse_args_protocol_choices(self):
        """Test that only valid protocols are accepted"""
        with patch('sys.argv', [
            'afl++wrapper.py',
            '/path/to/target',
            'binary_name',
            '--libdesock', '/path/to/libdesock.so',
            '--protocol', 'HTTP'
        ]):
            args = aflpp.parse_args()
            assert args.protocol == 'HTTP'

    def test_parse_args_invalid_protocol(self):
        """Test that invalid protocol raises error"""
        with patch('sys.argv', [
            'afl++wrapper.py',
            '/path/to/target',
            'binary_name',
            '--libdesock', '/path/to/libdesock.so',
            '--protocol', 'INVALID'
        ]):
            with pytest.raises(SystemExit):
                aflpp.parse_args()

    def test_parse_args_optional_defaults(self):
        """Test that optional arguments have correct defaults"""
        with patch('sys.argv', [
            'afl++wrapper.py',
            '/path/to/target',
            'binary_name',
            '--libdesock', '/path/to/libdesock.so'
        ]):
            args = aflpp.parse_args()
            
            assert args.input == './fuzzing_inputs'
            assert args.output == './fuzzing_output'
            assert args.num_seeds == 10
            assert args.no_build is False
            assert args.no_llm_seeds is False
            assert args.debug_ui is False

    def test_parse_args_with_target_args(self):
        """Test parsing target arguments after -- separator"""
        with patch('sys.argv', [
            'afl++wrapper.py',
            '/path/to/target',
            'binary_name',
            '--libdesock', '/path/to/libdesock.so',
            '--target-args', '-c', '/etc/config.conf'
        ]):
            args = aflpp.parse_args()
            assert args.target_args == ['-c', '/etc/config.conf']

    def test_parse_args_flags(self):
        """Test boolean flag arguments"""
        with patch('sys.argv', [
            'afl++wrapper.py',
            '/path/to/target',
            'binary_name',
            '--libdesock', '/path/to/libdesock.so',
            '--no-build',
            '--no-llm-seeds',
            '--debug-ui'
        ]):
            args = aflpp.parse_args()
            
            assert args.no_build is True
            assert args.no_llm_seeds is True
            assert args.debug_ui is True

    def test_parse_args_llm_mutator(self):
        """Test LLM mutator path argument"""
        with patch('sys.argv', [
            'afl++wrapper.py',
            '/path/to/target',
            'binary_name',
            '--libdesock', '/path/to/libdesock.so',
            '--llm-mutator', '/path/to/mutator'
        ]):
            args = aflpp.parse_args()
            assert args.llm_mutator == '/path/to/mutator'

    def test_parse_args_num_seeds(self):
        """Test num-seeds argument"""
        with patch('sys.argv', [
            'afl++wrapper.py',
            '/path/to/target',
            'binary_name',
            '--libdesock', '/path/to/libdesock.so',
            '--num-seeds', '25'
        ]):
            args = aflpp.parse_args()
            assert args.num_seeds == 25


class TestBuildMutator:
    """Test C mutator building"""

    def test_build_c_mutator_missing_directory(self):
        """Test build fails when source directory doesn't exist"""
        with pytest.raises(FileNotFoundError, match="Mutator directory not found"):
            aflpp.build_c_mutator("/nonexistent/path")

    def test_build_c_mutator_successful(self):
        """Test successful mutator build"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake .so file to simulate successful build
            mutator_path = Path(tmpdir)
            so_file = mutator_path / "mutator.so"
            
            with patch('subprocess.run') as mock_run:
                so_file.touch()  # Simulate result of make
                result = aflpp.build_c_mutator(str(mutator_path))
            
            assert result == str(so_file.resolve())

    def test_build_c_mutator_no_so_produced(self):
        """Test build fails when no .so file is produced"""
        with tempfile.TemporaryDirectory() as tmpdir:
            mutator_path = Path(tmpdir)
            
            with patch('subprocess.run'):
                with pytest.raises(RuntimeError, match="No .so file produced"):
                    aflpp.build_c_mutator(str(mutator_path))


class TestOllamaConnection:
    """Test Ollama connection verification"""

    def test_verify_ollama_connection_success(self):
        """Test successful Ollama connection verification"""
        mock_model = Mock()
        mock_model.model = "llama3.1:8b"
        
        with patch('ollama.list') as mock_list:
            mock_list.return_value.models = [mock_model]
            result = aflpp.verify_ollama_connection()
            
            assert result is True

    def test_verify_ollama_connection_model_not_found(self):
        """Test error when target model is not available"""
        mock_model = Mock()
        mock_model.model = "other-model:7b"
        
        with patch('ollama.list') as mock_list:
            mock_list.return_value.models = [mock_model]
            
            with pytest.raises(RuntimeError, match="Model.*not found"):
                aflpp.verify_ollama_connection()

    def test_verify_ollama_connection_disconnected(self):
        """Test error when Ollama is not running"""
        with patch('ollama.list', side_effect=ConnectionError("Connection refused")):
            with pytest.raises(RuntimeError, match="Cannot connect to Ollama"):
                aflpp.verify_ollama_connection()

    def test_verify_ollama_connection_no_models(self):
        """Test error when no models are available"""
        with patch('ollama.list') as mock_list:
            mock_list.return_value.models = []
            
            with pytest.raises(RuntimeError, match="Model.*not found"):
                aflpp.verify_ollama_connection()


class TestBuildTarget:
    """Test target binary building"""

    def test_build_target_missing_source(self):
        """Test build fails when source directory doesn't exist"""
        with pytest.raises(FileNotFoundError, match="Target source not found"):
            aflpp.build_target(
                source_dir="/nonexistent/path",
                binary_name="test_binary"
            )

    def test_build_target_already_instrumented(self):
        """Test that existing instrumented binary is reused"""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            binary = source_path / "test_binary"
            binary.touch()
            
            with patch.object(aflpp, 'verify_instrumentation', return_value=True):
                result = aflpp.build_target(
                    source_dir=str(source_path),
                    binary_name="test_binary"
                )
            
            assert result == binary.resolve()


class TestIntegration:
    """Integration tests combining multiple components"""

    def test_full_workflow_dry_run(self):
        """Test dry-run of full fuzzing workflow"""
        with tempfile.TemporaryDirectory() as tmpdir:
            target_dir = Path(tmpdir) / "target"
            target_dir.mkdir()
            
            libdesock = Path(tmpdir) / "libdesock.so"
            libdesock.touch()
            
            input_dir = Path(tmpdir) / "inputs"
            input_dir.mkdir()
            output_dir = Path(tmpdir) / "outputs"
            
            binary = target_dir / "test_server"
            binary.touch()
            binary.chmod(0o755)
            
            with patch.object(aflpp, 'verify_instrumentation', return_value=True):
                with patch('shutil.which', return_value='/usr/bin/afl-fuzz'):
                    env = aflpp.setup_aflpp_env(str(libdesock))
            
            assert "AFL_PRELOAD" in env
            assert env["AFL_PRELOAD"] == str(libdesock)

    def test_seed_generation_pipeline(self):
        """Test seed generation with mocked LLM"""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "inputs"
            input_dir.mkdir()
            
            with patch.object(aflpp, 'verify_ollama_connection'):
                with patch('ollama.generate') as mock_generate:
                    mock_generate.return_value = {'response': 'GET / HTTP/1.1\r\n'}
                    
                    with patch.object(aflpp, 'clean_llm_output') as mock_clean:
                        mock_clean.return_value = 'GET / HTTP/1.1\r\n'
                        
                        generated = aflpp.generate_llm_seeds(
                            input_dir=str(input_dir),
                            binary_name="test_server",
                            protocol="HTTP",
                            num_seeds=2,
                            keep_existing=False
                        )
            
            assert generated > 0


# ============================================================================
# PYTEST CONFIGURATION
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
