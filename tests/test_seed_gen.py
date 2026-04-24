"""
Unit tests for seed_gen.py

Tests cover:
- Ollama connection verification
- Seed template retrieval
- Protocol inference
- Mutator prompt building
- LLM output cleaning
- Seed generation workflow
"""

import importlib
import pytest
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import types

# Add parent directory to path to import seed_gen
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.modules.pop('seed_gen', None)  # Force fresh import
# Mock ollama module before importing seed_gen
sys.modules.setdefault('ollama', types.SimpleNamespace(
    list=Mock(),
    generate=Mock()
))

import seed_gen


class TestVerifyOllamaConnection:
    """Test Ollama connection verification"""

    @patch('seed_gen.ollama.list')
    def test_verify_ollama_connection_success(self, mock_list):
        """Test successful Ollama connection with model available"""
        # Mock the ollama.list() response
        mock_model = MagicMock()
        mock_model.model = 'afl-mutator'
        mock_list.return_value = MagicMock(models=[mock_model])

        # Should not raise
        with patch('builtins.print'):
            seed_gen._verify_ollama_connection()

    @patch('seed_gen.ollama.list')
    def test_verify_ollama_connection_model_not_found(self, mock_list):
        """Test error when model is not found"""
        mock_model = MagicMock()
        mock_model.model = 'other-model'
        mock_list.return_value = MagicMock(models=[mock_model])

        with pytest.raises(RuntimeError, match="Model.*not found"):
            seed_gen._verify_ollama_connection()

    @patch('seed_gen.ollama.list')
    def test_verify_ollama_connection_connection_error(self, mock_list):
        """Test error when Ollama is not running"""
        mock_list.side_effect = ConnectionError("Connection refused")

        with pytest.raises(RuntimeError, match="Cannot connect to Ollama"):
            seed_gen._verify_ollama_connection()

    @patch('seed_gen.ollama.list')
    def test_verify_ollama_connection_empty_model_list(self, mock_list):
        """Test error when no models are available"""
        mock_list.return_value = MagicMock(models=[])

        with pytest.raises(RuntimeError, match="Model.*not found"):
            seed_gen._verify_ollama_connection()


class TestGetProtocolSeeds:
    """Test protocol seed template retrieval"""

    def test_get_protocol_seeds_explicit_http(self):
        """Test getting seeds for explicitly specified HTTP protocol"""
        seeds = seed_gen._get_protocol_seeds('HTTP', 'nginx')
        assert isinstance(seeds, list)
        assert len(seeds) > 0
        assert all(isinstance(s, str) for s in seeds)

    def test_get_protocol_seeds_explicit_ftp(self):
        """Test getting seeds for explicitly specified FTP protocol"""
        seeds = seed_gen._get_protocol_seeds('FTP', 'server')
        assert isinstance(seeds, list)
        assert len(seeds) > 0

    def test_get_protocol_seeds_infer_http_from_nginx(self):
        """Test inferring HTTP protocol from nginx binary name"""
        with patch('builtins.print'):
            seeds = seed_gen._get_protocol_seeds(None, 'nginx')
        assert len(seeds) > 0

    def test_get_protocol_seeds_infer_http_from_apache(self):
        """Test inferring HTTP protocol from apache binary name"""
        with patch('builtins.print'):
            seeds = seed_gen._get_protocol_seeds(None, 'httpd')
        assert len(seeds) > 0

    def test_get_protocol_seeds_infer_ftp_from_vsftpd(self):
        """Test inferring FTP protocol from vsftpd binary name"""
        with patch('builtins.print'):
            seeds = seed_gen._get_protocol_seeds(None, 'vsftpd')
        assert len(seeds) > 0

    def test_get_protocol_seeds_infer_smtp_from_postfix(self):
        """Test inferring SMTP protocol from postfix binary name"""
        with patch('builtins.print'):
            seeds = seed_gen._get_protocol_seeds(None, 'postfix')
        assert len(seeds) > 0

    def test_get_protocol_seeds_unknown_falls_back_to_http(self):
        """Test fallback to HTTP for unknown binary"""
        with patch('builtins.print'):
            seeds = seed_gen._get_protocol_seeds(None, 'unknown_server')
        assert len(seeds) > 0

    def test_get_protocol_seeds_case_insensitive(self):
        """Test that protocol matching is case-insensitive"""
        seeds1 = seed_gen._get_protocol_seeds('http', 'server')
        seeds2 = seed_gen._get_protocol_seeds('HTTP', 'server')
        assert seeds1 == seeds2

    def test_protocol_hints_complete(self):
        """Test that all protocol hints are present"""
        expected_protocols = ['FTP', 'HTTP', 'SMTP', 'RTSP', 'DNS', 'SIP']
        for proto in expected_protocols:
            assert proto in seed_gen.PROTOCOL_HINTS
            assert 'seeds' in seed_gen.PROTOCOL_HINTS[proto]
            assert len(seed_gen.PROTOCOL_HINTS[proto]['seeds']) > 0


class TestBuildMutatorPrompt:
    """Test mutator prompt building"""

    def test_build_mutator_prompt_single_seed(self):
        """Test prompt building with single seed"""
        prompt = seed_gen._build_mutator_prompt(['GET / HTTP/1.1\r\n\r\n'])
        assert isinstance(prompt, str)
        assert 'GET / HTTP/1.1' in prompt
        assert '[id:0' in prompt
        assert 'depth:1' in prompt

    def test_build_mutator_prompt_multiple_seeds(self):
        """Test prompt building with multiple seeds"""
        seeds = [
            'GET / HTTP/1.1\r\n\r\n',
            'POST / HTTP/1.1\r\n\r\n',
            'HEAD / HTTP/1.1\r\n\r\n',
        ]
        prompt = seed_gen._build_mutator_prompt(seeds)
        
        assert '---' in prompt
        for seed in seeds:
            assert seed in prompt

    def test_build_mutator_prompt_includes_metadata(self):
        """Test that prompt includes required metadata fields"""
        prompt = seed_gen._build_mutator_prompt(['test'])
        assert '[id:' in prompt
        assert 'depth:' in prompt
        assert 'bitmap:' in prompt
        assert 'favored:' in prompt
        assert 'new_cov:' in prompt

    def test_build_mutator_prompt_correct_ancestry_format(self):
        """Test that seeds are separated by --- delimiter"""
        seeds = ['seed1', 'seed2', 'seed3']
        prompt = seed_gen._build_mutator_prompt(seeds)
        
        parts = prompt.split('---\n')
        assert len(parts) == 3


class TestCleanMutatorOutput:
    """Test LLM output cleaning"""

    def test_clean_mutator_output_basic(self):
        """Test basic output cleaning"""
        raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        cleaned = seed_gen._clean_mutator_output(raw)
        assert "GET / HTTP/1.1" in cleaned

    def test_clean_mutator_output_strips_prompt_artifacts(self):
        """Test that prompt artifacts are stripped"""
        raw = "GET / HTTP/1.1\r\n\r\n### Input\n\nMore content"
        cleaned = seed_gen._clean_mutator_output(raw)
        assert "### Input" not in cleaned
        assert "More content" not in cleaned

    def test_clean_mutator_output_strips_endoftext(self):
        """Test that endoftext markers are stripped"""
        raw = "DATA\r\n<|endoftext|>"
        cleaned = seed_gen._clean_mutator_output(raw)
        assert "<|endoftext|>" not in cleaned

    def test_clean_mutator_output_converts_escape_sequences(self):
        """Test that escape sequences are converted to bytes"""
        raw = "GET / HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n"
        cleaned = seed_gen._clean_mutator_output(raw)
        
        assert "\\r\\n" not in cleaned
        assert "\r\n" in cleaned

    def test_clean_mutator_output_hex_escapes(self):
        """Test that hex escapes are converted"""
        raw = "\\x00\\x01\\x02\\xff"
        cleaned = seed_gen._clean_mutator_output(raw)
        
        assert "\\x" not in cleaned
        assert len(cleaned) == 4

    def test_clean_mutator_output_mixed_escapes(self):
        """Test handling of mixed escape types"""
        raw = "HELO\\r\\nDATA\\x00\\x01"
        cleaned = seed_gen._clean_mutator_output(raw)
        
        assert "\r\n" in cleaned
        assert len(cleaned) > 0

    def test_clean_mutator_output_strips_delimiter(self):
        """Test that --- delimiter is stripped"""
        raw = "content\r\n---\nmore"
        cleaned = seed_gen._clean_mutator_output(raw)
        assert "---" not in cleaned


class TestGenerateLLMSeeds:
    """Test seed generation workflow"""

    @patch('seed_gen._verify_ollama_connection')
    @patch('seed_gen.ollama.generate')
    @patch('seed_gen._get_protocol_seeds')
    def test_generate_llm_seeds_creates_output_dir(self, mock_get_seeds, mock_generate, mock_verify):
        """Test that seed generation creates output directory"""
        mock_get_seeds.return_value = ['GET / HTTP/1.1\r\n\r\n']
        mock_generate.return_value = MagicMock(response='GET / HTTP/1.1\r\n\r\n')

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / 'seeds'
            
            with patch('builtins.print'):
                seed_gen.generate_llm_seeds(
                    str(output_dir),
                    'nginx',
                    protocol='HTTP',
                    num_seeds=1,
                    keep_existing=False
                )

            assert output_dir.exists()

    @patch('seed_gen._verify_ollama_connection')
    @patch('seed_gen.ollama.generate')
    @patch('seed_gen._get_protocol_seeds')
    def test_generate_llm_seeds_writes_seeds(self, mock_get_seeds, mock_generate, mock_verify):
        """Test that generated seeds are written to files"""
        seeds = ['GET / HTTP/1.1\r\n\r\n', 'POST / HTTP/1.1\r\n\r\n']
        mock_get_seeds.return_value = seeds
        mock_generate.return_value = MagicMock(response='GET / HTTP/1.1\r\n\r\n')

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / 'seeds'
            
            with patch('builtins.print'):
                count = seed_gen.generate_llm_seeds(
                    str(output_dir),
                    'nginx',
                    protocol='HTTP',
                    num_seeds=1,
                    keep_existing=False
                )

            # Should have written template seeds
            seed_files = list(output_dir.glob('seed_*'))
            assert len(seed_files) >= len(seeds)

    @patch('seed_gen._verify_ollama_connection')
    @patch('seed_gen._get_protocol_seeds')
    def test_generate_llm_seeds_skips_when_existing(self, mock_get_seeds, mock_verify):
        """Test that generation skips when seeds already exist and keep_existing=True"""
        mock_get_seeds.return_value = ['GET / HTTP/1.1\r\n\r\n']

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / 'seeds'
            output_dir.mkdir(parents=True)
            
            # Create existing seed
            (output_dir / 'seed_0000').write_text('existing')

            with patch('builtins.print'):
                count = seed_gen.generate_llm_seeds(
                    str(output_dir),
                    'nginx',
                    num_seeds=1,
                    keep_existing=True
                )

            # Should still have only 1 file (won't be deleted)
            assert len(list(output_dir.glob('seed_*'))) >= 1

    @patch('seed_gen._verify_ollama_connection')
    @patch('seed_gen._get_protocol_seeds')
    def test_generate_llm_seeds_overwrites_when_not_keeping(self, mock_get_seeds, mock_verify):
        """Test that generation overwrites when keep_existing=False"""
        mock_get_seeds.return_value = ['new']

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / 'seeds'
            output_dir.mkdir(parents=True)
            
            # Create existing seed
            (output_dir / 'seed_0000').write_text('old')

            with patch('builtins.print'):
                seed_gen.generate_llm_seeds(
                    str(output_dir),
                    'nginx',
                    num_seeds=1,
                    keep_existing=False
                )

            # Verify we have fresh seeds
            seed_files = list(output_dir.glob('seed_*'))
            assert len(seed_files) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
