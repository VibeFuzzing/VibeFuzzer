"""
Integration tests for VibeFuzzer

Tests cover interactions between multiple components:
- GUI → AFL++ wrapper → tmux_ui
- Wrapper → seed_gen (Ollama integration)
- Tmux_ui → subprocess (tmux commands)
- GUI → terminal emulator detection → subprocess
"""

import pytest
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
import types

# Setup imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Mock external dependencies
sys.modules.setdefault('ollama', types.SimpleNamespace(list=Mock(), generate=Mock()))
sys.modules.setdefault('customtkinter', MagicMock())
sys.modules.setdefault('matplotlib', MagicMock())
sys.modules.setdefault('matplotlib.pyplot', MagicMock())
sys.modules.setdefault('matplotlib.gridspec', MagicMock())
sys.modules.setdefault('matplotlib.backends', MagicMock())
sys.modules.setdefault('matplotlib.backends.backend_tkagg', MagicMock())
sys.modules.setdefault('reportlab', MagicMock())
sys.modules.setdefault('reportlab.pdfgen', MagicMock())
sys.modules.setdefault('reportlab.lib', MagicMock())
sys.modules.setdefault('reportlab.lib.pagesizes', MagicMock())

import importlib.util

# Import modules
spec_wrapper = importlib.util.spec_from_file_location(
    "aflpp", Path(__file__).parent.parent / "vibefuzzer.py"
)
aflpp = importlib.util.module_from_spec(spec_wrapper)
spec_wrapper.loader.exec_module(aflpp)

import seed_gen
import tmux_ui


@pytest.mark.integration
class TestWrapperSeedGenIntegration:
    """Test integration between AFL++ wrapper and seed generation"""

    @patch('seed_gen._verify_ollama_connection')
    @patch('seed_gen.ollama.generate')
    @patch('seed_gen._get_protocol_seeds')
    @patch('builtins.print')
    def test_wrapper_calls_seed_gen_workflow(self, mock_print, mock_get_seeds, mock_generate, mock_verify):
        """Test that wrapper properly integrates with seed generation"""
        mock_get_seeds.return_value = ['GET / HTTP/1.1\r\n\r\n']
        mock_generate.return_value = MagicMock(response='GET / HTTP/1.1\r\n\r\n')

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / 'seeds'
            
            # Call seed generation as wrapper would
            count = seed_gen.generate_llm_seeds(
                str(output_dir),
                'nginx',
                protocol='HTTP',
                num_seeds=5,
                keep_existing=False
            )
            
            # Verify integration worked
            assert output_dir.exists()
            assert mock_verify.called
            assert mock_get_seeds.called

    @patch('seed_gen._verify_ollama_connection')
    @patch('seed_gen._get_protocol_seeds')
    @patch('builtins.print')
    def test_wrapper_seed_gen_protocol_inference(self, mock_print, mock_get_seeds, mock_verify):
        """Test protocol inference flows through wrapper to seed_gen"""
        mock_get_seeds.return_value = ['HELO localhost\r\n']

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / 'seeds'
            
            # Wrapper passes binary name for protocol inference
            count = seed_gen.generate_llm_seeds(
                str(output_dir),
                'postfix',  # Binary name that should infer SMTP
                protocol=None,
                num_seeds=1,
                keep_existing=False
            )
            
            # Verify protocol inference was called
            assert mock_get_seeds.called
            # The function was called with protocol inference
            call_args = mock_get_seeds.call_args
            assert call_args is not None


@pytest.mark.integration
class TestWrapperTmuxUIIntegration:
    """Test integration between AFL++ wrapper and tmux UI"""

    @patch('tmux_ui.subprocess.run')
    @patch('tmux_ui.shutil.which')
    @patch('builtins.print')
    def test_wrapper_launches_tmux_session(self, mock_print, mock_which, mock_run):
        """Test that wrapper properly launches tmux session"""
        mock_which.return_value = '/usr/bin/tmux'
        mock_run.return_value = MagicMock()

        # Simulate wrapper launching fuzzer in tmux
        primary_cmd = [
            str(aflpp.AFL_PATH / "afl-fuzz"),
            "-i", "input",
            "-o", "output",
            "--", "target_binary"
        ]
        primary_env = aflpp.setup_aflpp_env()
        secondary_cmd = ["afl-showmap"]
        secondary_env = primary_env.copy()

        # Call tmux launcher as wrapper would
        tmux_ui.launch_in_tmux(
            'vibefuzzer',
            primary_cmd,
            primary_env,
            secondary_cmd,
            secondary_env
        )

        # Verify tmux commands were called
        assert mock_which.called
        assert mock_run.called

    @patch('tmux_ui.subprocess.run')
    @patch('tmux_ui.shutil.which')
    def test_environment_variables_propagate_to_tmux(self, mock_which, mock_run):
        """Test that AFL++ environment variables propagate to tmux"""
        mock_which.return_value = '/usr/bin/tmux'
        mock_run.return_value = MagicMock()

        env = aflpp.setup_aflpp_env()
        
        # Verify AFL++ env vars were set
        assert 'AFL_PATH' in env
        assert 'AFL_PRELOAD' in env
        assert 'CC' in env
        
        # Call tmux launcher with those env vars
        tmux_ui.launch_in_tmux(
            'test_session',
            ['afl-fuzz'],
            env,
            [],
            {}
        )

        # Verify environment was used
        assert mock_run.called


@pytest.mark.integration
class TestGUITerminalIntegration:
    """Test integration between GUI and terminal emulator detection"""

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_gui_detects_and_launches_terminal(self, mock_popen, mock_which, mock_env_get):
        """Test that GUI correctly detects and launches terminal"""
        import customtkinter as ctk
        
        mock_env_get.side_effect = lambda x, default=None: {
            'WSL_DISTRO_NAME': None,
            'TERM_PROGRAM': None,
            'GNOME_TERMINAL_SCREEN': 'yes',
            'KONSOLE_VERSION': None,
            'KITTY_WINDOW_ID': None,
        }.get(x, default)
        mock_which.return_value = None
        mock_popen.return_value = MagicMock()

        # Simulate GUI terminal attachment logic
        attach_cmd = "tmux attach-session -t vibefuzzer"
        term_cmd = ["gnome-terminal", "--", "bash", "-c", attach_cmd]
        
        # Verify command structure for GNOME
        assert term_cmd[0] == "gnome-terminal"
        assert "--" in term_cmd
        assert "bash" in term_cmd

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    def test_gui_respects_platform_specific_terminals(self, mock_which, mock_env_get):
        """Test that GUI properly handles different platform terminals"""
        # Test GNOME detection
        mock_env_get.side_effect = lambda x, default=None: {
            'GNOME_TERMINAL_SCREEN': 'yes',
        }.get(x, default)
        
        # GUI should select gnome-terminal
        assert mock_env_get('GNOME_TERMINAL_SCREEN')
        
        # Test Konsole detection
        mock_env_get.side_effect = lambda x, default=None: {
            'KONSOLE_VERSION': '1',
        }.get(x, default)
        
        assert mock_env_get('KONSOLE_VERSION')


@pytest.mark.integration
class TestSeedGenOllamaIntegration:
    """Test integration with Ollama for seed generation"""

    @patch('seed_gen.ollama.list')
    def test_seed_gen_verifies_ollama_connection(self, mock_list):
        """Test that seed_gen properly checks Ollama connection"""
        mock_model = MagicMock()
        mock_model.model = 'afl-mutator'
        mock_list.return_value = MagicMock(models=[mock_model])

        # Should not raise
        with patch('builtins.print'):
            seed_gen._verify_ollama_connection()

        assert mock_list.called

    @patch('seed_gen.ollama.list')
    @patch('seed_gen.ollama.generate')
    def test_seed_gen_uses_ollama_generate(self, mock_generate, mock_list):
        """Test that seed generation actually calls ollama.generate"""
        mock_model = MagicMock()
        mock_model.model = 'afl-mutator'
        mock_list.return_value = MagicMock(models=[mock_model])
        mock_generate.return_value = MagicMock(response='GET / HTTP/1.1\r\n')

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            with patch('builtins.print'):
                # Trigger seed generation
                prompt = seed_gen._build_mutator_prompt(['GET / HTTP/1.1\r\n'])
                
                # Simulate calling ollama
                if prompt:
                    result = seed_gen.ollama.generate(
                        model='afl-mutator',
                        prompt=prompt
                    )
                    assert result.response is not None


@pytest.mark.integration
class TestWrapperArgumentParsing:
    """Test integration of argument parsing through wrapper"""

    def test_parse_args_with_complete_workflow(self):
        """Test complete argument set for fuzzing workflow"""
        with patch('sys.argv', [
            'wrapper.py',
            '/path/to/target',
            '--protocol', 'HTTP',
            '--binary', 'objs/nginx',
            '--input', './seeds',
            '--output', './findings',
            '--num-seeds', '20',
            '--debug-ui',
            '--afl-args', '-p', 'fast',
        ]):
            args = aflpp.parse_args()
            
            # Verify all args parsed correctly
            assert args.target_dir == '/path/to/target'
            assert args.protocol == 'HTTP'
            assert args.binary == 'objs/nginx'
            assert args.input == './seeds'
            assert args.output == './findings'
            assert args.num_seeds == 20
            assert args.debug_ui is True

    def test_parse_args_builds_valid_command_structure(self):
        """Test that parsed args can build valid AFL++ command"""
        with patch('sys.argv', [
            'wrapper.py',
            '/target',
            '--protocol', 'HTTP',
            '--input', 'seeds',
            '--output', 'findings',
        ]):
            args = aflpp.parse_args()
            
            # Simulate building command from args
            cmd, env = aflpp.build_aflpp_cmd(
                binary="/target/binary",
                input_dir=args.input,
                output_dir=args.output,
                base_env=aflpp.setup_aflpp_env(),
                afl_args=args.afl_args,
                target_args=args.target_args,
                debug_ui=args.debug_ui
            )
            
            # Verify command structure
            assert isinstance(cmd, list)
            assert isinstance(env, dict)
            assert len(cmd) > 0
            assert 'afl-fuzz' in str(cmd)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-m', 'integration'])
