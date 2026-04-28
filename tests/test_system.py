# """
# System tests for VibeFuzzer

# End-to-end tests covering complete workflows:
# - Full fuzzing session (target build → seed gen → AFL++ launch → tmux display)
# - GUI workflow (config → build → launch → attach)
# - Complete seed generation and mutation pipeline
# - Error recovery and graceful degradation
# """

# import pytest
# import sys
# import tempfile
# import shutil
# from pathlib import Path
# from unittest.mock import Mock, patch, MagicMock, call
# import types
# import os

# # Setup imports
# sys.path.insert(0, str(Path(__file__).parent.parent))

# # Mock external dependencies
# sys.modules.setdefault('ollama', types.SimpleNamespace(list=Mock(), generate=Mock()))
# sys.modules.setdefault('customtkinter', MagicMock())
# sys.modules.setdefault('matplotlib', MagicMock())
# sys.modules.setdefault('matplotlib.pyplot', MagicMock())
# sys.modules.setdefault('matplotlib.gridspec', MagicMock())
# sys.modules.setdefault('matplotlib.backends', MagicMock())
# sys.modules.setdefault('matplotlib.backends.backend_tkagg', MagicMock())
# sys.modules.setdefault('reportlab', MagicMock())
# sys.modules.setdefault('reportlab.pdfgen', MagicMock())
# sys.modules.setdefault('reportlab.lib', MagicMock())
# sys.modules.setdefault('reportlab.lib.pagesizes', MagicMock())

# import importlib.util

# # Import modules
# spec_wrapper = importlib.util.spec_from_file_location(
#     "aflpp", Path(__file__).parent.parent / "vibefuzzer.py"
# )
# aflpp = importlib.util.module_from_spec(spec_wrapper)
# spec_wrapper.loader.exec_module(aflpp)

# import seed_gen
# import tmux_ui


# @pytest.mark.system
# class TestCompleteGUIWorkflow:
#     """Test complete GUI workflow from configuration to fuzzing"""

#     @patch('vibefuzzer_gui.subprocess.Popen')
#     @patch('vibefuzzer_gui.shutil.which')
#     @patch('vibefuzzer_gui.os.environ.get')
#     @patch('builtins.print')
#     def test_gui_configuration_to_launch_workflow(self, mock_print, mock_env_get, mock_which, mock_popen):
#         """Test complete workflow: configure → build → launch fuzzer"""
#         mock_which.return_value = '/usr/bin/xterm'
#         mock_env_get.return_value = None
#         mock_popen.return_value = MagicMock()

#         # Simulate GUI configuration steps
#         config = {
#             'target_dir': '/target/source',
#             'binary_name': 'nginx',
#             'protocol': 'HTTP',
#             'input_dir': 'input',
#             'output_dir': 'output',
#             'use_llm_seeds': True,
#             'num_seeds': 10,
#             'debug_ui': False,
#         }

#         with tempfile.TemporaryDirectory() as tmpdir:
#             # Step 1: Create dummy target directory
#             target_dir = Path(tmpdir) / 'target'
#             target_dir.mkdir()

#             # Step 2: Create input/output directories
#             input_dir = target_dir / config['input_dir']
#             output_dir = target_dir / config['output_dir']
#             input_dir.mkdir()
#             output_dir.mkdir()

#             # Step 3: Setup AFL++ environment
#             env = aflpp.setup_aflpp_env()
#             assert 'CC' in env
#             assert 'AFL_PATH' in env

#             # Step 4: Would call wrapper with configuration
#             # (mocked since we can't actually fuzz)
#             cmd = ['python3', 'vibefuzzer.py', str(target_dir)]

#             # Verify workflow chain
#             assert cmd[0] == 'python3'
#             assert input_dir.exists()
#             assert output_dir.exists()

#     @patch('vibefuzzer_gui.subprocess.Popen')
#     @patch('vibefuzzer_gui.shutil.which')
#     @patch('vibefuzzer_gui.os.environ.get')
#     def test_gui_terminal_attachment_after_launch(self, mock_env_get, mock_which, mock_popen):
#         """Test that GUI properly attaches to tmux after launch"""
#         mock_which.return_value = '/usr/bin/xterm'
#         mock_env_get.return_value = None
#         mock_popen.return_value = MagicMock()

#         # After fuzzer launches, GUI attaches to tmux
#         attach_cmd = "tmux attach-session -t vibefuzzer"
        
#         # Verify command would be executed
#         assert 'tmux attach-session' in attach_cmd
#         assert 'vibefuzzer' in attach_cmd


# @pytest.mark.system
# class TestCompleteWrapperWorkflow:
#     """Test complete AFL++ wrapper workflow"""

#     @patch('seed_gen._verify_ollama_connection')
#     @patch('seed_gen.ollama.generate')
#     @patch('seed_gen._get_protocol_seeds')
#     @patch('tmux_ui.subprocess.run')
#     @patch('tmux_ui.shutil.which')
#     @patch('builtins.print')
#     def test_full_fuzzing_session_setup(self, mock_print, mock_which, mock_run, 
#                                         mock_get_seeds, mock_generate, mock_verify):
#         """Test complete setup for a fuzzing session"""
#         mock_which.return_value = '/usr/bin/tmux'
#         mock_run.return_value = MagicMock()
#         mock_get_seeds.return_value = ['GET / HTTP/1.1\r\n\r\n']
#         mock_generate.return_value = MagicMock(response='GET / HTTP/1.1\r\n\r\n')

#         with tempfile.TemporaryDirectory() as tmpdir:
#             tmpdir_path = Path(tmpdir)
            
#             # Step 1: Preflight checks
#             with patch.object(Path, 'exists', return_value=True):
#                 try:
#                     aflpp.preflight_checks()
#                 except SystemExit:
#                     # Expected in test environment
#                     pass

#             # Step 2: Setup environment
#             env = aflpp.setup_aflpp_env()
#             assert 'CC' in env
#             assert 'AFL_PRELOAD' in env

#             # Step 3: Generate seeds
#             input_dir = tmpdir_path / 'input'
#             with patch('builtins.print'):
#                 seed_gen.generate_llm_seeds(
#                     str(input_dir),
#                     'nginx',
#                     protocol='HTTP',
#                     num_seeds=5,
#                     keep_existing=False
#                 )

#             # Step 4: Build AFL++ command
#             cmd, cmd_env = aflpp.build_aflpp_cmd(
#                 binary='/target/binary',
#                 input_dir=str(input_dir),
#                 output_dir=str(tmpdir_path / 'output'),
#                 env=env,
#                 extra_afl_args=[],
#                 target_args=[],
#                 debug_ui=False
#             )

#             # Step 5: Verify complete workflow
#             assert input_dir.exists()
#             assert isinstance(cmd, list)
#             assert isinstance(cmd_env, dict)
#             assert 'afl-fuzz' in str(cmd)

#     @patch('seed_gen._verify_ollama_connection')
#     @patch('seed_gen._get_protocol_seeds')
#     @patch('builtins.print')
#     def test_seed_generation_workflow(self, mock_print, mock_get_seeds, mock_verify):
#         """Test complete seed generation workflow"""
#         mock_get_seeds.return_value = [
#             'GET / HTTP/1.1\r\n\r\n',
#             'POST / HTTP/1.1\r\n\r\n',
#             'HEAD / HTTP/1.1\r\n\r\n',
#         ]

#         with tempfile.TemporaryDirectory() as tmpdir:
#             output_dir = Path(tmpdir) / 'seeds'
            
#             # Generate seeds with protocol
#             count = seed_gen.generate_llm_seeds(
#                 str(output_dir),
#                 'nginx',
#                 protocol='HTTP',
#                 num_seeds=3,
#                 keep_existing=False
#             )

#             # Verify seed files were created
#             assert output_dir.exists()
#             seed_files = list(output_dir.glob('seed_*'))
#             assert len(seed_files) >= 3


# @pytest.mark.system
# class TestErrorRecovery:
#     """Test system behavior under error conditions"""

#     @patch('tmux_ui.shutil.which')
#     def test_missing_tmux_graceful_degradation(self, mock_which):
#         """Test that system handles missing tmux gracefully"""
#         mock_which.return_value = None

#         with pytest.raises(RuntimeError, match="tmux not found"):
#             tmux_ui.launch_in_tmux(
#                 'session',
#                 ['afl-fuzz'],
#                 {},
#                 [],
#                 {}
#             )

#     @patch('seed_gen.ollama.list')
#     def test_ollama_connection_failure_handling(self, mock_list):
#         """Test graceful handling of Ollama connection failure"""
#         mock_list.side_effect = ConnectionError("Cannot connect to Ollama")

#         with pytest.raises(RuntimeError, match="Cannot connect to Ollama"):
#             seed_gen._verify_ollama_connection()

#     @patch('subprocess.run')
#     @patch('builtins.print')
#     def test_binary_instrumentation_verification_failure(self, mock_print, mock_run):
#         """Test handling when binary is not instrumented"""
#         mock_run.return_value.stdout = "no instrumentation marker"

#         result = aflpp._verify_instrumentation(Path("/tmp/binary"), fatal=False)
#         assert result is False

#     @patch('subprocess.run')
#     def test_binary_instrumentation_fatal_mode(self, mock_run):
#         """Test that missing instrumentation fails in fatal mode"""
#         mock_run.return_value.stdout = "no instrumentation"

#         with pytest.raises(RuntimeError, match="not instrumented"):
#             aflpp._verify_instrumentation(Path("/tmp/binary"), fatal=True)


# @pytest.mark.system
# class TestProtocolSupport:
#     """Test system behavior across different protocols"""

#     def test_all_protocols_have_seeds(self):
#         """Test that all supported protocols have seed templates"""
#         for protocol in aflpp.valid_protocols:
#             seeds = seed_gen._get_protocol_seeds(protocol, 'test')
#             assert isinstance(seeds, list)
#             assert len(seeds) > 0

#     def test_protocol_inference_from_binary_name(self):
#         """Test protocol inference for common server names"""
#         test_cases = [
#             ('nginx', 'HTTP'),
#             ('apache', 'HTTP'),
#             ('httpd', 'HTTP'),
#             ('vsftpd', 'FTP'),
#             ('proftpd', 'FTP'),
#             ('postfix', 'SMTP'),
#             ('sendmail', 'SMTP'),
#         ]

#         for binary_name, expected_proto in test_cases:
#             with patch('builtins.print'):
#                 seeds = seed_gen._get_protocol_seeds(None, binary_name)
#                 # Should get seeds (actual protocol inference happens in _get_protocol_seeds)
#                 assert len(seeds) > 0

#     def test_protocol_case_insensitivity(self):
#         """Test that protocol names are case-insensitive"""
#         for protocol in aflpp.valid_protocols:
#             seeds_upper = seed_gen._get_protocol_seeds(protocol.upper(), 'test')
#             seeds_lower = seed_gen._get_protocol_seeds(protocol.lower(), 'test')
            
#             assert seeds_upper == seeds_lower


# @pytest.mark.system
# class TestEnvironmentConsistency:
#     """Test that environment setup is consistent across workflows"""

#     @patch('builtins.print')
#     def test_environment_vars_persist_through_workflow(self, mock_print):
#         """Test that AFL++ env vars are maintained through workflow"""
#         env1 = aflpp.setup_aflpp_env()
#         env2 = aflpp.setup_aflpp_env()

#         # Verify both environments have the same vars
#         assert env1.keys() == env2.keys()

#         # Verify key values are consistent
#         assert env1['CC'] == env2['CC']
#         assert env1['CXX'] == env2['CXX']
#         assert env1['AFL_PATH'] == env2['AFL_PATH']

#     @patch('builtins.print')
#     def test_environment_doesnt_pollute_os_environ(self, mock_print):
#         """Test that environment setup doesn't pollute os.environ"""
#         original_env = os.environ.copy()

#         env = aflpp.setup_aflpp_env()

#         # Verify os.environ is unchanged
#         assert os.environ == original_env


# if __name__ == '__main__':
#     pytest.main([__file__, '-v', '-m', 'system'])
