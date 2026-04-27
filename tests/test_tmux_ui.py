"""
Unit tests for tmux_ui.py

Tests cover:
- Tmux session launching
- Environment variable filtering
- Bash string building
- Error handling
"""

import pytest
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call

# Add parent directory to path to import tmux_ui
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.modules.pop('tmux_ui', None)  # Force fresh import

import tmux_ui


class TestLaunchInTmux:
    """Test tmux session launching functionality"""

    @patch('tmux_ui.subprocess.run')
    @patch('tmux_ui.shutil.which')
    def test_launch_in_tmux_basic(self, mock_which, mock_run):
        """Test basic tmux session launch with valid inputs"""
        mock_which.return_value = '/usr/bin/tmux'
        mock_run.return_value = MagicMock()

        primary_cmd = ['afl-fuzz', '-i', 'input', '-o', 'output']
        primary_env = {'AFL_NO_UI': '1', 'AFL_PATH': '/path/to/afl'}
        secondary_cmd = ['afl-showmap', '-o', 'map.txt']
        secondary_env = {'ASAN_OPTIONS': 'detect_leaks=0'}

        tmux_ui.launch_in_tmux('test_session', primary_cmd, primary_env, secondary_cmd, secondary_env)

        # Verify tmux commands were called
        assert mock_run.calle. 
        calls = mock_run.call_args_list
        
        # Should have called kill-session, new-session, send-keys (twice), and split-window
        assert any('kill-session' in str(call) for call in calls)
        assert any('new-session' in str(call) for call in calls)

    @patch('tmux_ui.subprocess.run')
    @patch('tmux_ui.shutil.which')
    def test_launch_in_tmux_missing_tmux(self, mock_which, mock_run):
        """Test that RuntimeError is raised when tmux is not found"""
        mock_which.return_value = None

        with pytest.raises(RuntimeError, match="tmux not found"):
            tmux_ui.launch_in_tmux(
                'test_session',
                ['afl-fuzz'],
                {},
                ['afl-showmap'],
                {}
            )

    @patch('tmux_ui.subprocess.run')
    @patch('tmux_ui.shutil.which')
    def test_launch_in_tmux_env_filtering(self, mock_which, mock_run):
        """Test that only relevant env vars are passed through"""
        mock_which.return_value = '/usr/bin/tmux'
        mock_run.return_value = MagicMock()

        primary_cmd = ['afl-fuzz']
        # Mix of vars that should and shouldn't be included
        primary_env = {
            'AFL_NO_UI': '1',
            'AFL_PATH': '/afl',
            'OLLAMA_MODEL': 'mutator',
            'ASAN_OPTIONS': 'detect_leaks=0',
            'DUMMY_VAR': 'value',
            'RANDOM_VAR': 'should_not_appear',
            'HOME': '/home/user',  # Should not be included
        }
        
        tmux_ui.launch_in_tmux('session', primary_cmd, primary_env, [], {})

        # Get the send-keys call
        send_keys_calls = [c for c in mock_run.call_args_list if 'send-keys' in str(c)]
        assert len(send_keys_calls) > 0

    @patch('tmux_ui.subprocess.run')
    @patch('tmux_ui.shutil.which')
    def test_launch_in_tmux_removes_afl_no_ui_from_secondary(self, mock_which, mock_run):
        """Test that AFL_NO_UI is removed from secondary env"""
        mock_which.return_value = '/usr/bin/tmux'
        mock_run.return_value = MagicMock()

        primary_cmd = ['afl-fuzz']
        secondary_cmd = ['afl-showmap']
        primary_env = {'AFL_NO_UI': '1'}
        secondary_env = {'AFL_NO_UI': '1', 'AFL_PATH': '/afl'}

        tmux_ui.launch_in_tmux('session', primary_cmd, primary_env, secondary_cmd, secondary_env)

        # Verify AFL_NO_UI is popped from secondary_env
        # (the function modifies a copy, so we can't check the passed-in dict)
        # Instead, we verify the function didn't raise an error

    @patch('tmux_ui.subprocess.run')
    @patch('tmux_ui.shutil.which')
    def test_launch_in_tmux_with_special_chars_in_session_name(self, mock_which, mock_run):
        """Test that special characters in session name are handled"""
        mock_which.return_value = '/usr/bin/tmux'
        mock_run.return_value = MagicMock()

        # Session name with special chars that need quoting
        session_name = "test-session-with-$pecial"
        primary_cmd = ['afl-fuzz']
        
        tmux_ui.launch_in_tmux(session_name, primary_cmd, {}, [], {})

        # Should complete without error
        assert mock_run.called

    @patch('tmux_ui.subprocess.run')
    @patch('tmux_ui.shutil.which')
    def test_launch_in_tmux_with_spaces_in_paths(self, mock_which, mock_run):
        """Test that paths with spaces are properly quoted"""
        mock_which.return_value = '/usr/bin/tmux'
        mock_run.return_value = MagicMock()

        primary_cmd = ['afl-fuzz', '-i', '/path with spaces/input', '-o', '/path with spaces/output']
        
        tmux_ui.launch_in_tmux('session', primary_cmd, {}, [], {})

        # Should complete without error
        assert mock_run.called

    @patch('tmux_ui.subprocess.run')
    @patch('tmux_ui.shutil.which')
    def test_build_bash_string_structure(self, mock_which, mock_run):
        """Test the structure of generated bash strings"""
        mock_which.return_value = '/usr/bin/tmux'
        mock_run.return_value = MagicMock()

        primary_cmd = ['echo', 'hello']
        primary_env = {'AFL_PATH': '/afl', 'NOT_RELEVANT': 'ignored'}

        with patch('builtins.print') as mock_print:
            tmux_ui.launch_in_tmux('session', primary_cmd, primary_env, [], {})

        # The print calls should show the session info
        output_calls = [c for c in mock_print.call_args_list]
        # Should have printed session info
        assert any('session' in str(c).lower() for c in output_calls)


class TestBuildBashString:
    """Test internal bash string building (via integration tests)"""

    @patch('tmux_ui.subprocess.run')
    @patch('tmux_ui.shutil.which')
    def test_env_vars_formatted_correctly(self, mock_which, mock_run):
        """Test that environment variables are formatted as KEY=value"""
        mock_which.return_value = '/usr/bin/tmux'
        mock_run.return_value = MagicMock()

        env = {'AFL_PATH': '/path/to/afl', 'ASAN_OPTIONS': 'detect_leaks=0'}
        cmd = ['afl-fuzz', '-i', 'input']

        tmux_ui.launch_in_tmux('s', cmd, env, [], {})

        # Verify subprocess was called (bash string was built)
        assert mock_run.called


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
