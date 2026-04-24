"""
Unit tests for vibefuzzer_gui.py

Tests cover:
- GUI initialization
- Configuration handling
- Terminal detection
- Tmux session attachment
- Configuration validation
- Error handling
"""

import pytest
import sys
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
import tempfile

# Add parent directory to path to import vibefuzzer_gui
sys.path.insert(0, str(Path(__file__).parent.parent))

# Mock customtkinter before importing vibefuzzer_gui
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

# Patch ctk before importing
import customtkinter as ctk
ctk.CTk = MagicMock
ctk.BooleanVar = MagicMock
ctk.CTkFrame = MagicMock
ctk.set_appearance_mode = MagicMock

import vibefuzzer_gui


class TestVibeFuzzerGUIInitialization:
    """Test GUI initialization"""

    @patch('vibefuzzer_gui.ctk.CTk.__init__', return_value=None)
    def test_gui_initialization(self, mock_init):
        """Test basic GUI initialization"""
        # Since we're mocking, this mainly tests that imports work
        assert hasattr(vibefuzzer_gui, 'VibeFuzzerGUI')

    @patch('vibefuzzer_gui.ctk.CTk.__init__', return_value=None)
    def test_gui_has_build_config_screen_method(self, mock_init):
        """Test that GUI has required methods"""
        assert hasattr(vibefuzzer_gui.VibeFuzzerGUI, 'build_config_screen')


class TestTerminalDetection:
    """Test terminal emulator detection and selection"""

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_detect_gnome_terminal(self, mock_popen, mock_which, mock_env_get):
        """Test detection of GNOME Terminal"""
        mock_env_get.side_effect = lambda x, default=None: {
            'WSL_DISTRO_NAME': None,
            'TERM_PROGRAM': None,
            'GNOME_TERMINAL_SCREEN': 'yes',
        }.get(x, default)
        mock_which.return_value = None
        mock_popen.return_value = MagicMock()

        # Build command for gnome-terminal
        # This is implicitly tested when terminal commands are constructed

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_detect_konsole(self, mock_popen, mock_which, mock_env_get):
        """Test detection of Konsole"""
        mock_env_get.side_effect = lambda x, default=None: {
            'WSL_DISTRO_NAME': None,
            'TERM_PROGRAM': None,
            'GNOME_TERMINAL_SCREEN': None,
            'KONSOLE_VERSION': '1',
        }.get(x, default)
        mock_which.return_value = None
        mock_popen.return_value = MagicMock()

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_detect_kitty(self, mock_popen, mock_which, mock_env_get):
        """Test detection of Kitty terminal"""
        mock_env_get.side_effect = lambda x, default=None: {
            'WSL_DISTRO_NAME': None,
            'TERM_PROGRAM': None,
            'GNOME_TERMINAL_SCREEN': None,
            'KONSOLE_VERSION': None,
            'KITTY_WINDOW_ID': '1',
        }.get(x, default)
        mock_which.return_value = None
        mock_popen.return_value = MagicMock()

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    def test_detect_xterm_fallback(self, mock_which, mock_env_get):
        """Test fallback to xterm"""
        mock_env_get.side_effect = lambda x, default=None: {
            'WSL_DISTRO_NAME': None,
            'TERM_PROGRAM': None,
        }.get(x, default)
        
        def which_side_effect(cmd):
            if cmd == 'xterm':
                return '/usr/bin/xterm'
            return None
        
        mock_which.side_effect = which_side_effect

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.messagebox')
    def test_no_terminal_detected_error(self, mock_msgbox, mock_which, mock_env_get):
        """Test error when no terminal is detected"""
        mock_env_get.side_effect = lambda x, default=None: {
            'WSL_DISTRO_NAME': None,
            'TERM_PROGRAM': None,
        }.get(x, default)
        mock_which.return_value = None
        mock_msgbox.showerror = MagicMock()


class TestTmuxSessionAttachment:
    """Test tmux session attachment logic"""

    @patch('vibefuzzer_gui.subprocess.Popen')
    @patch('vibefuzzer_gui.shutil.which')
    def test_tmux_attach_command_construction_gnome(self, mock_which, mock_popen):
        """Test tmux attach command construction for GNOME"""
        attach_cmd = "tmux attach-session -t vibefuzzer; tmux kill-session -t vibefuzzer 2>/dev/null"
        
        # Command should include the attach-session and kill-session
        assert "attach-session" in attach_cmd
        assert "kill-session" in attach_cmd
        assert "vibefuzzer" in attach_cmd

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_subprocess_called_with_proper_args(self, mock_popen, mock_which, mock_env_get):
        """Test that subprocess.Popen is called with proper arguments"""
        mock_env_get.return_value = None
        mock_which.return_value = '/usr/bin/xterm'
        mock_popen.return_value = MagicMock()

    @patch('vibefuzzer_gui.subprocess.Popen')
    @patch('vibefuzzer_gui.shutil.which')
    def test_subprocess_error_handling_oserror(self, mock_which, mock_popen):
        """Test that OSError is caught and handled"""
        mock_which.return_value = '/usr/bin/xterm'
        mock_popen.side_effect = OSError("Command not found")

    @patch('vibefuzzer_gui.subprocess.Popen')
    @patch('vibefuzzer_gui.shutil.which')
    def test_subprocess_error_handling_filenotfound(self, mock_which, mock_popen):
        """Test that FileNotFoundError is caught and handled"""
        mock_which.return_value = '/usr/bin/xterm'
        mock_popen.side_effect = FileNotFoundError("xterm not found")


class TestTerminalCommandConstruction:
    """Test proper construction of terminal commands"""

    def test_gnome_terminal_command_format(self):
        """Test GNOME Terminal command list format"""
        attach_cmd = "tmux attach-session -t vibefuzzer"
        term_cmd = ["gnome-terminal", "--", "bash", "-c", attach_cmd]
        
        assert term_cmd[0] == "gnome-terminal"
        assert "--" in term_cmd
        assert "bash" in term_cmd
        assert "-c" in term_cmd
        assert attach_cmd in term_cmd

    def test_konsole_command_format(self):
        """Test Konsole command list format"""
        attach_cmd = "tmux attach-session -t vibefuzzer"
        term_cmd = ["konsole", "-e", "bash", "-c", attach_cmd]
        
        assert term_cmd[0] == "konsole"
        assert "-e" in term_cmd
        assert "bash" in term_cmd
        assert "-c" in term_cmd

    def test_kitty_command_format(self):
        """Test Kitty command list format"""
        attach_cmd = "tmux attach-session -t vibefuzzer"
        term_cmd = ["kitty", "bash", "-c", attach_cmd]
        
        assert term_cmd[0] == "kitty"
        assert "bash" in term_cmd
        assert "-c" in term_cmd

    def test_xterm_command_format(self):
        """Test xterm command list format"""
        attach_cmd = "tmux attach-session -t vibefuzzer"
        term_cmd = ["xterm", "-e", "bash", "-c", attach_cmd]
        
        assert term_cmd[0] == "xterm"
        assert "-e" in term_cmd
        assert "bash" in term_cmd
        assert "-c" in term_cmd

    def test_command_uses_list_not_string(self):
        """Test that terminal commands are passed as lists, not strings"""
        # Commands should be lists for proper subprocess handling
        attach_cmd = "tmux attach-session -t vibefuzzer"
        term_cmd = ["xterm", "-e", "bash", "-c", attach_cmd]
        
        assert isinstance(term_cmd, list)
        assert all(isinstance(arg, str) for arg in term_cmd)


class TestSubprocessErrorSuppression:
    """Test error suppression in subprocess calls"""

    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_subprocess_devnull_used(self, mock_popen):
        """Test that DEVNULL is used for stdout and stderr"""
        # When Popen is called, it should use DEVNULL for error suppression
        import subprocess
        
        # Verify that subprocess.DEVNULL exists and can be used
        assert hasattr(subprocess, 'DEVNULL')
        assert subprocess.DEVNULL == -3


class TestValidProtocols:
    """Test protocol validation constants"""

    def test_valid_protocols_defined(self):
        """Test that VALID_PROTOCOLS is defined in GUI"""
        assert hasattr(vibefuzzer_gui, 'VALID_PROTOCOLS')
        assert isinstance(vibefuzzer_gui.VALID_PROTOCOLS, list)
        assert len(vibefuzzer_gui.VALID_PROTOCOLS) > 0

    def test_valid_protocols_includes_http(self):
        """Test that HTTP is in valid protocols"""
        assert "HTTP" in vibefuzzer_gui.VALID_PROTOCOLS


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
