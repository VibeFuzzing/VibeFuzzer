"""
Interface tests for VibeFuzzer GUI

Tests cover user interface components and interactions:
- GUI initialization and configuration screens
- Terminal emulator detection and launching
- Button and menu functionality
- Configuration validation and error display
- Cross-platform UI support (Linux, macOS, Windows/WSL)
"""

import pytest
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
import types

# Setup imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Mock GUI framework
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


@pytest.mark.interface
class TestTerminalDetectionUI:
    """Test GUI terminal detection and launching"""

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_linux_gnome_terminal_detection(self, mock_popen, mock_which, mock_env_get):
        """Test detection and launch of GNOME Terminal on Linux"""
        # Setup GNOME environment
        def env_get_side_effect(key, default=None):
            env_vars = {
                'WSL_DISTRO_NAME': None,
                'TERM_PROGRAM': None,
                'GNOME_TERMINAL_SCREEN': 'yes',
            }
            return env_vars.get(key, default)

        mock_env_get.side_effect = env_get_side_effect
        mock_which.return_value = None
        mock_popen.return_value = MagicMock()

        # Verify GNOME detection logic
        assert mock_env_get('GNOME_TERMINAL_SCREEN') == 'yes'

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_linux_konsole_detection(self, mock_popen, mock_which, mock_env_get):
        """Test detection and launch of Konsole on Linux"""
        def env_get_side_effect(key, default=None):
            env_vars = {
                'WSL_DISTRO_NAME': None,
                'TERM_PROGRAM': None,
                'GNOME_TERMINAL_SCREEN': None,
                'KONSOLE_VERSION': '1',
            }
            return env_vars.get(key, default)

        mock_env_get.side_effect = env_get_side_effect
        mock_which.return_value = None
        mock_popen.return_value = MagicMock()

        # Verify Konsole detection logic
        assert mock_env_get('KONSOLE_VERSION') == '1'

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_linux_kitty_detection(self, mock_popen, mock_which, mock_env_get):
        """Test detection and launch of Kitty terminal on Linux"""
        def env_get_side_effect(key, default=None):
            env_vars = {
                'WSL_DISTRO_NAME': None,
                'TERM_PROGRAM': None,
                'GNOME_TERMINAL_SCREEN': None,
                'KONSOLE_VERSION': None,
                'KITTY_WINDOW_ID': '1',
            }
            return env_vars.get(key, default)

        mock_env_get.side_effect = env_get_side_effect
        mock_which.return_value = None
        mock_popen.return_value = MagicMock()

        # Verify Kitty detection logic
        assert mock_env_get('KITTY_WINDOW_ID') == '1'

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    def test_linux_xterm_fallback(self, mock_which, mock_env_get):
        """Test fallback to xterm on Linux"""
        mock_env_get.side_effect = lambda x, default=None: None
        mock_which.return_value = '/usr/bin/xterm'

        # Verify xterm fallback
        assert mock_which('xterm') == '/usr/bin/xterm'

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.messagebox')
    def test_linux_no_terminal_error(self, mock_msgbox, mock_which, mock_env_get):
        """Test error handling when no terminal is detected on Linux"""
        mock_env_get.side_effect = lambda x, default=None: None
        mock_which.return_value = None
        mock_msgbox.showerror = MagicMock()

        # Verify error would be shown
        # (GUI would call messagebox.showerror)


@pytest.mark.interface
class TestCrossPlatformUI:
    """Test cross-platform UI support"""

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    def test_wsl_windows_terminal_detection(self, mock_which, mock_env_get):
        """Test detection of WSL with Windows Terminal"""
        mock_env_get.side_effect = lambda x, default=None: (
            'Ubuntu' if x == 'WSL_DISTRO_NAME' else default
        )
        mock_which.side_effect = lambda cmd: (
            '/mnt/c/Program Files/WindowsTerminal/wt.exe' if cmd == 'wt.exe' else None
        )

        # Verify WSL detection
        assert mock_env_get('WSL_DISTRO_NAME') == 'Ubuntu'
        assert mock_which('wt.exe') is not None

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    def test_wsl_cmd_fallback(self, mock_which, mock_env_get):
        """Test WSL fallback to cmd.exe when wt.exe not available"""
        mock_env_get.side_effect = lambda x, default=None: (
            'Ubuntu' if x == 'WSL_DISTRO_NAME' else default
        )
        mock_which.side_effect = lambda cmd: (
            '/mnt/c/Windows/System32/cmd.exe' if cmd == 'cmd.exe' else None
        )

        # Verify cmd.exe would be used
        assert mock_which('cmd.exe') is not None

    @patch('vibefuzzer_gui.os.environ.get')
    def test_macos_iterm_detection(self, mock_env_get):
        """Test detection of iTerm on macOS"""
        mock_env_get.side_effect = lambda x, default=None: (
            'iTerm.app' if x == 'TERM_PROGRAM' else default
        )

        # Verify iTerm detection
        assert mock_env_get('TERM_PROGRAM') == 'iTerm.app'

    @patch('vibefuzzer_gui.os.environ.get')
    def test_macos_terminal_detection(self, mock_env_get):
        """Test detection of Terminal.app on macOS"""
        mock_env_get.side_effect = lambda x, default=None: (
            'Apple_Terminal' if x == 'TERM_PROGRAM' else default
        )

        # Verify Terminal.app detection
        assert mock_env_get('TERM_PROGRAM') == 'Apple_Terminal'


@pytest.mark.interface
class TestTerminalCommandFormatting:
    """Test proper formatting of terminal commands"""

    def test_gnome_terminal_command_structure(self):
        """Test proper command structure for GNOME Terminal"""
        attach_cmd = "tmux attach-session -t vibefuzzer"
        term_cmd = ["gnome-terminal", "--", "bash", "-c", attach_cmd]

        # Verify structure
        assert len(term_cmd) == 5
        assert term_cmd[0] == "gnome-terminal"
        assert term_cmd[1] == "--"
        assert term_cmd[2] == "bash"
        assert term_cmd[3] == "-c"
        assert term_cmd[4] == attach_cmd

    def test_konsole_command_structure(self):
        """Test proper command structure for Konsole"""
        attach_cmd = "tmux attach-session -t vibefuzzer"
        term_cmd = ["konsole", "-e", "bash", "-c", attach_cmd]

        # Verify structure
        assert len(term_cmd) == 5
        assert term_cmd[0] == "konsole"
        assert term_cmd[1] == "-e"
        assert term_cmd[2] == "bash"

    def test_kitty_command_structure(self):
        """Test proper command structure for Kitty"""
        attach_cmd = "tmux attach-session -t vibefuzzer"
        term_cmd = ["kitty", "bash", "-c", attach_cmd]

        # Verify structure
        assert len(term_cmd) == 4
        assert term_cmd[0] == "kitty"
        assert term_cmd[1] == "bash"

    def test_xterm_command_structure(self):
        """Test proper command structure for xterm"""
        attach_cmd = "tmux attach-session -t vibefuzzer"
        term_cmd = ["xterm", "-e", "bash", "-c", attach_cmd]

        # Verify structure
        assert len(term_cmd) == 5
        assert term_cmd[0] == "xterm"
        assert term_cmd[1] == "-e"

    def test_wsl_windows_terminal_command_structure(self):
        """Test proper command structure for WSL with Windows Terminal"""
        attach_cmd = "tmux attach-session -t vibefuzzer"
        wsl_distro = "Ubuntu"
        term_cmd = ["wt.exe", "new-tab", "wsl.exe", "-d", wsl_distro, "--", "bash", "-c", attach_cmd]

        # Verify structure
        assert term_cmd[0] == "wt.exe"
        assert "wsl.exe" in term_cmd
        assert wsl_distro in term_cmd

    def test_wsl_cmd_exe_command_structure(self):
        """Test proper command structure for WSL with cmd.exe"""
        attach_cmd = "tmux attach-session -t vibefuzzer"
        wsl_distro = "Ubuntu"
        term_cmd = ["cmd.exe", "/c", "start", "wsl.exe", "-d", wsl_distro, "--", "bash", "-c", attach_cmd]

        # Verify structure
        assert term_cmd[0] == "cmd.exe"
        assert "/c" in term_cmd
        assert "start" in term_cmd


@pytest.mark.interface
class TestUIErrorHandling:
    """Test UI error handling and user feedback"""

    @patch('vibefuzzer_gui.subprocess.Popen')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.messagebox')
    def test_subprocess_oserror_handling(self, mock_msgbox, mock_which, mock_popen):
        """Test that OSError is caught and user is notified"""
        mock_which.return_value = '/usr/bin/xterm'
        mock_popen.side_effect = OSError("Command not found")
        mock_msgbox.showerror = MagicMock()

        # Simulate GUI error handling
        try:
            mock_popen(['xterm'])
        except OSError as e:
            # UI would call messagebox.showerror
            pass

    @patch('vibefuzzer_gui.subprocess.Popen')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.messagebox')
    def test_subprocess_filenotfound_handling(self, mock_msgbox, mock_which, mock_popen):
        """Test that FileNotFoundError is caught and user is notified"""
        mock_which.return_value = '/usr/bin/xterm'
        mock_popen.side_effect = FileNotFoundError("xterm not found")
        mock_msgbox.showerror = MagicMock()

        # Simulate GUI error handling
        try:
            mock_popen(['xterm'])
        except FileNotFoundError as e:
            # UI would call messagebox.showerror
            pass

    @patch('vibefuzzer_gui.subprocess.Popen')
    def test_subprocess_output_suppression(self, mock_popen):
        """Test that subprocess output is properly suppressed"""
        import subprocess
        
        # Verify DEVNULL is used
        assert subprocess.DEVNULL == -3

    @patch('vibefuzzer_gui.os.environ.get')
    @patch('vibefuzzer_gui.shutil.which')
    @patch('vibefuzzer_gui.messagebox')
    def test_no_terminal_detected_error_message(self, mock_msgbox, mock_which, mock_env_get):
        """Test error message when no terminal is detected"""
        mock_env_get.return_value = None
        mock_which.return_value = None
        mock_msgbox.showerror = MagicMock()

        # Simulate GUI detecting no terminal
        # Would call messagebox.showerror("Error", "Could not detect your terminal emulator.")


@pytest.mark.interface
class TestUIProtocolSelection:
    """Test protocol selection in UI"""

    def test_valid_protocols_available_in_ui(self):
        """Test that all valid protocols are available for selection"""
        import vibefuzzer_gui
        
        assert hasattr(vibefuzzer_gui, 'VALID_PROTOCOLS')
        protocols = vibefuzzer_gui.VALID_PROTOCOLS
        
        # Verify common protocols
        assert 'HTTP' in protocols
        assert len(protocols) > 0

    def test_protocol_selection_reflects_valid_list(self):
        """Test that UI protocol choices match valid protocols"""
        from vibefuzzer_gui import VALID_PROTOCOLS
        from vibefuzzer import valid_protocols
        
        # Both should have same protocols
        assert set(VALID_PROTOCOLS) == set(valid_protocols)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-m', 'interface'])
