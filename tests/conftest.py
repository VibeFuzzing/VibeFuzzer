"""
pytest configuration file for VibeFuzzer tests

Provides fixtures and configuration for unit, integration, system, and interface testing.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


def pytest_configure(config):
    """Configure pytest with markers and settings"""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test (multiple components)"
    )
    config.addinivalue_line(
        "markers", "system: mark test as a system test (end-to-end)"
    )
    config.addinivalue_line(
        "markers", "interface: mark test as an interface test (UI/GUI components)"
    )
