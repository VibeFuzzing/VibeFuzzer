# VibeFuzzer Test Suite

This directory contains comprehensive unit tests for the VibeFuzzer project, covering:

- **test_afl_wrapper.py** - Tests for AFL++ wrapper functionality
- **test_tmux_ui.py** - Tests for tmux session management
- **test_seed_gen.py** - Tests for LLM-based seed generation
- **test_vibefuzzer_gui.py** - Tests for GUI components

## Setup

### Install Test Dependencies

```bash
# Install test requirements
pip install -r requirements-test.txt

# Or using apt for system-wide installation
sudo apt install python3-pytest python3-pytest-mock
```

### Virtual Environment (Recommended)

```bash
# Create a virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install dependencies
pip install -r ../requirements.txt -r requirements-test.txt
```

## Running Tests

### Run All Tests

```bash
pytest -v
```

### Run Specific Test File

```bash
pytest test_afl_wrapper.py -v
pytest test_tmux_ui.py -v
pytest test_seed_gen.py -v
pytest test_vibefuzzer_gui.py -v
```

### Run Specific Test Class

```bash
pytest test_afl_wrapper.py::TestEnvironmentSetup -v
```

### Run Specific Test

```bash
pytest test_afl_wrapper.py::TestEnvironmentSetup::test_setup_aflpp_env_returns_dict -v
```

### Run with Coverage

```bash
# Install coverage
pip install coverage

# Run with coverage report
pytest --cov=.. --cov-report=html tests/

# View report
open htmlcov/index.html
```

### Run Only Unit Tests

```bash
pytest -m unit -v
```

## Test Organization

### test_afl_wrapper.py

Tests for the main AFL++ wrapper functionality:

- **TestEnvironmentSetup** - AFL++ environment configuration
- **TestPreflightChecks** - Dependency verification
- **TestInstrumentationVerification** - Binary instrumentation detection
- **TestBuildTarget** - Target compilation and building
- **TestAutoDetectBinary** - Binary auto-detection
- **TestBuildAFLppCmd** - AFL++ command construction
- **TestParseArgs** - Command-line argument parsing
- **TestValidProtocols** - Protocol validation

### test_tmux_ui.py

Tests for tmux session launching:

- **TestLaunchInTmux** - Session creation and management
- **TestBuildBashString** - Bash command construction with env vars
- Environment variable filtering and quoting

### test_seed_gen.py

Tests for LLM-based seed generation:

- **TestVerifyOllamaConnection** - Ollama connectivity
- **TestGetProtocolSeeds** - Protocol seed template retrieval
- **TestBuildMutatorPrompt** - Prompt construction for LLM
- **TestCleanMutatorOutput** - LLM output processing
- **TestGenerateLLMSeeds** - Seed generation workflow

### test_vibefuzzer_gui.py

Tests for GUI components:

- **TestVibeFuzzerGUIInitialization** - GUI initialization
- **TestTerminalDetection** - Terminal emulator detection
- **TestTmuxSessionAttachment** - Tmux session attachment
- **TestTerminalCommandConstruction** - Terminal command building
- **TestSubprocessErrorSuppression** - Error handling
- **TestValidProtocols** - Protocol validation in GUI

## Mocking Strategy

The test suite uses extensive mocking to avoid external dependencies:

- **subprocess.run** - Mocked to avoid executing real commands
- **ollama.list/generate** - Mocked to avoid requiring Ollama daemon
- **shutil.which** - Mocked to simulate tool availability
- **Path.exists** - Mocked to test file handling without filesystem
- **os.environ** - Mocked/patched to isolate environment changes

## Continuous Integration

The test suite is designed to run in CI/CD environments (e.g., GitHub Actions) without requiring:

- tmux
- AFL++
- Ollama
- External services

All external dependencies are mocked at the subprocess/API level.

## Adding New Tests

When adding new tests:

1. Follow the existing naming convention: `test_<function_or_feature>_<scenario>.py`
2. Use descriptive test names that explain what is being tested
3. Include docstrings explaining the purpose of each test
4. Use mocking for external dependencies
5. Keep tests isolated and independent
6. Add appropriate markers (`@pytest.mark.unit` or `@pytest.mark.integration`)

Example:

```python
def test_example_functionality(self):
    """Test that example function returns correct value"""
    with patch('module.external_call') as mock_call:
        mock_call.return_value = 'expected'
        result = function_under_test()
        assert result == 'expected'
```

## Troubleshooting

### Import Errors

If you get import errors for `customtkinter` or other GUI libraries:

```bash
# Install all dependencies
pip install -r ../requirements.txt
```

### Mock Errors

If mocks aren't working properly:

1. Verify the correct module path is being patched
2. Use `@patch('full.module.path.Class.method')` format
3. Check that patches are applied in the correct order (bottom-up)

### File Not Found Errors

If tests fail looking for files:

1. Verify you're in the correct directory
2. Use absolute paths from `Path(__file__).parent`
3. Check that test data exists or is properly mocked

## Performance

Tests should complete in under 5 seconds total. If individual tests are slow:

1. Consider splitting into smaller tests
2. Use mocks to avoid filesystem/network I/O
3. Use `pytest-xdist` for parallel execution

```bash
# Run tests in parallel
pip install pytest-xdist
pytest -n auto
```

## Contributing

When modifying tested code:

1. Run tests before committing
2. Add tests for new functionality
3. Ensure all tests pass with `pytest -v`
4. Update documentation if test expectations change

