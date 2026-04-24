# VibeFuzzer Test Suite - Complete Organization

Comprehensive test suite with 2,079 lines of test code organized into four test types.

## Test Types Overview

### 1. **Unit Tests** (4 files, 1,081 lines)
Isolated tests for individual components without external dependencies.

**Files:**
- `test_afl_wrapper.py` (318 lines) - 27 tests
- `test_seed_gen.py` (331 lines) - 28 tests
- `test_tmux_ui.py` (175 lines) - 8 test classes
- `test_vibefuzzer_gui.py` (257 lines) - 19 tests

**Scope:**
- Lightweight, fast execution
- Extensive mocking of external dependencies
- CI/CD friendly (no tmux, AFL++, Ollama required)
- Each function tested in isolation

### 2. **Integration Tests** (1 file, 316 lines)
Tests for interactions between multiple components.

**File:** `test_integration.py`

**Test Classes:**
- `TestWrapperSeedGenIntegration` - Wrapper ↔ seed_gen
- `TestWrapperTmuxUIIntegration` - Wrapper ↔ tmux_ui  
- `TestGUITerminalIntegration` - GUI ↔ terminal detection
- `TestSeedGenOllamaIntegration` - seed_gen ↔ Ollama API
- `TestWrapperArgumentParsing` - Args → command building

**What It Tests:**
- How AFL++ wrapper calls seed generation
- How wrapper launches tmux sessions
- How GUI detects and launches terminals
- How seed_gen integrates with Ollama
- Full command pipeline from parsed args

### 3. **System Tests** (1 file, 320 lines)
End-to-end tests of complete workflows.

**File:** `test_system.py`

**Test Classes:**
- `TestCompleteGUIWorkflow` - Full GUI flow to fuzzing
- `TestCompleteWrapperWorkflow` - Full fuzzer setup
- `TestErrorRecovery` - Graceful error handling
- `TestProtocolSupport` - All protocols work correctly
- `TestEnvironmentConsistency` - Env vars consistent throughout

**What It Tests:**
- Complete workflows from start to finish
- Error handling and recovery
- Protocol support across all six protocols
- Environment consistency throughout workflow
- End-to-end data flow

### 4. **Interface Tests** (1 file, 335 lines)
Tests for GUI/UI components and cross-platform support.

**File:** `test_interface.py`

**Test Classes:**
- `TestTerminalDetectionUI` - Terminal detection on Linux
- `TestCrossPlatformUI` - Windows/WSL, macOS, Linux
- `TestTerminalCommandFormatting` - Command structure
- `TestUIErrorHandling` - Error messages to user
- `TestUIProtocolSelection` - Protocol selection UI

**What It Tests:**
- Linux terminal detection (GNOME, Konsole, Kitty, xterm)
- Windows/WSL support (wt.exe, cmd.exe)
- macOS support (iTerm, Terminal.app)
- Proper terminal command formatting
- Error handling and user feedback
- Protocol selection UI consistency

## Test Statistics

| Metric | Count |
|--------|-------|
| **Total Lines** | 2,079 |
| **Test Files** | 7 |
| **Test Classes** | ~80+ |
| **Test Methods** | ~100+ |
| **Unit Tests** | ~82 |
| **Integration Tests** | ~10 |
| **System Tests** | ~15 |
| **Interface Tests** | ~20+ |

## Running Tests

### Run by Type

```bash
# Unit tests only (fast, ~2 seconds)
pytest tests/ -m unit -v

# Integration tests only
pytest tests/test_integration.py -v

# System tests only (E2E)
pytest tests/test_system.py -v

# Interface tests only (UI)
pytest tests/test_interface.py -v
```

### Run All Tests

```bash
# All tests with verbose output
pytest tests/ -v

# All tests with coverage report
pytest tests/ -v --cov=. --cov-report=html

# All tests except system tests (faster CI)
pytest tests/ -v -m "not system"
```

### Run Specific File

```bash
pytest tests/test_afl_wrapper.py -v
pytest tests/test_integration.py -v
pytest tests/test_system.py -v
pytest tests/test_interface.py -v
```

## GitHub Actions Workflow

The updated `.github/workflows/tests.yml` runs:

1. **C/C++ Tests** (ollama_test, mutator_test)
2. **Unit Tests** - Fast validation of components
3. **Integration Tests** - Component interaction testing
4. **System Tests** - End-to-end workflow testing
5. **Interface Tests** - UI/terminal testing
6. **Coverage Report** - All tests combined with coverage metrics

Each test type has clear section headers in the CI output for easy identification.

## Test Coverage by Component

### vibefuzzer_gui.py
- ✅ GUI initialization
- ✅ Terminal detection (Linux, macOS, Windows/WSL)
- ✅ Terminal command construction
- ✅ Error handling
- ✅ Tmux session attachment
- ✅ Configuration validation

### afl++wrapper.py  
- ✅ Environment setup
- ✅ Preflight checks
- ✅ Binary building
- ✅ Instrumentation verification
- ✅ AFL++ command construction
- ✅ Argument parsing
- ✅ Protocol support (6 protocols)

### seed_gen.py
- ✅ Ollama connection verification
- ✅ Protocol inference
- ✅ Seed template retrieval
- ✅ Prompt building
- ✅ LLM output cleaning
- ✅ Seed file generation

### tmux_ui.py
- ✅ Session creation
- ✅ Environment filtering
- ✅ Bash command construction
- ✅ Error handling
- ✅ Special character handling

### C Code (mutator.c, ollama.c)
- ✅ Compiled and tested via C test suite
- ✅ Integration tested via Python tests

## Mocking Strategy

All tests use comprehensive mocking:

| Component | Mocked? | Why? |
|-----------|---------|------|
| subprocess | Yes | Avoid actual command execution |
| ollama API | Yes | No Ollama daemon required |
| File I/O | Partial | Use tempdir when needed |
| shutil.which | Yes | Simulate tool availability |
| os.environ | Yes | Isolate environment changes |
| GUI framework | Yes | customtkinter not required |

## CI/CD Pipeline Output

The GitHub Actions workflow now shows clear sections:

```
========================================= 
Running Unit Tests (test_*.py)
=========================================
✓ test_afl_wrapper.py (27 tests)
✓ test_seed_gen.py (28 tests)
✓ test_tmux_ui.py (8 tests)
✓ test_vibefuzzer_gui.py (19 tests)

=========================================
Running Integration Tests
=========================================
✓ test_integration.py (10 tests)

=========================================
Running System Tests (End-to-End)
=========================================
✓ test_system.py (15 tests)

=========================================
Running Interface Tests (GUI/UI)
=========================================
✓ test_interface.py (20+ tests)

=========================================
Running All Tests with Coverage Report
=========================================
Coverage: 65%+ across all modules
```

## Test Execution Time

Typical CI execution times:

- **Unit Tests**: ~2-3 seconds
- **Integration Tests**: ~2-3 seconds
- **System Tests**: ~3-4 seconds
- **Interface Tests**: ~2-3 seconds
- **Coverage Report**: ~1-2 seconds
- **Total**: ~10-15 seconds

## Adding New Tests

### Adding to Unit Tests
```python
# In test_afl_wrapper.py, test_seed_gen.py, etc.
@pytest.mark.unit
def test_new_feature(self):
    """Test description"""
    # test code
```

### Adding to Integration Tests
```python
# In test_integration.py
@pytest.mark.integration
class TestNewComponentIntegration:
    def test_component_interaction(self):
        """Test how components work together"""
        # test code
```

### Adding to System Tests
```python
# In test_system.py
@pytest.mark.system
class TestNewWorkflow:
    def test_end_to_end_flow(self):
        """Test complete workflow"""
        # test code
```

### Adding to Interface Tests
```python
# In test_interface.py
@pytest.mark.interface
class TestNewUIFeature:
    def test_ui_component(self):
        """Test GUI/UI component"""
        # test code
```

## Best Practices

1. **Unit Tests First** - Start with unit tests for new functions
2. **Mock External Dependencies** - Don't require external services
3. **Use Descriptive Names** - Test names should explain what they test
4. **One Assertion Per Test** - Keep tests focused and clear
5. **Mark Tests Properly** - Use `@pytest.mark.unit/integration/system/interface`
6. **Document Complex Tests** - Add docstrings explaining the test
7. **Keep Tests Fast** - Unit tests should complete in < 100ms

## Troubleshooting

### Tests fail in CI but pass locally
- Check Python version (CI uses 3.11)
- Verify pytest plugins installed
- Check environment variables

### Coverage is low
- Add more unit tests for uncovered functions
- Check for integration gaps
- Review interface tests

### Tests timeout
- Reduce test scope (move to unit tests)
- Add timeout limits to slow tests
- Mock external service calls

## Related Files

- `conftest.py` - Pytest configuration with test markers
- `.github/workflows/tests.yml` - GitHub Actions workflow
- `requirements.txt` - Python dependencies
- `requirements-test.txt` - Test-only dependencies
- `tests/README.md` - Testing documentation
- `TESTING.md` - Test overview
