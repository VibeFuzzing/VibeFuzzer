import sys
import ollama
import os
import subprocess
from pathlib import Path
import shutil
import json

# Usage: python fuzz.py [target] [format]
MODEL = 'llama3:latest'
TARGET = ''
FORMAT = ''


def resolve_executable(target: str) -> str | None:
    """Resolve a target name/path to an executable path.
    Returns absolute path string if found, or None.
    """
    script_dir = Path(__file__).parent

    # If empty target, nothing to do
    if not target:
        return None

    p = Path(target)

    # If target is absolute -> use it directly (but still try adding .exe on Windows)
    if p.is_absolute():
        candidate = p
    else:
        # Append the path parts to the script directory so "vulnerable/vuln"
        # becomes script_dir / 'vulnerable' / 'vuln'
        candidate = script_dir.joinpath(*p.parts)

    # If candidate exists and is a file, return it (use .resolve() for absolute)
    if candidate.exists() and candidate.is_file():
        return str(candidate.resolve())

    # On Windows: try adding .exe suffix to the candidate path
    if os.name == 'nt':
        maybe = candidate.with_suffix('.exe')
        if maybe.exists() and maybe.is_file():
            return str(maybe.resolve())

    # If not found by path, try locating on PATH (shutil.which)
    which = shutil.which(target)
    if which:
        return which

    # On Windows, try looking for target + .exe on PATH too
    if os.name == 'nt':
        which_exe = shutil.which(target + '.exe')
        if which_exe:
            return which_exe

    return None

def main():
    global TARGET, FORMAT

    if len(sys.argv) < 2:
        print("Usage: python fuzz.py [target]")
        sys.exit(1)

    TARGET = resolve_executable(sys.argv[1])
    FORMAT = resolve_executable(sys.argv[2])

    with open(FORMAT, 'r') as file:
        format_str = file.read().strip()
    
    system = ''
    with open('system.txt', 'r') as file:
        system = file.read()

    memory = 'All I know is that an example input is "' + format_str + '". I should try it to figure out what happens.'
    while True:
        output_str = ''
        try:
            output_str = ollama.generate(model=MODEL, prompt=memory, system=system).response
        except Exception as e:
            print('\nError running ollama.generate:', e)
            print('If the model is installed but you still see errors, try running the model with the CLI:')
            print(f'  ollama run {MODEL}')
            sys.exit(1)

        try:
            cases = json.loads(output_str)['input']
        except Exception as e:
            print('output string ("' + output_str + '") had non-JSON data, retrying...')
            continue

        print('Trying "' + cases + '"...')
        try:
            res = subprocess.run([TARGET] + cases.split(' '), capture_output=True, text=True, timeout=10)
        except Exception as e:
            print('attempted input could not be correctly executed by the fuzzer, retrying...')
            continue
        
        response = ''
        if res.returncode == 0:
            response = 'The program, unfortunately, ran without error.'
        elif res.returncode < 0:
            response = 'The program crashed with an exit code of ' + str(res.returncode) + '.'
        elif res.returncode > 0:
            response = 'The program exited with an error code of ' + str(res.returncode) + '.'
        print('Response:', response)
        response += ' Responding conversationally, how would you summarize what you know for the next iteration?'

        messages = [{'role': 'system', 'content': system}, {'role': 'user', 'content': memory}, {'role': 'assistant', 'content': output_str}, {'role': 'user', 'content': response}]

        try:
            output_str = ollama.chat(model=MODEL, messages=messages).message.content
        except Exception as e:
            print('\nError running ollama.chat:', e)
            print('If the model is installed but you still see errors, try running the model with the CLI:')
            print(f'  ollama run {MODEL}')
            sys.exit(1)
        
        memory = 'As a reminder, my initial example to try was "' + format_str + '", and the input I tried this time was "' + cases + '". ' + output_str
        print('New memory:', memory)


if __name__ == '__main__':
  main()
