# tmux_ui.py
import shlex
import shutil
import subprocess

def launch_in_tmux(session_name: str, primary_cmd: list, primary_env: dict, secondary_cmd: list, secondary_env: dict):
    """
    Lightweight tmux launcher using send-keys.
    Leaves the session detached so the wrapper doesn't block.
    """
    if not shutil.which("tmux"):
        raise RuntimeError("tmux not found. Install it with: sudo apt install tmux")

    def build_bash_string(env: dict, cmd: list) -> str:
        env_vars = []
        for k, v in env.items():
            if k.startswith(("AFL_", "OLLAMA_", "DUMMY_", "ASAN_")):
                env_vars.append(f"{k}={shlex.quote(str(v))}")
        env_str = " ".join(env_vars)
        cmd_str = " ".join(shlex.quote(c) for c in cmd)
        return f"{env_str} {cmd_str}; tmux kill-session -t {shlex.quote(session_name)} 2>/dev/null"

    # Debug mode — both panes need their UI visible
    secondary_env = secondary_env.copy()
    secondary_env.pop("AFL_NO_UI", None)

    print(f"[*] Booting Tmux Debug UI: {session_name}")

    subprocess.run(["tmux", "kill-session", "-t", session_name], stderr=subprocess.DEVNULL)
    subprocess.run(["tmux", "new-session", "-d", "-s", session_name])

    p_str = build_bash_string(primary_env, primary_cmd)
    subprocess.run(["tmux", "send-keys", "-t", f"{session_name}:0.0", p_str, "C-m"])

    subprocess.run(["tmux", "split-window", "-h", "-t", f"{session_name}:0"])

    s_str = build_bash_string(secondary_env, secondary_cmd)
    subprocess.run(["tmux", "send-keys", "-t", f"{session_name}:0.1", s_str, "C-m"])

    print(f"\n[*] Tmux session '{session_name}' is running in the background.")
    print(f"    To view UI:      tmux attach -t {session_name}")
    print(f"    To kill session: tmux kill-session -t {session_name}\n")