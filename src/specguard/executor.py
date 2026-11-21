"""Allow-listed command execution in a materialised workspace.

What this module does:
* runs only actions named in `.specguard/actions.toml` (no shell, fixed argv);
* copies only the action's declared inputs that the policy's ceiling allows,
  plus the agent's own writes, into a fresh temporary directory;
* passes a minimal environment, so tokens in the parent environment are not
  inherited;
* applies a timeout and truncates output.

What it does NOT do: it is not an OS sandbox. The child process runs with the
user's privileges and could still open absolute paths, use the network or
read the original repository. Closing that gap needs an OS mechanism
(Capsicum capability mode with pre-opened directory descriptors on FreeBSD,
Landlock plus seccomp on Linux, or a container). This is planned thesis work.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import globmatch
from .inventory import Action, Inventory
from .policy import Policy

MAX_OUTPUT = 4000
TIMEOUT_S = 60


@dataclass(frozen=True)
class ExecOutcome:
    status: str  # "ok", "failed", "unavailable", "timeout"
    output: str
    exit_code: int | None
    files_in_workspace: int


def _minimal_env() -> dict[str, str]:
    keep = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC", "PATHEXT")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C", "SPECGUARD_WORKSPACE": "1"})
    return env


def workspace_files(action: Action, policy: Policy, inv: Inventory) -> list[str]:
    if not policy.enforce_invariants:
        return sorted(p for p in inv.files if not globmatch.match_any(inv.control_plane, p))
    out = []
    for path, info in inv.files.items():
        if not globmatch.match_any(action.inputs, path):
            continue
        if globmatch.match_any(inv.control_plane, path) or globmatch.match_any(inv.datastores, path):
            continue
        if info.label > policy.max_label:
            continue
        out.append(path)
    return sorted(out)


def run(action: Action, policy: Policy, inv: Inventory, overlay: dict[str, str], execute: bool = True) -> ExecOutcome:
    missing = [tool for tool in action.requires if shutil.which(tool) is None]
    if missing:
        return ExecOutcome("unavailable", f"toolchain not available on this machine: {', '.join(missing)}", None, 0)
    files = workspace_files(action, policy, inv)
    if not execute:
        return ExecOutcome("ok", "(dry run: action permitted, not executed)", None, len(files))
    with tempfile.TemporaryDirectory(prefix="specguard-ws-") as ws:
        wsp = Path(ws)
        for rel in files:
            dst = wsp / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(inv.root / rel, dst)
        for rel, text in overlay.items():
            dst = wsp / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(text, encoding="utf-8", newline="\n")
        argv = [sys.executable if a == "{python}" else a for a in action.argv]
        try:
            proc = subprocess.run(
                argv, cwd=wsp, env=_minimal_env(), capture_output=True, text=True,
                timeout=TIMEOUT_S, shell=False, check=False,
            )
        except subprocess.TimeoutExpired:
            return ExecOutcome("timeout", f"timed out after {TIMEOUT_S}s", None, len(files))
        except OSError as exc:
            return ExecOutcome("unavailable", f"could not start: {exc}", None, len(files))
        output = (proc.stdout + proc.stderr)
        if len(output) > MAX_OUTPUT:
            output = output[:MAX_OUTPUT] + "\n... output truncated"
        return ExecOutcome("ok" if proc.returncode == 0 else "failed", output, proc.returncode, len(files))
