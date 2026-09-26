"""Recon tool runner: executes ProjectDiscovery tools via local binaries
(preferred) or Docker images (fallback), with timeouts and JSON-lines parsing.

Nothing here knows about scope — wrappers are responsible for passing only
rulebook-validated targets into `ToolRunner.run`.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass


class ReconError(Exception):
    pass


class ToolUnavailable(ReconError):
    pass


class ToolError(ReconError):
    pass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    image: str  # docker image
    binary: str  # local binary name


SUBFASTER = ToolSpec("subfaster", "", "subfaster")
HTTPX = ToolSpec("httpx", "projectdiscovery/httpx", "httpx")
NUCLEI = ToolSpec("nuclei", "projectdiscovery/nuclei", "nuclei")
KATANA = ToolSpec("katana", "projectdiscovery/katana", "katana")
XNLINKFINDER = ToolSpec("xnLinkFinder", "", "xnLinkFinder")
INTERACTSH = ToolSpec("interactsh", "projectdiscovery/interactsh", "interactsh-client")
ALL_SPECS = (SUBFASTER, HTTPX, NUCLEI, KATANA, XNLINKFINDER, INTERACTSH)


def parse_json_lines(text: str) -> list[dict]:
    """Parse tool stdout as JSON lines, skipping non-JSON noise."""
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            out.append(data)
    return out


class ToolRunner:
    """Runs tools, preferring local binaries in bin/ or PATH, else Docker."""

    def __init__(self) -> None:
        self.modes: dict[str, str | None] = self.detect()

    def detect(self) -> dict[str, str | None]:
        modes: dict[str, str | None] = {}
        docker_ok = shutil.which("docker") is not None
        for spec in ALL_SPECS:
            if self._binary_path(spec) is not None:
                modes[spec.name] = "binary"
            elif docker_ok:
                modes[spec.name] = "docker"
            else:
                modes[spec.name] = None
        return modes

    def _binary_path(self, spec: ToolSpec) -> str | None:
        exe = spec.binary + (".exe" if os.name == "nt" else "")
        # 1. project-local bin/ (gitignored) — highest precedence
        local = os.path.join("bin", exe)
        if os.path.isfile(local):
            return local
        # 2. pip console scripts inside the active virtualenv (xnLinkFinder)
        venv_bin = os.path.dirname(sys.executable)
        candidate = os.path.join(venv_bin, exe)
        if os.path.isfile(candidate):
            return candidate
        # 3. go install location — must precede PATH lookup: an activated Python
        #    venv shadows `httpx` with the unrelated Python httpx CLI of the same name
        for home_dir in (os.path.expanduser("~/go/bin"), os.path.expanduser("~/.local/bin")):
            candidate = os.path.join(home_dir, spec.binary)
            if os.path.isfile(candidate):
                return candidate
        # 4. anything on PATH
        return shutil.which(spec.binary)

    def run(
        self,
        spec: ToolSpec,
        args: list[str],
        stdin_text: str | None = None,
        timeout: float = 300.0,
        docker_mounts: list[str] | None = None,
    ) -> str:
        mode = self.modes.get(spec.name)
        env = None
        if mode == "binary":
            path = self._binary_path(spec)
            if path is None:
                raise ToolUnavailable(f"{spec.binary} binary disappeared — rerun detect")
            cmd = [path, *args]
        elif mode == "docker":
            cmd = ["docker", "run", "--rm", "-i", *(docker_mounts or []), spec.image, *args]
            # Git Bash on Windows rewrites POSIX-looking arguments; disable that
            # for docker calls (named volumes like nuclei-templates:/root/...).
            env = {**os.environ, "MSYS_NO_PATHCONV": "1", "MSYS2_ARG_CONV_EXCL": "*"}
        else:
            raise ToolUnavailable(
                f"{spec.name} not available — run 'bounty-agent doctor' for setup hints"
            )
        try:
            proc = subprocess.run(
                cmd,
                input=stdin_text,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"{spec.name} timed out after {timeout}s") from exc
        except FileNotFoundError as exc:
            raise ToolUnavailable(f"cannot execute {cmd[0]}: {exc}") from exc
        if proc.returncode != 0:
            tail = (proc.stderr or "").strip().splitlines()[-5:]
            raise ToolError(f"{spec.name} exited {proc.returncode}: " + " | ".join(tail))
        return proc.stdout


def gather_environment(
    runner: ToolRunner | None = None,
    docker_binary: str | None = None,
    daemon_ok: bool | None = None,
    api_key_set: bool | None = None,
) -> list[dict]:
    """Doctor rows: what's installed and how to fix what isn't.

    Injectable parameters exist for testing; pass None to auto-detect.
    """
    rows: list[dict] = []
    docker_bin = docker_binary if docker_binary is not None else shutil.which("docker")
    if daemon_ok is None:
        daemon_ok = False
        if docker_bin:
            try:
                daemon_ok = (
                    subprocess.run(
                        [docker_bin, "info", "--format", "ok"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    ).returncode
                    == 0
                )
            except Exception:
                daemon_ok = False
    rows.append(
        {
            "component": "docker",
            "status": "daemon ok" if daemon_ok else ("cli only" if docker_bin else "missing"),
            "hint": "" if daemon_ok else "install Docker Desktop for containerized tools",
        }
    )
    status_map = {"docker": "docker image", "binary": "local binary"}
    modes = runner.modes if runner is not None else {}
    for spec in ALL_SPECS:
        mode = modes.get(spec.name)
        rows.append(
            {
                "component": spec.name,
                "status": status_map.get(mode or "", "MISSING"),
                "hint": (f"go install -v github.com/melvinsh/subfaster/v2/cmd/subfaster@latest"
                         if spec.name == "subfaster" else
                         f"go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
                         if spec.name == "katana" else
                         f"pip install xnLinkFinder"
                         if spec.name == "xnLinkFinder" else
                         f"go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
                         if spec.name == "interactsh" else
                         f"docker pull {spec.image} (or drop binary in bin/)") if not mode else "",
            }
        )
    key_set = api_key_set if api_key_set is not None else bool(os.environ.get("AGENT_LLM_API_KEY"))
    rows.append(
        {
            "component": "AGENT_LLM_API_KEY",
            "status": "set" if key_set else "NOT SET",
            "hint": "" if key_set else "export AGENT_LLM_API_KEY=<free OpenRouter key>",
        }
    )
    return rows
