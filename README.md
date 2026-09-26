# BountyHunter Agent

Autonomous, **scope-enforced** bug bounty hunting agent. Finds vulnerabilities on
authorized programs; every report draft requires **human approval** before submission.

See `PLAN.md` for the full architecture and roadmap.

## Safety model (M1)

- **Rulebook-driven scope**: every program gets a YAML rulebook (in-scope hosts,
  wildcards, path prefixes, out-of-scope list, rate limits, automation policy).
- **Enforcing HTTP client**: all agent network traffic goes through one client that
  blocks anything not explicitly in scope (fail-closed), rate-limits per host, and
  writes a hash-chained audit log of every request.
- **Private-range guard**: loopback/private/link-local IPs are blocked unless a human
  explicitly listed them (used for local lab targets).

## Setup (WSL / Linux — recommended)

The recon toolchain runs natively in Linux. With Go installed:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
export PATH="$HOME/go/bin:$PATH"   # add to ~/.bashrc

python3 -m venv .venv && . .venv/bin/activate
pip install -e . pytest
pytest -q
bounty-agent doctor                 # should show all green, no Docker needed
```

Keep the repo on the WSL filesystem (~/...), not /mnt/c, for acceptable I/O.

## Setup (Windows alternative)

```bash
uv sync
```

On Windows, drop ProjectDiscovery `windows_amd64` exes into `bin/` (gitignored) —
native binaries take precedence over the Docker fallback.

## Configure a free LLM (OpenRouter example)

```bash
export AGENT_LLM_MODEL="deepseek/deepseek-chat:free"
export AGENT_LLM_BASE_URL="https://openrouter.ai/api/v1"
export AGENT_LLM_API_KEY="sk-or-..."   # free account key
```

Any OpenAI-compatible endpoint works (free gateways, local llama.cpp/LM Studio, etc.).

## Try it locally (authorized lab target)

```bash
# terminal 1 — intentionally vulnerable local app
uv run python examples/lab_app.py --port 8765

# terminal 2 — verify the scope layer first
uv run bounty-agent test-scope examples/lab.program.yaml http://127.0.0.1:8765/robots.txt http://evil.example/

# hunt
uv run bounty-agent hunt examples/lab.program.yaml \
  --objective "Enumerate the app at http://127.0.0.1:8765 and find concrete vulnerabilities (XSS, IDOR, open redirect)."
```

## CLI

```bash
uv run bounty-agent hunt <program.yaml> --objective "..." [--max-steps 15]
uv run bounty-agent test-scope <program.yaml> <url> [<url>...]
uv run bounty-agent findings
uv run bounty-agent verify-audit
```
