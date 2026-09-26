"""M5b OOB callback loop: interactsh wrapper and correlation.

The agent is blind without an out-of-band channel: a server that fetches our
URL but never reflects anything leaves no differential we can see. interactsh
gives each probe a unique DNS/HTTP callback host; when the *target* triggers a
lookup, the interaction is correlated back by the payload's unique-id prefix.

Design:
- One ``interactsh-client`` process per agent run handles registration and
  polling; we spawn it with ``-json -ps -sf`` so payloads survive client
  restarts (session file + payload store).
- Payloads are RESERVED per probe (never shared), so one callback identifies
  exactly one probe.
- Correlation is conservative: a callback counts as evidence only when the
  payload was reserved by a known probe AND the interaction's unique-id
  matches. Unknown payloads are logged but never promote findings.
- Scope safety: the OOB payload travels only as parameter data inside
  in-scope requests. We never send requests to the OOB domain ourselves;
  the callback is made by the target, outside our scope layer.

Offline testing: ``FakeInteractshManager`` feeds scripted interactions without
any binary or network, so probe logic is testable anywhere.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
from typing import Any

DEFAULT_SERVERS = "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me"

_PAYLOAD_RE = re.compile(r"^[a-z0-9]{10,60}\.((?:[a-z0-9-]+\.)+[a-z]{2,})$", re.IGNORECASE)
_UNIQUE_ID_RE = re.compile(r"^[a-z0-9]{10,60}$", re.IGNORECASE)


class InteractshError(Exception):
    pass


class InteractshUnavailable(InteractshError):
    pass


def unique_id_of(payload: str) -> str:
    """The correlation-id prefix of an interactsh payload (text before the
    first dot)."""
    return payload.split(".", 1)[0] if "." in payload else ""


def valid_payload(payload: str) -> bool:
    return bool(_PAYLOAD_RE.match(payload or ""))


def parse_interaction_line(line: str) -> dict | None:
    """Parse one interactsh-client JSON line; None for noise/banners."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or "unique-id" not in data:
        return None
    return data


def parse_payload_store(text: str) -> list[str]:
    """Payload-store lines, one payload per line, order preserved."""
    out = []
    for ln in text.splitlines():
        p = ln.strip()
        if valid_payload(p) and p not in out:
            out.append(p)
    return out


class InteractshManager:
    """Spawns and drives one interactsh-client process.

    Usage:
        m = InteractshManager.start(n_payloads=4)
        payload = m.reserve("probe:ssrf:/fetch")
        ... inject payload into an in-scope request ...
        hits = m.poll("probe:ssrf:/fetch")   # [] until the target calls back
        m.stop()
    """

    def __init__(self, proc: subprocess.Popen, session_file: str,
                 payloads: list[str], poll_interval: float = 5.0) -> None:
        self._proc = proc
        self._session_file = session_file
        self.payloads: list[str] = list(payloads)
        self._pool: list[str] = list(payloads)
        self._reservations: dict[str, str] = {}     # probe_id -> payload
        self._payload_owner: dict[str, str] = {}    # payload -> probe_id
        self._interactions: dict[str, list[dict]] = {}  # unique_id -> [events]
        self._unknown_interactions: list[dict] = []
        self._lock = threading.Lock()
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    # ------------------------------------------------------------ lifecycle

    @classmethod
    def start(cls, client_path: str | None = None, n_payloads: int = 8,
              poll_interval: float = 5.0, servers: str = DEFAULT_SERVERS,
              session_dir: str | None = None,
              timeout: float = 30.0) -> "InteractshManager":
        exe = client_path or shutil.which("interactsh-client")
        if exe is None:
            # venv-activated shells often shadow lookup; try ~/go/bin explicitly
            home_candidate = os.path.join(os.path.expanduser("~"), "go", "bin",
                                          "interactsh-client")
            exe = home_candidate if os.path.isfile(home_candidate) else None
        if exe is None:
            raise InteractshUnavailable(
                "interactsh-client not found — install it or run 'bounty-agent doctor'"
            )
        session_dir = session_dir or ".interactsh"
        os.makedirs(session_dir, exist_ok=True)
        session_file = os.path.join(session_dir, f"session-{os.getpid()}.json")
        payload_file = session_file + ".payloads"
        for f in (session_file, payload_file):
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError:
                    pass
        cmd = [
            exe, "-n", str(max(1, n_payloads)), "-json", "-ps", "-psf", payload_file,
            "-sf", session_file, "-pi", str(max(1, int(poll_interval))),
            "-server", servers, "-duc",
        ]
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace",
            )
        except OSError as exc:
            raise InteractshUnavailable(f"cannot execute {exe}: {exc}") from exc

        # wait for the payload store to be written (registration complete)
        deadline = time.time() + timeout
        payloads: list[str] = []
        while time.time() < deadline:
            if os.path.exists(payload_file):
                try:
                    payloads = parse_payload_store(
                        open(payload_file, "r", encoding="utf-8", errors="replace").read()
                    )
                except OSError:
                    payloads = []
                if len(payloads) >= min(1, n_payloads):
                    break
            if proc.poll() is not None:
                raise InteractshError(
                    f"interactsh-client exited early (code {proc.returncode})"
                )
            time.sleep(0.25)
        if not payloads:
            proc.kill()
            raise InteractshError("interactsh-client did not register payloads in time")
        return cls(proc, session_file, payloads, poll_interval=poll_interval)

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self) -> "InteractshManager":
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ------------------------------------------------------------ internals

    def _read_loop(self) -> None:
        """Consume client stdout forever; JSON lines become interactions."""
        proc = self._proc
        assert proc.stdout is not None
        for line in proc.stdout:
            if self._stop.is_set():
                break
            ev = parse_interaction_line(line)
            if ev is None:
                continue
            uid = str(ev.get("unique-id", ""))
            if not _UNIQUE_ID_RE.match(uid):
                continue
            with self._lock:
                self._interactions.setdefault(uid, []).append(ev)

    # --------------------------------------------------------------- payload

    def reserve(self, probe_id: str) -> str | None:
        """Reserve one payload for a probe; None when the pool is exhausted."""
        with self._lock:
            if not self._pool:
                return None
            payload = self._pool.pop(0)
            self._reservations[probe_id] = payload
            self._payload_owner[payload] = probe_id
            return payload

    def payload_for(self, probe_id: str) -> str | None:
        with self._lock:
            return self._reservations.get(probe_id)

    # ---------------------------------------------------------- correlation

    def poll(self, probe_id: str, since_ts: float | None = None) -> list[dict]:
        """Interactions correlated to this probe (payload reserved + uid match)."""
        with self._lock:
            payload = self._reservations.get(probe_id)
            if payload is None:
                return []
            uid = unique_id_of(payload)
            events = list(self._interactions.get(uid, []))
        if since_ts is not None:
            events = [e for e in events if _ts_of(e) >= since_ts]
        return events

    def unknown_interactions(self) -> list[dict]:
        """Callbacks for payloads this run never reserved (logged, never used
        as evidence). Detected by matching no reserved unique-id."""
        with self._lock:
            reserved = {unique_id_of(p) for p in self._payload_owner}
            all_uids = set(self._interactions)
            return [e for uid in all_uids - reserved for e in self._interactions[uid]]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "payloads": len(self.payloads),
                "reserved": len(self._reservations),
                "interactions": sum(len(v) for v in self._interactions.values()),
                "probes_with_hits": sum(
                    1 for p in self._reservations.values()
                    if self._interactions.get(unique_id_of(p))
                ),
            }


def _ts_of(event: dict) -> float:
    ts = event.get("timestamp")
    if not ts:
        return 0.0
    try:
        from datetime import datetime, timezone
        if isinstance(ts, str):
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        return float(ts)
    except Exception:  # noqa: BLE001
        return 0.0


class FakeInteractshManager:
    """Offline stand-in: reserve() works, and test code pushes interactions
    directly with ``inject()``. Same correlation semantics as the real one."""

    def __init__(self, payloads: list[str] | None = None) -> None:
        if payloads is None:
            payloads = [f"fakeuid{i:03d}deadbeef.oast.fake" for i in range(4)]
        self.payloads = payloads
        self._pool = list(self.payloads)
        self._reservations: dict[str, str] = {}
        self._events: dict[str, list[dict]] = {}
        self.poll_interval = 0.0
        self.stats_data = {"payloads": len(self.payloads), "reserved": 0,
                           "interactions": 0, "probes_with_hits": 0}

    def reserve(self, probe_id: str) -> str | None:
        if not self._pool:
            return None
        p = self._pool.pop(0)
        self._reservations[probe_id] = p
        return p

    def payload_for(self, probe_id: str) -> str | None:
        return self._reservations.get(probe_id)

    def inject(self, payload: str, protocol: str = "http",
               **extra: Any) -> None:
        """Test helper: simulate the target hitting our payload."""
        uid = unique_id_of(payload)
        ev = {"protocol": protocol, "unique-id": uid,
              "timestamp": "2026-09-26T12:00:00Z", **extra}
        self._events.setdefault(uid, []).append(ev)

    def poll(self, probe_id: str, since_ts: float | None = None) -> list[dict]:
        payload = self._reservations.get(probe_id)
        if payload is None:
            return []
        return list(self._events.get(unique_id_of(payload), []))

    def unknown_interactions(self) -> list[dict]:
        reserved = {unique_id_of(p) for p in self._reservations.values()}
        out: list[dict] = []
        for uid, evs in self._events.items():
            if uid not in reserved:
                out.extend(evs)
        return out

    def stats(self) -> dict[str, Any]:
        hits = sum(1 for evs in self._events.values() if evs)
        return {"payloads": len(self.payloads), "reserved": len(self._reservations),
                "interactions": sum(len(v) for v in self._events.values()),
                "probes_with_hits": hits}

    def stop(self) -> None:
        pass

    def __enter__(self) -> "FakeInteractshManager":
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
