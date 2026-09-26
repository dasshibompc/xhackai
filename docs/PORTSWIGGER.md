# Benchmarking the Agent Against PortSwigger Labs

The PortSwigger Web Security Academy (free) is our benchmark suite: real,
deliberately vulnerable web apps, each a small, self-contained, **authorized**
target — you are attacking an instance created for you.

## Authorization note

Each lab instance (`https://lab-<id>.web-security-academy.net`) is provisioned
to your browser session and lives roughly 30–60 minutes. Attacking *your own
instance* is the intended use of the platform. Never point the agent at
`portswigger.net` itself or at other people's tooling. Add the lab domain to
the rulebook **only** for the exact instance host.

## Workflow (per lab)

1. **Launch a lab** in your browser from the Academy catalog.
2. **Copy the instance URL** from the address bar.
3. **Create a rulebook** for that single host:

   ```yaml
   # programs/ps-xss-html-context.yaml
   name: ps-lab-reflected-xss
   notes: >
     PortSwigger lab instance (ephemeral, personal). Reflected XSS,
     HTML context, no encoding. Benchmark run.
   rate_limit:
     requests_per_second: 5        # be gentle: instances are shared hardware
   automation_policy: allowed
   scope:
     - host: lab-xxxxxxxxxx.web-security-academy.net   # exact instance host
   ```

4. **Run recon** (discovers the real endpoints/parameters — this replaces
   guessing):

   ```bash
   bounty-agent recon programs/ps-xss-html-context.yaml --with-js
   ```

5. **Hunt** with the class matching the lab:

   ```bash
   bounty-agent hunt-vulns programs/ps-xss-html-context.yaml \
       --classes xss --max-steps 10
   ```

6. **Validate and report:**

   ```bash
   bounty-agent validate programs/ps-xss-html-context.yaml
   bounty-agent report
   ```

7. **Score it manually:** open the lab page in your browser. If the banner
   shows *"Congratulations, you have solved the lab"* **and** the agent produced
   a corresponding `validated` finding, the run counts as a success.

## Labs that map to current probe classes

| Lab (Web Security Academy) | Class | Notes |
|---|---|---|
| Reflected XSS into HTML context with nothing encoded | xss | easiest first benchmark |
| Reflected XSS into an HTML attribute value | xss | probe detects raw reflection; context work is LLM's job |
| SQL injection vulnerability in WHERE clause allowing retrieval of hidden data | sqli | GET parameter |
| SQL injection vulnerability allowing login bypass | sqli | POST form → `probe_sqli` uses `method=POST` |
| SQL injection UNION attack, determining number of columns | sqli | detection-only; do NOT let it dump data |
| DOM-based open redirect / redirect labs | redirect | Location-header check |

Run 5–10 different instances of each lab to get a real solve-rate number.
Track: solved/attempted, LLM steps used, tokens used, and whether findings were
`validated` vs `needs-review` vs `rejected`.

## Known limitations (be honest when scoring)

- **Session cookies:** labs behind a login (e.g. "logged-in user" scenarios)
  need the `Cookie: session=...` header from your browser. The generic
  `http_request` tool accepts headers, but the deterministic probes don't take
  cookie config yet — that is the M4 auth harness. Until then, score only
  unauthenticated labs.
- **Ephemeral instances:** the URL dies; store results (reports, findings DB)
  per run, not per lab.
- **Multi-step labs** (CSRF/token chains, OAuth) are out of scope for the
  current probes — don't count them as failures.
- **No destructive payloads by design:** UNION-based *data extraction* will not
  be completed by the agent; it detects and proves injectability. Score
  detection, not full lab completion, for those labs.

## Scoring the benchmark (for the go/no-go gate)

The PLAN.md gate for going live on real programs:

- ≥ 70% solve rate across ≥ 10 runs of the M3-class labs above, and
- validator precision ≥ 80% (`validated` findings that a human agrees with).

Record runs in a spreadsheet or `benchmarks/results.md` until this becomes a
harness command (planned M4).
