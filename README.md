# P.A.N.D.A

A local-first **security platform** in Python. One product, two capabilities
on one hardened core:

- **Vault** — an encrypted, per-device store behind a bcrypt-hashed password.
  Data is unreadable at rest and never written to disk in the clear.
- **TDR** (Threat Detection & Response) — a detection engine that turns
  honeypot + Windows Security telemetry into confidence-graded incident cases,
  persisted into the vault as encrypted evidence.

The whole thing runs **offline and deterministic by default** — no network, no
API key. Two opt-in extras add an LLM report polish (`[ai]`) and a live Splunk
pull (`[live]`); with neither installed, PANDA is fully functional on the
bundled offline snapshot.

## Quickstart

```bash
pip install -e .
panda          # or: python main.py
```

No configuration required. On first run PANDA creates an encrypted vault at
`~/.panda/vault.db`; set a password and your records are encrypted under it.

At the prompt:

- `TDR` — scan the telemetry and persist findings as encrypted cases.
- `CASES` — browse stored cases, filter by severity, open detections and reports.
- `VAULT` — open the record system. `SET` / `CHANGE` — manage the password.
- `HELP`, `QUIT`.

`TDR` runs on the offline snapshot by default; `TDR LIVE` pulls from Splunk when
the `[live]` extra is installed and configured (else it says so and falls back
to the snapshot).

## How TDR works

A scan (`panda/bridge.py`) runs a set of detectors over the telemetry and
persists each finding as a case with detections and reports:

- **Windows detectors** (stdlib) — brute-force / password-spray on failed
  logons (4625), account creation (4720), and a multi-stage **kill chain**
  that stitches failed → successful (4624) → persistence into one confirmed
  intrusion, with a technical and a plain-language incident report.
- **Cross-source correlation** (pandas + scikit-learn) — joins the Cowrie SSH
  honeypot against Windows failed logons on source IP (and a username
  fallback), scores severity with an interpretable decision tree, and renders
  an analyst alert card.

Every fact traces to the data; severity rules are deterministic policy, and the
reports state their honest limits plainly.

### One incident, one case — linked by source IP

Findings are **de-duplicated within a subsystem** (a standalone Windows
detection the kill chain already contains is skipped) but **never across
sensors**: the cross-source correlation is a different claim from a different
sensor than the Windows-only chain, so it stays its own case. When they share a
source IP, opening one case surfaces the others under **Related cases (same
source IP)** — the intended way to connect independent lines of evidence on one
actor, without double-counting.

## Case store (encrypted evidence)

TDR findings live in the same encrypted vault, so they inherit its
encryption-at-rest and login gate:

- **`cases`** — an incident: title, severity, graded confidence, status, shared
  source IP, summary.
- **`detections`** — the individual signals (rule, source, severity,
  confidence, IP, username, evidence).
- **`reports`** — the write-up, one row per audience (`technical`, `plain`).

`detections` and `reports` are foreign-keyed to `cases` (an orphan is
rejected). A scan writes with `cases.record_case` / `record_detection` /
`record_report` (the DB assigns ids); browsing is read-only and only inside an
unlocked vault, so evidence is readable only after login by construction.

> Note: a scan **appends** — re-running `TDR` writes the findings again.
> Idempotency is a planned refinement; with the fixed snapshot this is a demo
> artifact, not a risk.

## Core vs. optional extras

The core is offline and lightweight. The extras are strictly opt-in and never
weaken the core — each degrades to the deterministic path when absent.

| Install | Adds | Needs |
| --- | --- | --- |
| `pip install -e .` (core) | vault + full deterministic TDR engine, offline | — |
| `pip install -e '.[ai]'` | LLM-polished report **wording** | `crewai` + `GEMINI_API_KEY` |
| `pip install -e '.[live]'` | live Splunk pull instead of the snapshot | `splunk-sdk` + `SPLUNK_*`, Splunk reachable |

**The deterministic report is always the source of truth.** LLM polish only
rewords it, behind two integrity guards: a whole-card guard (rejects LaTeX, a
dropped or fabricated IP, a missing severity word) and a section-level fact
guard on the incident report (reverts any prose section that drops a hard
fact). A polish that fails *or* drifts ships the deterministic text — so an API
hiccup can't crash a run and a bad rewrite can't ship. The plain-language report
is never sent to an LLM. With no extra installed, the run summary reads
*"deterministic (AI extra not installed)"* — the expected default, not a silent
failure.

```bash
# optional, any combination:
pip install -e '.[ai]'      # + set GEMINI_API_KEY
pip install -e '.[live]'    # + set SPLUNK_USER / SPLUNK_PASSWORD / ...
```

## Security design

- **Password hashing — bcrypt** (`panda/auth.py`): salted, deliberately slow;
  never plaintext or a fast unsalted hash.
- **Encrypted vault at rest** (`panda/crypto.py`, `panda/db.py`): on disk the
  vault is only ciphertext — a random salt prepended to a Fernet (AES-CBC +
  HMAC, authenticated) token, keyed from the password via scrypt (memory-hard).
  Unlocking decrypts into an in-memory SQLite DB; locking re-encrypts —
  plaintext never touches the disk. A wrong password or tampered file is
  detected, not silently accepted.
- **Parameterized data access** (`panda/db.py`): values bind as `?` parameters;
  table/column identifiers validate against a strict whitelist — no user input
  is interpolated into SQL.
- **Offline core, no secrets.** Embedded `sqlite3`, one local file per device.
  The only network paths are the opt-in extras.

## Layout

```
PANDA/
├── main.py                # CLI: banner, command loop, security + tdr/cases commands
├── config.py              # local config (vault path); no keys/secrets
├── schema.sql             # cases / detections / reports (FK-enforced)
├── pyproject.toml         # package + deps: core, and [ai] / [live] / [dev] extras
├── DECISIONS.md           # decision record
├── panda/                 # the platform
│   ├── auth.py  crypto.py  db.py      # bcrypt auth, encryption, in-memory DAO
│   ├── router.py  system.py  vault.py # dispatch, console I/O, record system
│   ├── cases.py                       # case-store write/read API
│   ├── browse.py                      # interactive case browse (shared)
│   └── bridge.py                      # scan → detect + correlate → persist
├── panda_tdr/             # the vendored TDR engine (stdlib core + optional layers)
│   ├── detections.py  windows_records.py  incident_report.py   # Windows detectors
│   ├── correlation.py  cowrie_records.py                       # cross-source join
│   ├── severity_model.py  alerting.py  reporter.py             # scoring + alert card
│   ├── snapshot.py                                             # offline source
│   ├── polish.py  polish_guard.py  incident_polish.py  llm.py  crews/  # [ai]
│   └── live.py  splunk_client.py  windows_source.py  cowrie_source.py  # [live]
├── test_data/             # offline Splunk snapshot fixture
└── tests/                 # pytest suite (see below)
```

## Tests

```bash
pip install -e '.[dev]'
pytest
```

The suite runs fully offline (no crewai, no Splunk): the encryption round-trip
(wrong-password rejection, tamper detection, no-plaintext-on-disk), the
data-access layer (CRUD + injection), auth and routing, the TDR detectors,
correlation, both LLM-polish integrity guards (with injected fakes), the
live-source availability logic, and the bridge's persist / de-dup / related-case
behavior end to end.

## Design record

See [DECISIONS.md](DECISIONS.md) for the reasoning behind the security choices,
the case-store mapping, the de-dup principle, the offline-core / opt-in-extras
split, and the honest model caveat on the severity tree.
