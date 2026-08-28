# Decisions — PANDA

Decision record for this repo. PANDA is a local-first **security
platform**: an encrypted vault behind hardened auth that also serves as
the evidence store for the **PANDA TDR** (Threat Detection & Response)
engine. This file records the choices behind that; see *Lineage* at the
end for where the deeper restructuring history lives.

## What PANDA is

- **Vault** — an encrypted, per-device record store behind a
  bcrypt-hashed password. Data is unreadable at rest and never written to
  disk in the clear.
- **TDR** — a detection engine (honeypot + Windows Security telemetry →
  correlation + standalone detections → graded-confidence incident cases).
  The vault is its secure evidence store.

TDR is **integrated into this repo**: the deterministic engine is vendored
under `panda_tdr/`, and `panda/bridge.py` runs it and persists findings
through the vault. The core is offline; two opt-in extras (`[ai]`, `[live]`)
add an LLM report polish and a live Splunk pull. The vendored engine's own
lineage lives in the separate TDR repo.

## Security decisions

1. **Password hashing — bcrypt** (`panda/auth.py`). Stored as bcrypt
   hashes (per-password salt, deliberately slow), never plaintext or a
   fast unsalted hash. Verify compares hashes, never raw text. The hash
   file lives beside the vault (`config.DB_PATH.parent`), resolved from
   config, not the working directory.
2. **Encrypted vault at rest — `cryptography`, not SQLCipher**
   (`panda/crypto.py`, `panda/db.py`). `cryptography` ships abi3 wheels
   (installs on any modern Python, keeps the zero-install story) and lets
   the design use real primitives: a **scrypt** (memory-hard) key derived
   from the vault password, **Fernet** (AES-CBC + HMAC) *authenticated*
   encryption so a wrong password or tampered file is detected, and a
   random salt stored with the ciphertext. The live DB is held **in
   memory**; on disk there is only the encrypted blob. `unlock` decrypts
   into memory (`deserialize`), `lock` re-encrypts (`serialize`) — so
   plaintext never touches disk. The key derives from the login password,
   so a password change unlocks-old then locks-new. Tradeoff (accepted):
   the vault re-encrypts on **exit** (in a `finally`, so a normal exit or
   an error still saves) — only a hard kill mid-session loses that
   session's changes. Could extend to envelope encryption (wrap a random
   data key) so a password change re-wraps instead of re-encrypting.
3. **Parameterized data access** (`panda/db.py`). All queries go through
   a small DAO that binds values as `?` parameters and validates
   table/column identifiers against a strict whitelist (identifiers can't
   be bound, so they're validated instead). User input is never
   interpolated into SQL.
4. **Offline core, no secrets.** The core is fully offline, embedded
   SQLite: no server, no credentials, no API keys. `config.py` reads only
   the (optional) vault path — no import-time key check, so any component
   (including TDR) imports config without extra config. The **only** network
   paths are the two strictly opt-in extras (`[ai]`, `[live]`), whose
   dependencies are imported lazily so a core install never loads them.

## Case store (TDR evidence)

A TDR run persists its findings into the vault, inheriting the same
encryption-at-rest and login gate as every other record.

- **Schema** (`schema.sql`): `cases` (an incident), `detections` (the
  individual signals), `reports` (the write-up, one row per audience).
  `detections` and `reports` are foreign-keyed to `cases`, and
  `PRAGMA foreign_keys = ON` enforces it — an orphan detection is
  rejected. Ids are `INTEGER PRIMARY KEY AUTOINCREMENT` (the DB assigns
  them; TDR doesn't invent ids), timestamps are ISO-8601 UTC TEXT.
- **Write API** (`panda/cases.py` + `db.insert_row`): `record_case` /
  `record_detection` / `record_report`; `insert_row(table, {col: val})`
  sets named columns and returns the new id (so AUTOINCREMENT/DEFAULT
  columns fill themselves).
- **Read/browse** (`CASES` command / in-vault menu): list cases, filter
  by severity, open a case's detections and reports — only inside an
  unlocked (logged-in) vault session, so evidence is readable only after
  login by construction. One implementation (`panda/browse.py`) is shared
  by the top-level `cases` command and the in-vault menu entry.
- **Related cases by source IP** (Step 5). Opening a case surfaces other
  cases sharing its `source_ip` (`cases.related_by_source_ip`) — the one
  actor seen through different lenses (a Windows kill chain, a cross-source
  correlation, a standalone brute-force all keyed on the same IP). This is
  the payoff of the dedup principle: those stay **separate** cases (distinct
  evidence, no double-counting), and the shared IP is how the analyst
  connects them. A null `source_ip` (e.g. an account-creation case) never
  links spuriously.

## TDR bridge (Step 1 — offline, deterministic)

The detection engine is vendored from the separate TDR repo into
`panda_tdr/` (stdlib only: `detections.py`, `windows_records.py`,
`incident_report.py`) with the offline `test_data/splunk_snapshot.json`
fixture and a Windows-only `snapshot.py` loader. No pandas / scikit-learn
/ crewai / Splunk — the correlation, LLM, and live-pull pieces are later,
opt-in cuts, so the core stays offline and lightweight.

- **The bridge** (`panda/bridge.py`, `scan_and_persist`): load the
  snapshot, run the Windows detectors + the multi-stage kill-chain
  stitcher, and persist each finding as a case (+ detections, + reports).
  Wired in as the `tdr` command (unlock → scan → summary → re-lock).
- **Mapping.** A kill chain → one case, a detection per stage
  (`brute-force` → `successful-logon` → `account-creation`), and two
  reports (advanced → `technical`, normal → `plain`). A standalone
  brute/spray or account creation → a case + one detection, no report.
- **De-duplication — one incident, one case.** Chains are persisted
  first; a standalone finding a chain already subsumes is skipped (a
  brute/spray whose `(src_ip, account)` the chain covers, or an account
  creation attached as its persistence stage). Only *subsumed* findings
  are skipped: a brute-force that never succeeded, or a 4720 with no
  preceding breach, stays its own standalone case.
- **Honesty in the rows.** A stage-3 (persistence) detection is attributed
  by host + timing, not source IP (Event 4720 carries none); its evidence
  says so. A standalone account creation is `confidence: medium` (a
  legitimate admin trips the same rule) with a null `source_ip`.
- **Known limitation — append, not idempotent.** `scan_and_persist`
  appends; re-running `tdr` writes the findings again. With the fixed
  snapshot this is a demo artifact, not a real risk. Idempotency (skip or
  supersede an already-recorded finding) is a deliberate later cut.

## Correlation cut (Step 2 — offline, cross-source)

The cross-source correlation engine is vendored (`correlation.py` on
pandas; `severity_model.py` / `alerting.py` / `reporter.py` on
scikit-learn). It joins the Cowrie SSH-honeypot events against the Windows
failed-logon telemetry, and `bridge.scan_and_persist` persists each
correlated identity as a case + a `rule="correlation"` detection + one
technical report (the deterministic analyst card).

- **pandas / scikit-learn are core, and offline.** They are heavier than
  the stdlib engine but do no network I/O, so the no-network identity holds
  (only crewai/Gemini `[ai]` and splunk `[live]` are opt-in network deps).
- **No cowrie_detector dependency.** `correlation.py` duck-types the Cowrie
  side (src_ip / username / timestamp / eventid / message), so the offline
  path needs no file parser. `cowrie_records.py` is vendored with its
  `_time`/username mapping intact but its `CowrieRecord` import swapped for
  a local record type — so offline records are identical to the live path,
  with no external package. The real `cowrie_detector` (the file/live
  parser) waits for the `[live]` cut, where it is actually load-bearing.
- **De-dup principle — within a subsystem, never across sensors.** The
  Windows detectors dedup against the chain (same 4625/4720 events →
  duplicate cases). Correlation is a **different claim from a different
  sensor** (honeypot interaction + cross-source timing) that the
  Windows-only chain does not capture, so it is **never** deduped against
  the chain — collapsing it would delete the cross-sensor signal, which is
  TDR's core thesis. The shared `source_ip` (e.g. `10.0.2.3` on both the
  chain case and the correlation case) is the **intended link** an analyst
  follows when browsing, not a duplicate.
- **Honesty caveat (model).** The severity tree recovers a small
  policy-derived label set; near-perfect fit is by construction — a
  readable rule path and methodology demo, not generalization evidence.
  The alert card cites only the features the fitted tree actually split on.

## `[ai]` extra — LLM-polished reports (Step 3, opt-in)

crewai + Gemini polish report **wording only**; the deterministic card
stays the source of truth. This is a strict opt-in that never weakens the
offline core.

- **Lazy, both-mode fallback** (`panda_tdr/polish.py`). `ai_available()`
  is true only when crewai is importable AND `GEMINI_API_KEY` is set —
  covering both "extra not installed" and "installed but unconfigured".
  crewai is imported **only inside** the returned polish function, so a
  core install never touches it. `make_polisher(kind)` builds either the
  whole-card polisher (`card`, for correlation reports) or the section
  polisher (`section`, for incident reports) from the one scaffold.
- **Two stdlib guards, one discipline.** `polish_guard.guarded_polish`
  guards the whole correlation card (rejects LaTeX, a dropped/fabricated
  IP, a missing severity word). `incident_polish` guards the advanced
  incident report **section by section** (Step 3b): it polishes only the
  prose sections (executive_summary, impact) and reverts any that lost a
  hard fact (src_ip / account / failure_count / created accounts, plus the
  'impact' honest-limit keywords); tables, timeline, IOCs, and MITRE IDs
  are never sent to the LLM. Both degrade in both directions — a polish
  that raises (API down / no key) OR drifts reverts to deterministic — so
  a hiccup can't crash a run and a bad rewrite can't ship. The
  plain-language report is never LLM-touched (fully offline by design).
- **Deterministic reads as the default, not a failure.** The `tdr` summary
  says "Reports: N — deterministic (AI extra not installed)" vs
  "LLM-polished (X polished, Y fell back)", so offline output is the
  expected state, not a silent degrade.

## `[live]` extra — live Splunk pull (Step 4, opt-in)

`tdr live` pulls the pipeline's four inputs (cowrie / failed / success /
account-creation) from Splunk instead of the snapshot, returning the SAME
dict shape as `snapshot.load_snapshot`, so the rest of the bridge is
unchanged — only the source swaps.

- **Lazy, both-mode fallback** (`panda_tdr/live.py`). splunk-sdk and the
  SDK-dependent source modules (`splunk_client.py`, `windows_source.py`,
  `cowrie_source.py`) are imported ONLY inside `load_live` — a core install
  never touches splunklib. `live_available()` is true only when splunklib
  imports AND `SPLUNK_USER`/`SPLUNK_PASSWORD` are set (both failure modes).
  If `tdr live` is requested but the extra is unusable, the run degrades to
  the snapshot with the reason in `summary["source"]` — never a crash.
- **Build/test needs no lab; a real pull does.** The availability logic is
  env-only and the bridge's live path is tested with an injected loader, so
  Step 4 is fully covered offline. Splunk-reachable (`SPLUNK_*`, the lab up)
  is required only to execute an actual live pull — a verify-when-up step,
  not a blocker. The SPL/pull logic in `splunk_client.py` is unit-testable
  only where splunk-sdk is installed (guard those with `importorskip`).
- **One connection, reused.** `load_live` opens a single Splunk `service`
  (with the client's capped-exponential backoff) and shares it across all
  four pulls.

## Packaging — `pyproject.toml`

Dependencies live in a single `pyproject.toml` (setuptools backend), the
one source of truth — the earlier flat `requirements*.txt` files were
removed. Core deps are `[project].dependencies`; the opt-in extras are real
`[project.optional-dependencies]`, so the offline/opt-in split is expressed
in the packaging itself:

```
pip install -e .            # core (offline)
pip install -e '.[ai]'      # + crewai (LLM polish)
pip install -e '.[live]'    # + splunk-sdk (live pull)
pip install -e '.[dev]'     # + pytest
```

- **Editable (`-e`) is the supported install.** PANDA runs from the source
  tree (`schema.sql` is read by path relative to `panda/db.py`), so an
  editable install keeps that working while resolving the extras; a console
  script (`panda = main:main`) gives a clean entry point. A non-editable
  install would need `schema.sql` packaged as data — deferred until there's
  a reason to ship a wheel.
- Flat layout is declared explicitly (`packages`, `py-modules`) rather than
  auto-discovered, because the root carries `main.py` / `config.py` as
  modules alongside the `panda` / `panda_tdr` packages.

## Architecture / the TDR extension seam

- **`panda/db.py`** — the one shared, encrypted store (connection,
  unlock/lock, DAO). TDR persists through it; no second connection.
- **`panda/router.py`** — a command registry (whole-word, best-score
  matching). New capabilities `router.register(...)` their commands
  **without editing the main loop**, so TDR bolts on without touching the
  vault code path (Open/Closed).
- Net: vault and TDR are one product sharing auth + storage + dispatch,
  with no coupling between their feature code.

## Scope decision: security-only

PANDA is derived from an earlier assistant project (PandaVault). Its
utility features (jokes, weather, news, calculator, timers, reminders,
web shortcuts) were **intentionally left out** so the product reads as
security-first — the right framing for a detection/DFIR portfolio, and
less surface to finish, test, and document. The utility code still lives
in the original PandaVault repo (nothing deleted there). The command
registry makes this reversible: those commands simply aren't registered
here.

The leftover PandaVault **domain tables** (`Emergency` / `Medicine` /
`Student_Marks`) and their view/edit menu code were **removed** for the
same reason — the vault's one built-in domain is now the TDR case store.
Dropping them from `schema.sql` only affects fresh vaults; an existing
vault blob keeps those now-unused empty tables harmlessly (no migration
needed, and there is no real user data). The DAO and encryption tests,
which had used `Emergency` merely as a sample table, now exercise the
`cases` table instead — so that coverage is preserved, not lost.

## Lineage

Derived from PandaVault. The record system's history — the MySQL→SQLite
migration and the original security/correctness hardening — happened in
that repo; this file records PANDA's own decisions rather than repeating
that saga.

## How to work in this repo

- Read the actual code and verify assumptions before proposing.
- Work in the smallest reviewable pieces; use the test suite as the net
  (`pytest`).
- Explain in plain language before and after each change.
