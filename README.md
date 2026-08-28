# P.A.N.D.A

A local-first **security platform** in Python. Two capabilities share one
hardened core:

- **Vault** — an encrypted, per-device record store behind a bcrypt-hashed
  password. The data is unreadable at rest and never written to disk in the
  clear.
- **TDR** (Threat Detection & Response) — a detection pipeline that turns
  Splunk telemetry (an SSH honeypot and Windows Security logs) into
  analyst-grade, confidence-graded incident reports. *Integrated in a
  separate track; the vault is its secure evidence store.*

This repository is the vault + platform core. It provides the auth,
encrypted storage, and command dispatch that TDR plugs into.

## Security design

- **Password hashing — bcrypt.** Passwords are stored as bcrypt hashes
  (per-password salt, deliberately slow), never plaintext or fast unsalted
  hashes. See `panda/auth.py`.
- **Encrypted vault at rest.** On disk the vault is only ciphertext: a
  random salt prepended to a Fernet (AES-CBC + HMAC, authenticated) token.
  The key is derived from the vault password with scrypt (memory-hard).
  Opening the vault decrypts it into an in-memory SQLite database; leaving
  it re-encrypts to disk — plaintext records never touch the disk. A wrong
  password or a tampered file is detected, not silently accepted. See
  `panda/crypto.py` and `panda/db.py`.
- **Parameterized data access.** All queries go through a small data-access
  layer that binds values as `?` parameters and validates table/column
  identifiers against a strict whitelist, so user input can't be
  interpolated into SQL. See `panda/db.py`.
- **No secrets, no network.** Fully offline and embedded (Python's stdlib
  `sqlite3`): no server, no credentials, no external API. One local file
  per device.

## Architecture

- **`panda/db.py`** — the shared, encrypted store: in-memory connection,
  `unlock`/`lock` lifecycle, and the parameterized data-access helpers.
  This is the seam TDR uses to persist alerts into the same vault.
- **`panda/router.py`** — a command registry (whole-word, best-score
  matching). New capabilities register commands without editing the main
  loop, so TDR bolts on without touching the vault code.
- **`panda/cases.py`** — the case store: how a TDR run persists its
  findings, and how the vault reads them back.
- **`panda/auth.py`, `panda/crypto.py`, `panda/vault.py`** — auth,
  encryption primitives, and the record system.

## Case store (TDR evidence)

A TDR run persists its findings into the vault, so they inherit the same
encryption-at-rest and login gate as every other record:

- **`cases`** — an incident (a correlated group of activity, or a single
  standalone detection): title, severity, graded confidence, status,
  shared source IP.
- **`detections`** — the individual signals for a case (rule, source —
  cowrie/windows —, severity, confidence, IP, username, evidence).
- **`reports`** — the incident write-up, one row per audience
  (`technical`, `plain`).

`detections` and `reports` are foreign-keyed to `cases`, so an orphan
detection is rejected. A run records with `cases.record_case` /
`record_detection` / `record_report` (the DB assigns the ids); the vault's
**CASES** command lists stored cases, filters by severity, and opens a
case's detections and reports — only after login, since the vault must be
unlocked (decrypted) first.

```
PANDA/
├── main.py              # CLI: banner, command loop, security commands
├── config.py            # local config (vault path); no keys/secrets
├── schema.sql           # SQLite schema for the built-in record tables
├── requirements.txt
└── panda/
    ├── auth.py          # bcrypt password hashing + verification
    ├── crypto.py        # scrypt key derivation + Fernet encrypt/decrypt
    ├── db.py            # in-memory DB, unlock/lock, data-access layer
    ├── router.py        # command registry / dispatch
    ├── system.py        # console I/O (banner, input, help)
    └── vault.py          # the record system
```

## Setup

```bash
pip install -r requirements.txt
python main.py
```

No configuration is required. On first run PANDA creates an encrypted
vault at `~/.panda/vault.db`; set a password, and your records are
encrypted under it.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

Coverage includes the encryption round-trip (wrong-password rejection,
tamper detection, no-plaintext-on-disk), the data-access layer (CRUD +
injection cases), auth, and command routing.
