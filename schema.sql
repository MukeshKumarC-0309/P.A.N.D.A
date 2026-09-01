-- PANDA schema (SQLite)
--
-- Run by init_db() on first launch. Ships with NO data: every table is
-- created empty. PANDA is security-only, so the vault holds a single
-- built-in domain: the TDR evidence store (cases / detections / reports).
-- Users can still create their own tables at runtime (CREATOR MODE).
--
-- Type choices follow SQLite's affinities (TEXT / INTEGER / REAL).
-- PRIMARY KEYs are declared on the column the code identifies rows by.
--
-- (Earlier PandaVault domain tables — Emergency / Medicine / Student_Marks —
-- were removed when PANDA became security-only. Dropping them here only
-- affects fresh vaults; an existing vault blob keeps those now-unused empty
-- tables harmlessly.)

-- ---------------------------------------------------------------------------
-- TDR evidence store.
--
-- A TDR run persists its findings here: a `case` (an incident), its
-- `detections` (the individual signals), and its `reports` (the incident
-- write-up, one row per audience). These live in the same encrypted vault,
-- so they are encrypted at rest and readable only after the vault is
-- unlocked (login). Foreign keys tie detections/reports to their case.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cases (
    case_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,          -- ISO 8601 UTC
    title      TEXT NOT NULL,
    severity   TEXT,                    -- low / medium / high / critical
    confidence TEXT,                    -- graded confidence (TDR states only what the data supports)
    status     TEXT NOT NULL DEFAULT 'open',
    source_ip  TEXT,                    -- shared attacker key, when correlated
    summary    TEXT,
    disposition TEXT                    -- analyst verdict: confirmed / false_positive / benign (NULL = unreviewed)
);

CREATE TABLE IF NOT EXISTS detections (
    detection_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id      INTEGER NOT NULL REFERENCES cases(case_id),
    detected_at  TEXT NOT NULL,         -- ISO 8601 UTC
    rule         TEXT NOT NULL,         -- brute-force / password-spray / account-creation / kill-chain / correlation
    source       TEXT,                  -- cowrie / windows
    severity     TEXT,
    confidence   TEXT,
    source_ip    TEXT,
    username     TEXT,
    evidence     TEXT                    -- supporting detail / raw summary
);

CREATE TABLE IF NOT EXISTS reports (
    report_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id    INTEGER NOT NULL REFERENCES cases(case_id),
    audience   TEXT NOT NULL,           -- 'technical' or 'plain'
    created_at TEXT NOT NULL,           -- ISO 8601 UTC
    body       TEXT NOT NULL
);

