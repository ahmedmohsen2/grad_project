-- =============================================================================
-- db.sql  —  IDS/IPS PostgreSQL Schema (Production Grade)
-- =============================================================================
-- Database : ids_system
-- Engine   : PostgreSQL 14+
-- Encoding : UTF-8
--
-- HOW TO APPLY (fresh install):
--   psql -U postgres -c "CREATE DATABASE ids_system;"
--   psql -U postgres -d ids_system -f db.sql
--
-- HOW TO APPLY (existing DB — safe to re-run):
--   psql -U postgres -d ids_system -f db.sql
--
-- All DDL uses IF NOT EXISTS / DO NOTHING — fully idempotent.
-- All column names match EXACTLY what db.py inserts/queries.
-- =============================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- COLUMN  →  db.py REFERENCE MAP  (do not rename without updating db.py)
-- ─────────────────────────────────────────────────────────────────────────────
-- hosts        : ip, status, first_seen, last_seen
-- flows        : src_ip, dst_ip, packets, bytes, pps, duration_us, captured_at
-- detections   : src_ip, result, attack_type, confidence, iso_flag, detected_at
-- actions      : ip, action_type, reason, acted_at
-- blocked_ips  : ip (UNIQUE), reason, blocked_at
-- alerts       : ip_address, alert_type, message, is_read, created_at
-- ─────────────────────────────────────────────────────────────────────────────


-- =============================================================================
-- 1. HOSTS
--    db.py query : INSERT INTO hosts (ip, status, first_seen, last_seen)
--    db.py query : ON CONFLICT (ip) DO UPDATE ... WHERE hosts.status = 'SEEN'
--    db.py query : UPDATE hosts SET status = $1, last_seen = NOW() WHERE ip = $2
-- =============================================================================

CREATE TABLE IF NOT EXISTS hosts (
    id         SERIAL       PRIMARY KEY,
    ip         TEXT         NOT NULL,                       -- IMPROVED: TEXT > VARCHAR(45)
    status     TEXT         NOT NULL DEFAULT 'SEEN',        -- IMPROVED: TEXT + NOT NULL + correct default ('SEEN' not 'NORMAL')
    first_seen TIMESTAMP    NOT NULL DEFAULT NOW(),         -- IMPROVED: NOT NULL
    last_seen  TIMESTAMP    NOT NULL DEFAULT NOW(),         -- IMPROVED: NOT NULL

    CONSTRAINT hosts_ip_unique UNIQUE (ip)                 -- REQUIRED: enables ON CONFLICT (ip)
);

-- Fast lookup by IP (primary access pattern)
CREATE INDEX IF NOT EXISTS idx_hosts_ip
    ON hosts (ip);                                         -- ADDED

-- Fast dashboard query: "show all non-clean hosts"
CREATE INDEX IF NOT EXISTS idx_hosts_status
    ON hosts (status)
    WHERE status != 'SEEN';                                -- ADDED: partial index, small and fast


-- =============================================================================
-- 2.  FLOWS
--     db.py query : INSERT INTO flows
--                   (src_ip, dst_ip, packets, bytes, pps, duration_us, captured_at)
-- =============================================================================

CREATE TABLE IF NOT EXISTS flows (
    id          SERIAL           PRIMARY KEY,
    src_ip      TEXT             NOT NULL,                  -- IMPROVED: TEXT + NOT NULL
    dst_ip      TEXT,                                       -- IMPROVED: TEXT (nullable — dst may be unknown)
    packets     INTEGER,
    bytes       BIGINT,                                     -- IMPROVED: BIGINT (was INT — overflows at 2 GB)
    pps         DOUBLE PRECISION,                           -- IMPROVED: DOUBLE PRECISION (was FLOAT)
    duration_us DOUBLE PRECISION,                          -- FIXED: renamed from 'duration' → matches db.py insert
    captured_at TIMESTAMP        NOT NULL DEFAULT NOW()    -- FIXED: renamed from 'created_at' → matches db.py insert
);

-- Most frequent query: "all flows from this source IP"
CREATE INDEX IF NOT EXISTS idx_flows_src_ip
    ON flows (src_ip, captured_at DESC);                   -- ADDED

-- Filter by destination IP (bidirectional traffic analysis)
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip
    ON flows (dst_ip, captured_at DESC);                   -- ADDED


-- =============================================================================
-- 3.  DETECTIONS
--     db.py query : INSERT INTO detections
--                   (src_ip, result, attack_type, confidence, iso_flag, detected_at)
-- =============================================================================

CREATE TABLE IF NOT EXISTS detections (
    id          SERIAL           PRIMARY KEY,
    src_ip      TEXT             NOT NULL,                  -- IMPROVED: TEXT + NOT NULL
    result      TEXT             NOT NULL,                  -- IMPROVED: TEXT + NOT NULL (ATTACK|SUSPICIOUS|NORMAL)
    attack_type TEXT,                                       -- IMPROVED: TEXT (nullable — NORMAL has no type)
    confidence  DOUBLE PRECISION,                           -- IMPROVED: DOUBLE PRECISION (was FLOAT)
    iso_flag    SMALLINT         NOT NULL DEFAULT 0,        -- IMPROVED: SMALLINT + NOT NULL + DEFAULT
    detected_at TIMESTAMP        NOT NULL DEFAULT NOW()    -- FIXED: renamed from 'created_at' → matches db.py insert
);

-- Primary lookup: "all detections for this IP ordered by time"
CREATE INDEX IF NOT EXISTS idx_detections_src_ip
    ON detections (src_ip, detected_at DESC);              -- IMPROVED: composite (was single-column)

-- Dashboard aggregate: "how many ATTACKs in the last hour?"
CREATE INDEX IF NOT EXISTS idx_detections_result_time
    ON detections (result, detected_at DESC);              -- ADDED


-- =============================================================================
-- 4.  ACTIONS
--     db.py query : INSERT INTO actions (ip, action_type, reason, acted_at)
--     db.py query : (no WHERE clause on ip — full history kept)
-- =============================================================================

CREATE TABLE IF NOT EXISTS actions (
    id          SERIAL    PRIMARY KEY,
    ip          TEXT      NOT NULL,                        -- FIXED: renamed from 'ip_address' → matches db.py insert
    action_type TEXT      NOT NULL,                        -- IMPROVED: TEXT + NOT NULL (BLOCK|MONITOR|ISOLATE|UNBLOCK)
    reason      TEXT,                                      -- nullable — some actions have no explicit reason
    source      TEXT      NOT NULL DEFAULT 'system',
    confidence  DOUBLE PRECISION NOT NULL DEFAULT 0,
    actor_username TEXT  NOT NULL DEFAULT 'system',
    actor_role TEXT      NOT NULL DEFAULT 'service',
    enforcement_method TEXT NOT NULL DEFAULT 'database',
    verification_status TEXT NOT NULL DEFAULT 'unknown',
    real_block_applied BOOLEAN NOT NULL DEFAULT FALSE,
    database_only BOOLEAN NOT NULL DEFAULT TRUE,
    inline_block BOOLEAN NOT NULL DEFAULT FALSE,
    gateway_block BOOLEAN NOT NULL DEFAULT FALSE,
    rule_exists BOOLEAN NOT NULL DEFAULT FALSE,
    command_status TEXT NOT NULL DEFAULT 'unknown',
    enforcement_message TEXT,
    acted_at    TIMESTAMP NOT NULL DEFAULT NOW()           -- FIXED: renamed from 'created_at' → matches db.py insert
);

-- Fast history lookup per IP with time ordering
CREATE INDEX IF NOT EXISTS idx_actions_ip
    ON actions (ip, acted_at DESC);                        -- IMPROVED: composite + correct column name


-- =============================================================================
-- 5.  BLOCKED_IPS
--     db.py query : INSERT INTO blocked_ips (ip, reason, blocked_at)
--                   ON CONFLICT (ip) DO NOTHING
--     db.py query : DELETE FROM blocked_ips WHERE ip = $1
-- =============================================================================

CREATE TABLE IF NOT EXISTS blocked_ips (
    id         SERIAL    PRIMARY KEY,
    ip         TEXT      NOT NULL,                         -- FIXED: renamed from 'ip_address' → matches db.py
    reason     TEXT,
    blocked_at TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT blocked_ips_ip_unique UNIQUE (ip)          -- REQUIRED: enables ON CONFLICT (ip) DO NOTHING
);

-- Fast existence check: "is this IP currently blocked?"
CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip
    ON blocked_ips (ip);                                   -- ADDED


-- =============================================================================
-- 6.  ALERTS
--     db.py query : INSERT INTO alerts (ip_address, alert_type, message)
--     db.py query : SELECT ... FROM alerts ORDER BY created_at DESC LIMIT $n
--     db.py query : UPDATE alerts SET is_read = TRUE WHERE id = $1
-- =============================================================================

CREATE TABLE IF NOT EXISTS alerts (
    id          SERIAL    PRIMARY KEY,
    ip_address  TEXT      NOT NULL,                        -- IMPROVED: TEXT + NOT NULL
    alert_type  TEXT      NOT NULL,                        -- IMPROVED: TEXT + NOT NULL (ATTACK|BLOCK|SUSPICIOUS|MALWARE)
    message     TEXT      NOT NULL,                        -- IMPROVED: NOT NULL
    is_read     BOOLEAN   NOT NULL DEFAULT FALSE,          -- IMPROVED: NOT NULL (was nullable)
    created_at  TIMESTAMP NOT NULL DEFAULT NOW()           -- IMPROVED: NOT NULL
);

-- CRITICAL: newest-first pagination (GET /alerts ORDER BY created_at DESC)
CREATE INDEX IF NOT EXISTS idx_alerts_created_at
    ON alerts (created_at DESC);                           -- ADDED

-- Filter by source IP (host-specific alert history)
CREATE INDEX IF NOT EXISTS idx_alerts_ip
    ON alerts (ip_address);                                -- ADDED

-- Filter by alert type (e.g., show only MALWARE alerts)
CREATE INDEX IF NOT EXISTS idx_alerts_type
    ON alerts (alert_type);                                -- ADDED

-- Partial index: unread alerts only (notification badge count — tiny, very fast)
CREATE INDEX IF NOT EXISTS idx_alerts_unread
    ON alerts (created_at DESC)
    WHERE is_read = FALSE;                                 -- ADDED: partial index


-- =============================================================================
-- 7.  FINALIZE — update planner statistics for all tables
-- =============================================================================

ANALYZE hosts;
ANALYZE flows;
ANALYZE detections;
ANALYZE actions;
ANALYZE blocked_ips;
ANALYZE alerts;

-- =============================================================================
-- Done.
-- =============================================================================
SELECT 'db.sql applied successfully — IDS/IPS schema ready.' AS result;
