-- =============================================================================
-- migration_v2.sql — Production Indexes + Schema Fixes
-- IDS/IPS PostgreSQL Database
--
-- Run once:
--   psql -U postgres -d ids_system -f migration_v2.sql
--
-- All statements use IF NOT EXISTS / DO NOTHING — safe to re-run.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. ALERTS TABLE — ensure it exists with correct schema
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id          SERIAL       PRIMARY KEY,
    ip_address  VARCHAR(45)  NOT NULL,
    alert_type  VARCHAR(20)  NOT NULL,
    message     TEXT         NOT NULL,
    is_read     BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Critical: newest-first pagination (used by GET /alerts ORDER BY created_at DESC)
CREATE INDEX IF NOT EXISTS idx_alerts_created_at
    ON alerts (created_at DESC);

-- Filter by IP address (dashboard: "show all alerts for this host")
CREATE INDEX IF NOT EXISTS idx_alerts_ip
    ON alerts (ip_address);

-- Filter by type (e.g., show only MALWARE alerts)
CREATE INDEX IF NOT EXISTS idx_alerts_type
    ON alerts (alert_type);

-- Filtered index: unread alerts only — tiny index, fast for notification queries
CREATE INDEX IF NOT EXISTS idx_alerts_unread
    ON alerts (created_at DESC)
    WHERE is_read = FALSE;


-- -----------------------------------------------------------------------------
-- 2. BLOCKED_IPS TABLE — ensure UNIQUE constraint on ip
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blocked_ips (
    id         SERIAL       PRIMARY KEY,
    ip         VARCHAR(45)  NOT NULL,
    reason     TEXT,
    blocked_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT blocked_ips_ip_unique UNIQUE (ip)    -- enables ON CONFLICT (ip) DO NOTHING
);

-- Fast existence check: "is this IP currently blocked?"
CREATE INDEX IF NOT EXISTS idx_blocked_ip
    ON blocked_ips (ip);


-- -----------------------------------------------------------------------------
-- 3. DETECTIONS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detections (
    id          SERIAL       PRIMARY KEY,
    src_ip      VARCHAR(45)  NOT NULL,
    result      VARCHAR(20)  NOT NULL,       -- ATTACK | SUSPICIOUS | NORMAL
    attack_type VARCHAR(100),
    confidence  DOUBLE PRECISION,
    iso_flag    SMALLINT     DEFAULT 0,
    detected_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Most common query: "all detections for this IP in time range"
CREATE INDEX IF NOT EXISTS idx_detections_src_ip
    ON detections (src_ip, detected_at DESC);

-- Dashboard aggregate: "how many ATTACKs in last hour?"
CREATE INDEX IF NOT EXISTS idx_detections_result_time
    ON detections (result, detected_at DESC);


-- -----------------------------------------------------------------------------
-- 4. ACTIONS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS actions (
    id          SERIAL       PRIMARY KEY,
    ip          VARCHAR(45)  NOT NULL,
    action_type VARCHAR(20)  NOT NULL,       -- BLOCK | MONITOR | ISOLATE | UNBLOCK
    reason      TEXT,
    source      TEXT NOT NULL DEFAULT 'system',
    confidence  DOUBLE PRECISION NOT NULL DEFAULT 0,
    actor_username TEXT NOT NULL DEFAULT 'system',
    actor_role TEXT NOT NULL DEFAULT 'service',
    enforcement_method TEXT NOT NULL DEFAULT 'database',
    verification_status TEXT NOT NULL DEFAULT 'unknown',
    real_block_applied BOOLEAN NOT NULL DEFAULT FALSE,
    database_only BOOLEAN NOT NULL DEFAULT TRUE,
    inline_block BOOLEAN NOT NULL DEFAULT FALSE,
    gateway_block BOOLEAN NOT NULL DEFAULT FALSE,
    rule_exists BOOLEAN NOT NULL DEFAULT FALSE,
    command_status TEXT NOT NULL DEFAULT 'unknown',
    enforcement_message TEXT,
    acted_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_actions_ip
    ON actions (ip, acted_at DESC);


-- -----------------------------------------------------------------------------
-- 5. FLOWS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS flows (
    id          SERIAL       PRIMARY KEY,
    src_ip      VARCHAR(45)  NOT NULL,
    dst_ip      VARCHAR(45),
    packets     INTEGER,
    bytes       BIGINT,
    pps         DOUBLE PRECISION,
    duration_us DOUBLE PRECISION,
    captured_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_flows_src_ip
    ON flows (src_ip, captured_at DESC);


-- -----------------------------------------------------------------------------
-- 6. HOSTS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hosts (
    id         SERIAL       PRIMARY KEY,
    ip         VARCHAR(45)  NOT NULL,
    status     VARCHAR(20)  NOT NULL DEFAULT 'SEEN',
    first_seen TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT hosts_ip_unique UNIQUE (ip)
);

CREATE INDEX IF NOT EXISTS idx_hosts_status
    ON hosts (status)
    WHERE status != 'SEEN';     -- partial index: only non-clean hosts (small, fast)


-- -----------------------------------------------------------------------------
-- 7. Analyze all tables to update planner statistics
-- -----------------------------------------------------------------------------
ANALYZE alerts;
ANALYZE detections;
ANALYZE blocked_ips;
ANALYZE actions;
ANALYZE flows;
ANALYZE hosts;

-- Done.
SELECT 'migration_v2.sql applied successfully.' AS result;
