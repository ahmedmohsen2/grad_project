"""
db.py  —  Async PostgreSQL Layer (Production Grade)
=====================================================
Why asyncpg over SQLAlchemy async:
  - asyncpg is 3-5x faster for raw SQL (no ORM overhead)
  - Direct protocol driver with zero abstraction tax
  - Perfect fit for a SOC backend that needs sub-millisecond query latency
  - SQLAlchemy async adds ORM complexity we do not need here

Architecture:
  ┌─────────────────────────────────────────────────────────────┐
  │  FastAPI routes  → await db_function()        (async path)  │
  │  Flask routes    → sync_*() wrappers          (sync path)   │
  │  agent threads   → sync_*() wrappers          (sync path)   │
  │  action_manager  → sync_*() wrappers          (sync path)   │
  └─────────────────────────────────────────────────────────────┘

Pool sizing:
  min=5   keeps connections warm; eliminates cold-start latency
  max=20  handles burst traffic without exhausting PG max_connections

Tables:
  hosts       — one row per IP (upserted)
  flows       — completed network flow summaries
  detections  — ML + rule-based verdicts
  actions     — IPS actions taken (BLOCK / MONITOR / ISOLATE)
  blocked_ips — currently active blocks (UNIQUE on ip)
  alerts      — real-time IPS alerts served via /alerts API

Logging levels:
  INFO  — important lifecycle events (pool created, host blocked, alert inserted)
  DEBUG — high-frequency ops (flows, routine upserts) to avoid log spam
  ERROR — structured DB failures (never raises, always returns False / [])
"""

from __future__ import annotations

import asyncio
import logging
import concurrent.futures          # FIXED: needed for safe thread-pool bridge
import threading                   # FIXED: dual-lock cooldown
import time
from contextlib import asynccontextmanager
from typing import Any, Optional

import asyncpg
from asyncpg import Pool

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

DB_DSN        = "postgresql://postgres:123@localhost:5432/ids_system"
POOL_MIN_SIZE = 5
POOL_MAX_SIZE = 20

# Alert cooldown — same (ip, alert_type) will not produce a row for N seconds
ALERT_COOLDOWN_SEC = 60

log = logging.getLogger("DB")


# ──────────────────────────────────────────────────────────────────────────────
# POOL MANAGEMENT
# ──────────────────────────────────────────────────────────────────────────────

_pool: Optional[Pool] = None


async def init_pool() -> Pool:
    """
    Creates the asyncpg connection pool.
    Must be called once at application startup (e.g., FastAPI lifespan or
    Flask before_first_request).

    Returns the pool so callers can await it if needed.
    """
    global _pool
    if _pool is not None:
        return _pool
    try:
        _pool = await asyncpg.create_pool(
            dsn          = DB_DSN,
            min_size     = POOL_MIN_SIZE,
            max_size     = POOL_MAX_SIZE,
            command_timeout  = 10,   # seconds — query timeout guard
            max_inactive_connection_lifetime = 300,  # release idle conns after 5m
        )
        log.info(
            f"[DB] Pool created — min={POOL_MIN_SIZE} max={POOL_MAX_SIZE} "
            f"dsn=postgresql://.../{DB_DSN.split('/')[-1]}"
        )
    except Exception as exc:
        log.error(f"[DB ERROR] Pool creation failed: {exc}")
        _pool = None
    return _pool


async def close_pool() -> None:
    """Gracefully close the pool (call on app shutdown)."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
        log.info("[DB] Pool closed.")


def get_pool() -> Optional[Pool]:
    """
    Returns the pool instance, or None if not yet initialised / unavailable.
    Callers must handle None gracefully.

    # IMPROVED: emits a WARNING (not silent) if pool was never initialised,
    # making misconfigured deployments immediately visible in logs.
    """
    if _pool is None:
        log.warning(
            "[DB] Pool is None — call init_pool() (async) or sync_init_pool() "
            "at application startup before any DB operation."
        )
    return _pool


# ──────────────────────────────────────────────────────────────────────────────
# INTERNAL ASYNC HELPERS
# ──────────────────────────────────────────────────────────────────────────────

async def _execute(query: str, *args: Any) -> bool:
    """
    Execute a parameterised DML statement (INSERT / UPDATE / DELETE).

    Args:
        query: SQL with $1, $2, ... placeholders (asyncpg style)
        *args: positional parameters

    Returns:
        True  — statement executed successfully
        False — DB unavailable or query error (never raises)
    """
    pool = get_pool()
    if pool is None:
        log.error("[DB ERROR] _execute called but pool is not initialised.")
        return False
    try:
        async with pool.acquire() as conn:
            await conn.execute(query, *args)
        return True
    except asyncpg.UniqueViolationError:
        # ON CONFLICT DO NOTHING equivalent — not a real error
        log.debug(f"[DB] Unique conflict silenced — SQL: {query[:60]}")
        return True
    except Exception as exc:
        log.error(f"[DB ERROR] _execute failed: {exc} | SQL: {query[:80]}")
        return False


async def _fetchall(query: str, *args: Any) -> list[dict]:
    """
    Execute a SELECT and return all matching rows as list[dict].

    Returns [] on any error — never raises.
    """
    pool = get_pool()
    if pool is None:
        return []
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, *args)
        # asyncpg Record supports dict-like access; convert explicitly
        return [dict(row) for row in rows]
    except Exception as exc:
        log.error(f"[DB ERROR] _fetchall failed: {exc} | SQL: {query[:80]}")
        return []


async def _fetchone(query: str, *args: Any) -> Optional[dict]:
    """
    Execute a SELECT and return the first row as dict, or None.
    Never raises.
    """
    pool = get_pool()
    if pool is None:
        return None
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, *args)
        return dict(row) if row else None
    except Exception as exc:
        log.error(f"[DB ERROR] _fetchone failed: {exc} | SQL: {query[:80]}")
        return None


async def _fetchval(query: str, *args: Any) -> Any:
    """
    Execute a SELECT and return the first column of the first row.
    Useful for COUNT(*), MAX(...), etc.
    Returns None on error — never raises.
    """
    pool = get_pool()
    if pool is None:
        return None
    try:
        async with pool.acquire() as conn:
            return await conn.fetchval(query, *args)
    except Exception as exc:
        log.error(f"[DB ERROR] _fetchval failed: {exc} | SQL: {query[:80]}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
# SYNC → ASYNC BRIDGE  (persistent background loop)
# ──────────────────────────────────────────────────────────────────────────────
#
# WHY a persistent loop?
#   asyncpg pools bind to the event loop they are created on.  If we create
#   a fresh loop per call and close it afterwards, the pool's internal
#   connections reference a dead loop → "Event loop is closed" on every
#   subsequent query.
#
#   The fix: ONE daemon thread runs ONE event loop that never closes.
#   The pool is created on that loop (via sync_init_pool) and all sync_*
#   wrappers submit coroutines to it.  The loop — and therefore the pool's
#   connections — stay alive for the entire process lifetime.
#
# SAFETY:
#   • The loop thread is a daemon — it dies automatically on process exit.
#   • run_coroutine_threadsafe is the stdlib-blessed way to submit work
#     from any thread to a running loop (no deadlocks, no cross-loop issues).
#   • 5-second timeout ceiling prevents sync callers from hanging forever.
# ──────────────────────────────────────────────────────────────────────────────

_bg_loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()

def _run_bg_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Target for the background thread — runs the loop forever."""
    asyncio.set_event_loop(loop)
    loop.run_forever()

_bg_thread = threading.Thread(
    target=_run_bg_loop,
    args=(_bg_loop,),
    daemon=True,
    name="db-async-loop",
)
_bg_thread.start()


def _run_async(coro, timeout: float = 5.0) -> Any:
    """
    Submit a coroutine to the persistent background loop and wait for result.
    Safe to call from ANY thread (Flask, agent, action executor, etc.).
    """
    try:
        future = asyncio.run_coroutine_threadsafe(coro, _bg_loop)
        result = future.result(timeout=timeout)
        return result
    except concurrent.futures.TimeoutError:
        log.error(f"[DB ERROR] _run_async timed out after {timeout}s")
        return None
    except Exception as exc:
        log.error(f"[DB ERROR] _run_async failed: {exc}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
# ALERT COOLDOWN  (in-memory dedup, hybrid-safe)
# ──────────────────────────────────────────────────────────────────────────────
# FIXED: dual-lock strategy:
#   _cooldown_thread_lock  — threading.Lock  for sync callers (agent, action_manager)
#   _cooldown_async_lock   — asyncio.Lock    for async callers (FastAPI routes)
#
# Both locks protect the same _alert_cooldown dict.
# Sync callers acquire the thread lock (never the async lock — they can't await).
# Async callers acquire the async lock (they do await, so they must not block).
# The two lock types operate on separate paths, so there is zero cross-blocking.
# ──────────────────────────────────────────────────────────────────────────────

_alert_cooldown: dict[tuple, float] = {}
_cooldown_thread_lock = threading.Lock()         # FIXED: for sync callers
_cooldown_async_lock: Optional[asyncio.Lock] = None  # lazy — requires event loop


def _get_async_cooldown_lock() -> asyncio.Lock:
    """Lazy-initialise asyncio.Lock (requires a running event loop)."""
    global _cooldown_async_lock
    if _cooldown_async_lock is None:
        _cooldown_async_lock = asyncio.Lock()
    return _cooldown_async_lock


def _check_cooldown_sync(ip: str, alert_type: str) -> bool:
    """
    # FIXED: Thread-safe cooldown check for sync callers.
    Returns True if suppressed, False if allowed (updates timestamp).
    Uses threading.Lock — never blocks an event loop.
    """
    key = (ip, alert_type.upper())
    now = time.monotonic()
    with _cooldown_thread_lock:
        last = _alert_cooldown.get(key, 0.0)
        if now - last < ALERT_COOLDOWN_SEC:
            return True
        _alert_cooldown[key] = now
        return False


async def _check_cooldown(ip: str, alert_type: str) -> bool:
    """
    Async-safe cooldown check for async callers (FastAPI routes).
    Returns True if suppressed, False if allowed (updates timestamp).
    Uses asyncio.Lock — correct for coroutine context.
    """
    key = (ip, alert_type.upper())
    now = time.monotonic()
    lock = _get_async_cooldown_lock()
    async with lock:
        last = _alert_cooldown.get(key, 0.0)
        if now - last < ALERT_COOLDOWN_SEC:
            return True    # still cooling down → suppress
        _alert_cooldown[key] = now
        return False       # cooldown expired → allow insert


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC ASYNC API
# ──────────────────────────────────────────────────────────────────────────────

async def insert_detection(
    src_ip:      str,
    result:      str,
    attack_type: str,
    confidence:  float,
    iso_flag:    int  = 0,
) -> bool:
    """
    Store one ML / rule-based detection result.
    Table: detections(src_ip, result, attack_type, confidence, iso_flag, detected_at)
    """
    ok = await _execute(
        """
        INSERT INTO detections
            (src_ip, result, attack_type, confidence, iso_flag, detected_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        """,
        src_ip, result, attack_type, float(confidence), int(iso_flag),
    )
    if ok:
        log.debug(
            f"[DB] detection — ip={src_ip} result={result} "
            f"type={attack_type} conf={confidence:.3f}"
        )
    return ok


async def insert_action(
    ip:          str,
    action_type: str,
    reason:      str = "",
) -> bool:
    """
    Log an IPS action against an IP.
    Table: actions(ip, action_type, reason, acted_at)
    """
    ok = await _execute(
        "INSERT INTO actions (ip, action_type, reason, acted_at) VALUES ($1, $2, $3, NOW())",
        ip, action_type.upper(), reason[:500],
    )
    if ok:
        log.info(f"[DB] action — ip={ip} action={action_type}")
    return ok


async def insert_blocked_ip(ip: str, reason: str = "") -> bool:
    """
    Insert into blocked_ips. ON CONFLICT DO NOTHING prevents duplicates.
    Table: blocked_ips(ip UNIQUE, reason, blocked_at)
    """
    ok = await _execute(
        """
        INSERT INTO blocked_ips (ip, reason, blocked_at)
        VALUES ($1, $2, NOW())
        ON CONFLICT (ip) DO NOTHING
        """,
        ip, reason[:500],
    )
    if ok:
        log.info(f"[DB] blocked — ip={ip}")
    return ok


async def remove_blocked_ip(ip: str) -> bool:
    """Remove an IP from blocked_ips on unblock."""
    ok = await _execute("DELETE FROM blocked_ips WHERE ip = $1", ip)
    if ok:
        log.info(f"[DB] unblocked — ip={ip}")
    return ok


async def insert_flow(
    src_ip:   str,
    dst_ip:   str,
    packets:  int,
    bytes_:   int,
    pps:      float,
    duration: float,
) -> bool:
    """
    Store a completed flow summary.
    Table: flows(src_ip, dst_ip, packets, bytes, pps, duration_us, captured_at)
    """
    ok = await _execute(
        """
        INSERT INTO flows
            (src_ip, dst_ip, packets, bytes, pps, duration_us, captured_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        """,
        src_ip, dst_ip, int(packets), int(bytes_), float(pps), float(duration),
    )
    if ok:
        log.debug(f"[DB] flow — {src_ip}→{dst_ip} pkts={packets} pps={pps:.1f}")
    return ok


async def upsert_host(ip: str, status: str = "SEEN") -> bool:
    """
    Insert a new host or update last_seen timestamp.
    Status is NOT degraded — COMPROMISED stays COMPROMISED even if
    SEEN is passed again (WHERE clause guard).

    Table: hosts(ip UNIQUE, status, first_seen, last_seen)
    """
    ok = await _execute(
        """
        INSERT INTO hosts (ip, status, first_seen, last_seen)
        VALUES ($1, $2, NOW(), NOW())
        ON CONFLICT (ip) DO UPDATE
            SET last_seen = NOW(),
                status    = EXCLUDED.status
        WHERE hosts.status = 'SEEN'
        """,
        ip, status,
    )
    if ok:
        log.debug(f"[DB] host upserted — ip={ip} status={status}")
    return ok


async def update_host_status(ip: str, status: str) -> bool:
    """
    Escalate a host's status (MONITORED → COMPROMISED → ISOLATED → CRITICAL).
    """
    ok = await _execute(
        "UPDATE hosts SET status = $1, last_seen = NOW() WHERE ip = $2",
        status, ip,
    )
    if ok:
        log.info(f"[DB] host status — ip={ip} → {status}")
    return ok


async def insert_alert(
    ip:         str,
    alert_type: str,
    message:    str,
    metadata:   Optional[dict] = None,
) -> bool:
    """
    Insert one alert with 60-second in-memory cooldown.

    Cooldown: the same (ip, alert_type) pair will not generate a new DB row
    within ALERT_COOLDOWN_SEC seconds, preventing alert storms.

    Table: alerts(ip_address, alert_type, message, is_read, created_at)
    Returns True on insert or suppressed duplicate, False on DB error.
    """
    suppressed = await _check_cooldown(ip, alert_type)
    if suppressed:
        log.debug(f"[DB] alert suppressed (cooldown) — ip={ip} type={alert_type}")
        return True

    import json as _json

    ok = await _execute(
        """
        INSERT INTO alerts (ip_address, alert_type, message, metadata)
        VALUES ($1, $2, $3, $4::jsonb)
        """,
        ip, alert_type.upper(), message[:1000], _json.dumps(metadata or {}, default=str),
    )
    if ok:
        log.info(f"[DB] Alert inserted — ip={ip} type={alert_type}")
    else:
        log.error(f"[DB ERROR] Alert insert failed — ip={ip} type={alert_type}")
    return ok


async def get_alerts(
    limit:       int  = 50,
    offset:      int  = 0,
    ip:          Optional[str]  = None,
    unread_only: bool = False,
) -> list[dict]:
    """
    Return alerts ordered by created_at DESC with optional filters.

    Args:
        limit:       max rows (capped at 200 for safety)
        offset:      pagination offset (OFFSET/LIMIT pattern)
        ip:          filter by ip_address (optional)
        unread_only: return only unread alerts

    Returns list[dict] with keys: id, ip, type, message, is_read, time
    """
    params = [limit, offset]

    rows = await _fetchall(
        """
        SELECT * FROM alerts
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        """,
        *params,
    )

    # Convert timestamps → ISO 8601 strings (JSON-serialisable)
    for row in rows:
        if row.get("created_at") and hasattr(row["created_at"], "isoformat"):
            row["created_at"] = row["created_at"].isoformat()
        if row.get("time") and hasattr(row["time"], "isoformat"):
            row["time"] = row["time"].isoformat()

    return rows


async def mark_alert_read(alert_id: int) -> bool:
    """
    Mark a single alert as read.
    Returns True on success, False if not found or DB error.
    """
    # Check the row exists first (cheap indexed lookup by PK)
    exists = await _fetchval("SELECT 1 FROM alerts WHERE id = $1", int(alert_id))
    if not exists:
        log.warning(f"[DB] mark_alert_read — id={alert_id} not found")
        return False

    ok = await _execute(
        "UPDATE alerts SET is_read = TRUE WHERE id = $1",
        int(alert_id),
    )
    if ok:
        log.debug(f"[DB] alert read — id={alert_id}")
    return ok


async def get_alerts_count(unread_only: bool = False) -> int:
    """Return total alerts count (for pagination metadata)."""
    where = "WHERE is_read = FALSE" if unread_only else ""
    val = await _fetchval(f"SELECT COUNT(*) FROM alerts {where}")
    return int(val) if val is not None else 0


async def get_detections(
    limit:  int = 20,
    offset: int = 0,
    src_ip: Optional[str] = None,
) -> list[dict]:
    """
    Return recent detections ordered by detected_at DESC.
    Keys: id, src_ip, result, attack_type, confidence, iso_flag, detected_at
    """
    limit = min(int(limit), 200)
    params: list[Any] = []
    idx = 1
    where = ""
    if src_ip:
        where = f"WHERE src_ip = ${idx}"
        params.append(src_ip)
        idx += 1
    params += [limit, offset]
    rows = await _fetchall(
        f"""
        SELECT id, src_ip, result, attack_type,
               confidence, iso_flag, detected_at
        FROM detections
        {where}
        ORDER BY detected_at DESC
        LIMIT ${idx} OFFSET ${idx + 1}
        """,
        *params,
    )
    for row in rows:
        if row.get("detected_at") and hasattr(row["detected_at"], "isoformat"):
            row["detected_at"] = row["detected_at"].isoformat()
    return rows


async def get_flows(
    limit:  int = 20,
    offset: int = 0,
    src_ip: Optional[str] = None,
) -> list[dict]:
    """
    Return recent flows ordered by captured_at DESC.
    Keys: id, src_ip, dst_ip, packets, bytes, pps, duration_us, captured_at
    """
    limit = min(int(limit), 200)
    params: list[Any] = []
    idx = 1
    where = ""
    if src_ip:
        where = f"WHERE src_ip = ${idx}"
        params.append(src_ip)
        idx += 1
    params += [limit, offset]
    rows = await _fetchall(
        f"""
        SELECT id, src_ip, dst_ip, packets, bytes,
               pps, duration_us, captured_at
        FROM flows
        {where}
        ORDER BY captured_at DESC
        LIMIT ${idx} OFFSET ${idx + 1}
        """,
        *params,
    )
    for row in rows:
        if row.get("captured_at") and hasattr(row["captured_at"], "isoformat"):
            row["captured_at"] = row["captured_at"].isoformat()
    return rows


async def get_actions(limit: int = 20, offset: int = 0) -> list[dict]:
    """
    Return recent IPS actions ordered by acted_at DESC.
    Keys: id, ip, action_type, reason, acted_at
    """
    limit = min(int(limit), 200)
    rows = await _fetchall(
        """
        SELECT id, ip, action_type, reason, acted_at
        FROM actions
        ORDER BY acted_at DESC
        LIMIT $1 OFFSET $2
        """,
        int(limit), int(offset),
    )
    for row in rows:
        if row.get("acted_at") and hasattr(row["acted_at"], "isoformat"):
            row["acted_at"] = row["acted_at"].isoformat()
    return rows


async def get_blocked_ips() -> list[dict]:
    """
    Return all currently blocked IPs.
    Keys: ip, reason, blocked_at
    """
    rows = await _fetchall(
        "SELECT ip, reason, blocked_at FROM blocked_ips ORDER BY blocked_at DESC",
    )
    for row in rows:
        if row.get("blocked_at") and hasattr(row["blocked_at"], "isoformat"):
            row["blocked_at"] = row["blocked_at"].isoformat()
    return rows


async def db_ping() -> bool:
    """
    Check DB reachability.
    Used by /health endpoint and monitoring.
    Returns True if DB responds, False otherwise.
    """
    pool = get_pool()
    if pool is None:
        return False
    try:
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return True
    except Exception:
        return False


async def upsert_action_control(
    target: str,
    *,
    action: str,
    reason: str = "",
    source: str = "system",
) -> bool:
    """
    Persist the latest simulated containment state for a target.
    """
    action_upper = action.upper()
    is_blocked = action_upper == "BLOCK"
    is_isolated = action_upper == "ISOLATE"
    is_whitelisted = action_upper == "WHITELIST"
    ok = await _execute(
        """
        INSERT INTO action_controls
            (target, is_blocked, is_isolated, is_whitelisted, is_quarantined,
             last_action, reason, source, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        ON CONFLICT (target) DO UPDATE
            SET is_blocked = EXCLUDED.is_blocked,
                is_isolated = EXCLUDED.is_isolated,
                is_whitelisted = EXCLUDED.is_whitelisted,
                is_quarantined = EXCLUDED.is_quarantined,
                last_action = EXCLUDED.last_action,
                reason = EXCLUDED.reason,
                source = EXCLUDED.source,
                updated_at = NOW()
        """,
        target,
        is_blocked,
        is_isolated,
        is_whitelisted,
        is_isolated,
        action_upper,
        reason[:500],
        source[:100],
    )
    if ok:
        log.info(f"[DB] action control - target={target} action={action_upper}")
    return ok


async def get_action_control(target: str) -> Optional[dict]:
    row = await _fetchone(
        """
        SELECT target, is_blocked, is_isolated, is_whitelisted, is_quarantined,
               last_action, reason, source, updated_at
        FROM action_controls
        WHERE target = $1
        """,
        target,
    )
    if row and row.get("updated_at") and hasattr(row["updated_at"], "isoformat"):
        row["updated_at"] = row["updated_at"].isoformat()
    return row


async def ensure_runtime_schema() -> bool:
    """
    Apply additive schema updates needed by newer API features.
    Safe to call repeatedly at startup.
    """
    statements = [
        "ALTER TABLE actions ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'system'",
        "ALTER TABLE actions ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION NOT NULL DEFAULT 0",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb",
        "ALTER TABLE pentest_scans ADD COLUMN IF NOT EXISTS progress INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE pentest_scans ADD COLUMN IF NOT EXISTS current_stage TEXT NOT NULL DEFAULT 'queued'",
        "ALTER TABLE pentest_scans ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
        """
        CREATE TABLE IF NOT EXISTS action_controls (
            target TEXT PRIMARY KEY,
            is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
            is_isolated BOOLEAN NOT NULL DEFAULT FALSE,
            is_whitelisted BOOLEAN NOT NULL DEFAULT FALSE,
            is_quarantined BOOLEAN NOT NULL DEFAULT FALSE,
            last_action TEXT NOT NULL DEFAULT 'NONE',
            reason TEXT,
            source TEXT NOT NULL DEFAULT 'system',
            confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
            trigger TEXT NOT NULL DEFAULT 'manual',
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "ALTER TABLE action_controls ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION NOT NULL DEFAULT 0",
        "ALTER TABLE action_controls ADD COLUMN IF NOT EXISTS trigger TEXT NOT NULL DEFAULT 'manual'",
        "CREATE INDEX IF NOT EXISTS idx_action_controls_updated_at ON action_controls (updated_at DESC)",
        """
        CREATE TABLE IF NOT EXISTS security_findings (
            finding_id TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL UNIQUE,
            scan_id TEXT,
            target TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'detected',
            mitigation_state TEXT NOT NULL DEFAULT 'unresolved',
            risk_score INTEGER NOT NULL DEFAULT 0,
            affected_component TEXT,
            description TEXT,
            evidence TEXT,
            remediation TEXT,
            source TEXT NOT NULL DEFAULT 'pentest',
            action_type TEXT,
            action_reason TEXT,
            action_source TEXT,
            revalidation_scan_id TEXT,
            last_action_at TIMESTAMPTZ,
            last_retested_at TIMESTAMPTZ,
            first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            resolved_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            timeline JSONB NOT NULL DEFAULT '[]'::jsonb,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_security_findings_target ON security_findings (target)",
        "CREATE INDEX IF NOT EXISTS idx_security_findings_status ON security_findings (status, mitigation_state)",
        "CREATE INDEX IF NOT EXISTS idx_security_findings_updated_at ON security_findings (updated_at DESC)",
        """
        CREATE TABLE IF NOT EXISTS activity_logs (
            id          BIGSERIAL PRIMARY KEY,
            timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            type        TEXT NOT NULL DEFAULT 'system',
            action      TEXT NOT NULL DEFAULT 'unknown',
            target      TEXT NOT NULL DEFAULT '',
            reason      TEXT NOT NULL DEFAULT '',
            source      TEXT NOT NULL DEFAULT 'system',
            status      TEXT NOT NULL DEFAULT 'success',
            metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_activity_logs_type ON activity_logs (type)",
        "CREATE INDEX IF NOT EXISTS idx_activity_logs_created_at ON activity_logs (created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_activity_logs_target ON activity_logs (target)",
        # ── Auth: users table ────────────────────────────────────────────────
        """
        CREATE TABLE IF NOT EXISTS users (
            id            SERIAL PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'analyst',
            is_active     BOOLEAN NOT NULL DEFAULT TRUE,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_login_at TIMESTAMPTZ
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)",
        "CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)",
    ]
    for statement in statements:
        ok = await _execute(statement)
        if not ok:
            return False
    return True


async def insert_action(
    ip: str,
    action_type: str,
    reason: str = "",
    source: str = "system",
) -> bool:
    """
    Override that records action source alongside the action log.
    """
    ok = await _execute(
        """
        INSERT INTO actions (ip, action_type, reason, source, acted_at)
        VALUES ($1, $2, $3, $4, NOW())
        """,
        ip,
        action_type.upper(),
        reason[:500],
        source[:100],
    )
    if ok:
        log.info(f"[DB] action - ip={ip} action={action_type} source={source}")
    return ok


def _normalize_finding_row(row: Optional[dict]) -> Optional[dict]:
    if not row:
        return row
    for ts_key in (
        "first_seen_at",
        "last_seen_at",
        "last_action_at",
        "last_retested_at",
        "resolved_at",
        "updated_at",
    ):
        if row.get(ts_key) and hasattr(row[ts_key], "isoformat"):
            row[ts_key] = row[ts_key].isoformat()
    return row


async def get_security_finding(finding_id: str) -> Optional[dict]:
    return _normalize_finding_row(
        await _fetchone("SELECT * FROM security_findings WHERE finding_id = $1", finding_id)
    )


async def get_security_finding_by_fingerprint(fingerprint: str) -> Optional[dict]:
    return _normalize_finding_row(
        await _fetchone("SELECT * FROM security_findings WHERE fingerprint = $1", fingerprint)
    )


async def get_security_findings(
    limit: int = 50,
    *,
    target: Optional[str] = None,
    include_resolved: bool = True,
) -> list[dict]:
    limit = min(int(limit), 200)
    clauses: list[str] = []
    vals: list[Any] = []
    if target:
        vals.append(target)
        clauses.append(f"target = ${len(vals)}")
    if not include_resolved:
        clauses.append("mitigation_state <> 'mitigated'")

    sql = "SELECT * FROM security_findings"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    vals.append(int(limit))
    sql += f" ORDER BY updated_at DESC LIMIT ${len(vals)}"

    rows = await _fetchall(sql, *vals)
    return [_normalize_finding_row(row) for row in rows]


async def upsert_security_finding(record: dict) -> bool:
    import json as _json

    if not record.get("finding_id") or not record.get("fingerprint"):
        return False

    ok = await _execute(
        """
        INSERT INTO security_findings (
            finding_id, fingerprint, scan_id, target, title, severity, confidence,
            status, mitigation_state, risk_score, affected_component, description,
            evidence, remediation, source, action_type, action_reason, action_source,
            revalidation_scan_id, last_action_at, last_retested_at, first_seen_at,
            last_seen_at, resolved_at, updated_at, timeline, metadata
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11, $12,
            $13, $14, $15, $16, $17, $18,
            $19, $20::timestamptz, $21::timestamptz, COALESCE($22::timestamptz, NOW()),
            COALESCE($23::timestamptz, NOW()), $24::timestamptz, COALESCE($25::timestamptz, NOW()), $26::jsonb, $27::jsonb
        )
        ON CONFLICT (finding_id) DO UPDATE
            SET fingerprint = EXCLUDED.fingerprint,
                scan_id = EXCLUDED.scan_id,
                target = EXCLUDED.target,
                title = EXCLUDED.title,
                severity = EXCLUDED.severity,
                confidence = EXCLUDED.confidence,
                status = EXCLUDED.status,
                mitigation_state = EXCLUDED.mitigation_state,
                risk_score = EXCLUDED.risk_score,
                affected_component = EXCLUDED.affected_component,
                description = EXCLUDED.description,
                evidence = EXCLUDED.evidence,
                remediation = EXCLUDED.remediation,
                source = EXCLUDED.source,
                action_type = EXCLUDED.action_type,
                action_reason = EXCLUDED.action_reason,
                action_source = EXCLUDED.action_source,
                revalidation_scan_id = EXCLUDED.revalidation_scan_id,
                last_action_at = EXCLUDED.last_action_at,
                last_retested_at = EXCLUDED.last_retested_at,
                first_seen_at = COALESCE(security_findings.first_seen_at, EXCLUDED.first_seen_at),
                last_seen_at = EXCLUDED.last_seen_at,
                resolved_at = EXCLUDED.resolved_at,
                updated_at = EXCLUDED.updated_at,
                timeline = EXCLUDED.timeline,
                metadata = EXCLUDED.metadata
        """,
        record.get("finding_id"),
        record.get("fingerprint"),
        record.get("scan_id"),
        record.get("target"),
        record.get("title"),
        record.get("severity"),
        float(record.get("confidence") or 0.0),
        record.get("status") or "detected",
        record.get("mitigation_state") or "unresolved",
        int(record.get("risk_score") or 0),
        record.get("affected_component"),
        record.get("description"),
        record.get("evidence"),
        record.get("remediation"),
        record.get("source") or "pentest",
        record.get("action_type"),
        record.get("action_reason"),
        record.get("action_source"),
        record.get("revalidation_scan_id"),
        record.get("last_action_at"),
        record.get("last_retested_at"),
        record.get("first_seen_at"),
        record.get("last_seen_at"),
        record.get("resolved_at"),
        record.get("updated_at"),
        _json.dumps(record.get("timeline") or [], default=str),
        _json.dumps(record.get("metadata") or {}, default=str),
    )
    if ok:
        log.info(
            f"[DB] security finding - id={record.get('finding_id')} target={record.get('target')} status={record.get('status')}"
        )
    return ok


async def get_actions(limit: int = 20, offset: int = 0) -> list[dict]:
    """
    Override that exposes action source in API responses.
    """
    limit = min(int(limit), 200)
    rows = await _fetchall(
        """
        SELECT id, ip, action_type, reason, source, acted_at
        FROM actions
        ORDER BY acted_at DESC
        LIMIT $1 OFFSET $2
        """,
        int(limit), int(offset),
    )
    for row in rows:
        if row.get("acted_at") and hasattr(row["acted_at"], "isoformat"):
            row["acted_at"] = row["acted_at"].isoformat()
    return rows


async def update_pentest_scan(
    scan_id: str,
    *,
    status: Optional[str] = None,
    progress: Optional[int] = None,
    current_stage: Optional[str] = None,
    results: Optional[dict] = None,
    completed_at: Optional[str] = None,
) -> bool:
    """
    Override that stores scan progress metadata and refreshes updated_at.
    """
    import json as _json

    parts, vals = [], []
    if status:
        parts.append("status = $" + str(len(vals) + 1))
        vals.append(status)
    if progress is not None:
        parts.append("progress = $" + str(len(vals) + 1))
        vals.append(max(0, min(100, int(progress))))
    if current_stage is not None:
        parts.append("current_stage = $" + str(len(vals) + 1))
        vals.append(current_stage)
    if results is not None:
        parts.append("results = $" + str(len(vals) + 1) + "::jsonb")
        vals.append(_json.dumps(results, default=str))
    if completed_at:
        parts.append("completed_at = $" + str(len(vals) + 1) + "::timestamptz")
        vals.append(completed_at)
    parts.append("updated_at = NOW()")

    vals.append(scan_id)
    sql = f"UPDATE pentest_scans SET {', '.join(parts)} WHERE scan_id = ${len(vals)}"
    ok = await _execute(sql, *vals)
    if ok:
        log.debug(f"[DB] pentest scan updated - id={scan_id} status={status} stage={current_stage} progress={progress}")
    return ok


async def get_pentest_scan(scan_id: str) -> Optional[dict]:
    row = await _fetchone("SELECT * FROM pentest_scans WHERE scan_id = $1", scan_id)
    if row:
        import json as _json
        if row.get("results") and isinstance(row["results"], str):
            try:
                row["results"] = _json.loads(row["results"])
            except (_json.JSONDecodeError, TypeError):
                pass
        for ts_key in ("created_at", "updated_at", "completed_at"):
            if row.get(ts_key) and hasattr(row[ts_key], "isoformat"):
                row[ts_key] = row[ts_key].isoformat()
    return row


async def list_pentest_scans(limit: int = 50, offset: int = 0) -> list[dict]:
    limit = min(int(limit), 200)
    rows = await _fetchall(
        """
        SELECT scan_id, target, scan_type, status, progress, current_stage,
               created_at, updated_at, completed_at, triggered_by
        FROM pentest_scans
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        """,
        int(limit), int(offset),
    )
    for row in rows:
        for ts_key in ("created_at", "updated_at", "completed_at"):
            if row.get(ts_key) and hasattr(row[ts_key], "isoformat"):
                row[ts_key] = row[ts_key].isoformat()
    return rows


async def insert_pentest_scan(
    scan_id: str,
    target: str,
    scan_type: str = "quick",
    triggered_by: str = "user",
) -> bool:
    ok = await _execute(
        """
        INSERT INTO pentest_scans
            (scan_id, target, scan_type, status, progress, current_stage, created_at, updated_at, triggered_by)
        VALUES ($1, $2, $3, 'queued', 0, 'queued', NOW(), NOW(), $4)
        """,
        scan_id,
        target,
        scan_type,
        triggered_by,
    )
    if ok:
        log.info(f"[DB] pentest scan created - id={scan_id} target={target} type={scan_type}")
    return ok


async def upsert_action_control(
    target: str,
    *,
    action: str,
    reason: str = "",
    source: str = "manual",
    confidence: float = 0.0,
    trigger: str = "manual",
) -> bool:
    """
    Override that stores explainable action metadata and source/trigger.
    """
    action_upper = action.upper()
    is_blocked = action_upper == "BLOCK"
    is_isolated = action_upper == "ISOLATE"
    is_whitelisted = action_upper == "WHITELIST"
    ok = await _execute(
        """
        INSERT INTO action_controls
            (target, is_blocked, is_isolated, is_whitelisted, is_quarantined,
             last_action, reason, source, confidence, trigger, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
        ON CONFLICT (target) DO UPDATE
            SET is_blocked = EXCLUDED.is_blocked,
                is_isolated = EXCLUDED.is_isolated,
                is_whitelisted = EXCLUDED.is_whitelisted,
                is_quarantined = EXCLUDED.is_quarantined,
                last_action = EXCLUDED.last_action,
                reason = EXCLUDED.reason,
                source = EXCLUDED.source,
                confidence = EXCLUDED.confidence,
                trigger = EXCLUDED.trigger,
                updated_at = NOW()
        """,
        target,
        is_blocked,
        is_isolated,
        is_whitelisted,
        is_isolated,
        action_upper,
        reason[:500],
        source[:100],
        float(confidence),
        trigger[:50],
    )
    if ok:
        log.info(f"[DB] action control - target={target} action={action_upper} source={source} trigger={trigger}")
    return ok


async def get_action_control(target: str) -> Optional[dict]:
    row = await _fetchone(
        """
        SELECT target, is_blocked, is_isolated, is_whitelisted, is_quarantined,
               last_action, reason, source, confidence, trigger, updated_at
        FROM action_controls
        WHERE target = $1
        """,
        target,
    )
    if row and row.get("updated_at") and hasattr(row["updated_at"], "isoformat"):
        row["updated_at"] = row["updated_at"].isoformat()
    return row


async def insert_action(
    ip: str,
    action_type: str,
    reason: str = "",
    source: str = "manual",
    confidence: float = 0.0,
) -> bool:
    """
    Override that records action source and confidence in the action log.
    """
    ok = await _execute(
        """
        INSERT INTO actions (ip, action_type, reason, source, confidence, acted_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        """,
        ip,
        action_type.upper(),
        reason[:500],
        source[:100],
        float(confidence),
    )
    if ok:
        log.info(f"[DB] action - ip={ip} action={action_type} source={source} confidence={confidence:.2f}")
    return ok


async def get_actions(limit: int = 20, offset: int = 0) -> list[dict]:
    limit = min(int(limit), 200)
    rows = await _fetchall(
        """
        SELECT id, ip, action_type, reason, source, confidence, acted_at
        FROM actions
        ORDER BY acted_at DESC
        LIMIT $1 OFFSET $2
        """,
        int(limit), int(offset),
    )
    for row in rows:
        if row.get("acted_at") and hasattr(row["acted_at"], "isoformat"):
            row["acted_at"] = row["acted_at"].isoformat()
    return rows


# ──────────────────────────────────────────────────────────────────────────────
# SYNC WRAPPERS  (for Flask + threaded agent + action_manager)
# ──────────────────────────────────────────────────────────────────────────────
# FIXED: every wrapper now:
#   1. catches ALL exceptions (never crashes the caller)
#   2. returns a guaranteed safe default (False / [])
#   3. uses _run_async() which has its own 5s timeout
#   4. sync_insert_alert uses _check_cooldown_sync (threading.Lock path)
#      instead of going through the async path for cooldown checking
# ──────────────────────────────────────────────────────────────────────────────

def sync_insert_detection(src_ip, result, attack_type, confidence, iso_flag=0) -> bool:
    """Sync bridge → insert_detection()"""
    try:
        return _run_async(insert_detection(src_ip, result, attack_type, confidence, iso_flag)) or False
    except Exception:
        return False

def sync_insert_action(ip: str, action_type: str, reason: str = "") -> bool:
    """Sync bridge → insert_action()"""
    try:
        return _run_async(insert_action(ip, action_type, reason)) or False
    except Exception:
        return False

def sync_insert_blocked_ip(ip: str, reason: str = "") -> bool:
    """Sync bridge → insert_blocked_ip()"""
    try:
        return _run_async(insert_blocked_ip(ip, reason)) or False
    except Exception:
        return False

def sync_remove_blocked_ip(ip: str) -> bool:
    """Sync bridge → remove_blocked_ip()"""
    try:
        return _run_async(remove_blocked_ip(ip)) or False
    except Exception:
        return False

def sync_insert_flow(src_ip, dst_ip, packets, bytes_, pps, duration) -> bool:
    """Sync bridge → insert_flow()"""
    print("[DEBUG] flow insert called")
    try:
        return _run_async(insert_flow(src_ip, dst_ip, packets, bytes_, pps, duration)) or False
    except Exception as e:
        print(f"[DB ERROR] flow insert skipped safely: {e}")
        return False

def sync_upsert_host(ip: str, status: str = "SEEN") -> bool:
    """Sync bridge → upsert_host()"""
    try:
        return _run_async(upsert_host(ip, status)) or False
    except Exception:
        return False

def sync_update_host_status(ip: str, status: str) -> bool:
    """Sync bridge → update_host_status()"""
    try:
        return _run_async(update_host_status(ip, status)) or False
    except Exception:
        return False

def sync_insert_alert(ip: str, alert_type: str, message: str, metadata: Optional[dict] = None) -> bool:
    """
    # FIXED: sync path uses _check_cooldown_sync (threading.Lock) directly,
    # then delegates only the DB write to _run_async. This avoids submitting
    # the asyncio.Lock-based cooldown check through the thread bridge, which
    # would create a lock-type mismatch and potential deadlock.
    """
    try:
        suppressed = _check_cooldown_sync(ip, alert_type)
        if suppressed:
            log.debug(f"[DB] alert suppressed (cooldown/sync) — ip={ip} type={alert_type}")
            return True
        # Cooldown passed — only the DB write goes async
        async def _insert_only():
            import json as _json
            return await _execute(
                """
                INSERT INTO alerts (ip_address, alert_type, message, metadata)
                VALUES ($1, $2, $3, $4::jsonb)
                """,
                ip, alert_type.upper(), message[:1000], _json.dumps(metadata or {}, default=str),
            )
        ok = _run_async(_insert_only()) or False
        if ok:
            log.info(f"[DB] Alert inserted (sync) — ip={ip} type={alert_type}")
        return ok
    except Exception as exc:
        log.error(f"[DB ERROR] sync_insert_alert failed: {exc}")
        return False

def sync_get_alerts(limit: int = 50, offset: int = 0) -> list:
    """Sync bridge → get_alerts()"""
    try:
        return _run_async(get_alerts(limit=limit, offset=offset)) or []
    except Exception:
        return []

def sync_mark_alert_read(alert_id: int) -> bool:
    """Sync bridge → mark_alert_read()"""
    try:
        return _run_async(mark_alert_read(alert_id)) or False
    except Exception:
        return False

def sync_db_ping() -> bool:
    """Sync bridge → db_ping()"""
    try:
        return _run_async(db_ping()) or False
    except Exception:
        return False


# ── NEW READ-ONLY SYNC WRAPPERS  (used by Flask /detections /flows /actions) ─

def sync_get_detections(limit: int = 20, offset: int = 0, src_ip: Optional[str] = None) -> list:
    """Sync bridge → get_detections()"""
    try:
        return _run_async(get_detections(limit=limit, offset=offset, src_ip=src_ip)) or []
    except Exception:
        return []

def sync_get_flows(limit: int = 20, offset: int = 0, src_ip: Optional[str] = None) -> list:
    """Sync bridge → get_flows()"""
    try:
        return _run_async(get_flows(limit=limit, offset=offset, src_ip=src_ip)) or []
    except Exception:
        return []

def sync_get_actions(limit: int = 20, offset: int = 0) -> list:
    """Sync bridge → get_actions()"""
    try:
        return _run_async(get_actions(limit=limit, offset=offset)) or []
    except Exception:
        return []

def sync_get_blocked_ips() -> list:
    """Sync bridge → get_blocked_ips()"""
    try:
        return _run_async(get_blocked_ips()) or []
    except Exception:
        return []


# ──────────────────────────────────────────────────────────────────────────────
# PENTEST SCAN CRUD (PostgreSQL)
# ──────────────────────────────────────────────────────────────────────────────

async def insert_pentest_scan(
    scan_id:      str,
    target:       str,
    scan_type:    str = "quick",
    triggered_by: str = "user",
) -> bool:
    """
    Create a new pentest scan record.
    Table: pentest_scans(scan_id, target, scan_type, status, created_at, triggered_by)
    """
    ok = await _execute(
        """
        INSERT INTO pentest_scans
            (scan_id, target, scan_type, status, created_at, triggered_by)
        VALUES ($1, $2, $3, 'queued', NOW(), $4)
        """,
        scan_id, target, scan_type, triggered_by,
    )
    if ok:
        log.info(f"[DB] pentest scan created — id={scan_id} target={target} type={scan_type}")
    return ok


async def update_pentest_scan(
    scan_id:      str,
    *,
    status:       Optional[str] = None,
    results:      Optional[dict] = None,
    completed_at: Optional[str] = None,
) -> bool:
    """
    Update pentest scan status and/or results.
    Results are stored as JSONB.
    """
    import json as _json

    parts, vals = [], []
    if status:
        parts.append("status = $" + str(len(vals) + 1))
        vals.append(status)
    if results is not None:
        parts.append("results = $" + str(len(vals) + 1) + "::jsonb")
        vals.append(_json.dumps(results, default=str))
    if completed_at:
        parts.append("completed_at = $" + str(len(vals) + 1) + "::timestamptz")
        vals.append(completed_at)
    if not parts:
        return True

    vals.append(scan_id)
    sql = f"UPDATE pentest_scans SET {', '.join(parts)} WHERE scan_id = ${len(vals)}"
    ok = await _execute(sql, *vals)
    if ok:
        log.debug(f"[DB] pentest scan updated — id={scan_id} status={status}")
    return ok


async def get_pentest_scan(scan_id: str) -> Optional[dict]:
    """Fetch a single pentest scan by ID, including full results."""
    row = await _fetchone(
        "SELECT * FROM pentest_scans WHERE scan_id = $1", scan_id
    )
    if row:
        # Parse JSONB results if present
        import json as _json
        if row.get("results") and isinstance(row["results"], str):
            try:
                row["results"] = _json.loads(row["results"])
            except (_json.JSONDecodeError, TypeError):
                pass
        # Convert timestamps
        for ts_key in ("created_at", "completed_at"):
            if row.get(ts_key) and hasattr(row[ts_key], "isoformat"):
                row[ts_key] = row[ts_key].isoformat()
    return row


async def list_pentest_scans(limit: int = 50, offset: int = 0) -> list[dict]:
    """List pentest scans (summary only, no results blob), newest first."""
    limit = min(int(limit), 200)
    rows = await _fetchall(
        """
        SELECT scan_id, target, scan_type, status, created_at, completed_at, triggered_by
        FROM pentest_scans
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        """,
        int(limit), int(offset),
    )
    for row in rows:
        for ts_key in ("created_at", "completed_at"):
            if row.get(ts_key) and hasattr(row[ts_key], "isoformat"):
                row[ts_key] = row[ts_key].isoformat()
    return rows


# ── Pentest Sync Wrappers ────────────────────────────────────────────────────

def sync_insert_pentest_scan(scan_id, target, scan_type="quick", triggered_by="user") -> bool:
    """Sync bridge → insert_pentest_scan()"""
    try:
        return _run_async(insert_pentest_scan(scan_id, target, scan_type, triggered_by)) or False
    except Exception:
        return False

def sync_update_pentest_scan(scan_id, *, status=None, results=None, completed_at=None) -> bool:
    """Sync bridge → update_pentest_scan()"""
    try:
        return _run_async(update_pentest_scan(
            scan_id, status=status, results=results, completed_at=completed_at
        )) or False
    except Exception:
        return False

def sync_get_pentest_scan(scan_id: str) -> Optional[dict]:
    """Sync bridge → get_pentest_scan()"""
    try:
        return _run_async(get_pentest_scan(scan_id))
    except Exception:
        return None

def sync_list_pentest_scans(limit: int = 50, offset: int = 0) -> list:
    """Sync bridge → list_pentest_scans()"""
    try:
        return _run_async(list_pentest_scans(limit=limit, offset=offset)) or []
    except Exception:
        return []


# ──────────────────────────────────────────────────────────────────────────────
# POOL INIT HELPER FOR FLASK / THREADS
# ──────────────────────────────────────────────────────────────────────────────

def sync_insert_action(
    ip: str,
    action_type: str,
    reason: str = "",
    source: str = "manual",
    confidence: float = 0.0,
) -> bool:
    try:
        return _run_async(insert_action(ip, action_type, reason, source, confidence)) or False
    except Exception:
        return False


def sync_update_pentest_scan(
    scan_id,
    *,
    status=None,
    progress=None,
    current_stage=None,
    results=None,
    completed_at=None,
) -> bool:
    try:
        return _run_async(
            update_pentest_scan(
                scan_id,
                status=status,
                progress=progress,
                current_stage=current_stage,
                results=results,
                completed_at=completed_at,
            )
        ) or False
    except Exception:
        return False


def sync_upsert_action_control(
    target: str,
    *,
    action: str,
    reason: str = "",
    source: str = "manual",
    confidence: float = 0.0,
    trigger: str = "manual",
) -> bool:
    try:
        return _run_async(
            upsert_action_control(
                target,
                action=action,
                reason=reason,
                source=source,
                confidence=confidence,
                trigger=trigger,
            )
        ) or False
    except Exception:
        return False


def sync_get_action_control(target: str) -> Optional[dict]:
    try:
        return _run_async(get_action_control(target))
    except Exception:
        return None


def sync_get_security_finding(finding_id: str) -> Optional[dict]:
    try:
        return _run_async(get_security_finding(finding_id))
    except Exception:
        return None


def sync_get_security_finding_by_fingerprint(fingerprint: str) -> Optional[dict]:
    try:
        return _run_async(get_security_finding_by_fingerprint(fingerprint))
    except Exception:
        return None


def sync_get_security_findings(
    limit: int = 50,
    *,
    target: Optional[str] = None,
    include_resolved: bool = True,
) -> list:
    try:
        return _run_async(
            get_security_findings(limit=limit, target=target, include_resolved=include_resolved)
        ) or []
    except Exception:
        return []


def sync_upsert_security_finding(record: dict) -> bool:
    try:
        return _run_async(upsert_security_finding(record)) or False
    except Exception:
        return False


async def update_security_finding_status(
    finding_id: str,
    *,
    mitigation_status: str,
    action_taken: Optional[str] = None,
    action_source: Optional[str] = None,
) -> Optional[dict]:
    """Partially update a finding's mitigation state and action metadata."""
    import json as _json
    now = datetime.utcnow().isoformat()
    parts = [
        "mitigation_state = $2",
        "updated_at = NOW()",
        "last_action_at = NOW()",
    ]
    vals: list = [finding_id, mitigation_status]
    if action_taken:
        vals.append(action_taken)
        parts.append(f"action_type = ${len(vals)}")
    if action_source:
        vals.append(action_source)
        parts.append(f"action_source = ${len(vals)}")
    if mitigation_status == "mitigated":
        parts.append("status = 'resolved'")
        parts.append("resolved_at = NOW()")
    elif mitigation_status == "partially_mitigated":
        parts.append("status = 'action_taken'")
    sql = f"UPDATE security_findings SET {', '.join(parts)} WHERE finding_id = $1"
    ok = await _execute(sql, *vals)
    if ok:
        log.info(f"[DB] finding updated - id={finding_id} status={mitigation_status}")
        return await get_security_finding(finding_id)
    return None


def sync_update_security_finding_status(
    finding_id: str,
    *,
    mitigation_status: str,
    action_taken: Optional[str] = None,
    action_source: Optional[str] = None,
) -> Optional[dict]:
    try:
        return _run_async(
            update_security_finding_status(
                finding_id,
                mitigation_status=mitigation_status,
                action_taken=action_taken,
                action_source=action_source,
            )
        )
    except Exception:
        return None


async def insert_activity_log(event: Optional[dict] = None, **kwargs) -> bool:
    """
    Insert one activity log event.
    Table: activity_logs(id, timestamp, type, action, target, reason, source, status, metadata, created_at)
    """
    import json as _json
    payload = dict(event or {})
    payload.update(kwargs)
    ok = await _execute(
        """
        INSERT INTO activity_logs
            (timestamp, type, action, target, reason, source, status, metadata, created_at)
        VALUES
            (COALESCE($1::timestamptz, NOW()), $2, $3, $4, $5, $6, $7, $8::jsonb, NOW())
        """,
        payload.get("timestamp"),
        (payload.get("type") or "system")[:50],
        (payload.get("action") or "unknown")[:100],
        (payload.get("target") or "")[:255],
        (payload.get("reason") or "")[:500],
        (payload.get("source") or "system")[:50],
        (payload.get("status") or "success")[:50],
        _json.dumps(payload.get("metadata") or {}, default=str),
    )
    return ok


def sync_insert_activity_log(event: Optional[dict] = None, **kwargs) -> bool:
    try:
        payload = dict(event or {})
        payload.update(kwargs)
        return _run_async(insert_activity_log(payload)) or False
    except Exception:
        return False


async def get_activity_logs(
    limit: int = 50,
    *,
    type_filter: Optional[str] = None,
    target: Optional[str] = None,
) -> list[dict]:
    limit = min(int(limit), 200)
    clauses: list[str] = []
    vals: list = []
    if type_filter:
        vals.append(type_filter)
        clauses.append(f"type = ${len(vals)}")
    if target:
        vals.append(target)
        clauses.append(f"target = ${len(vals)}")
    sql = "SELECT * FROM activity_logs"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    vals.append(int(limit))
    sql += f" ORDER BY created_at DESC LIMIT ${len(vals)}"
    rows = await _fetchall(sql, *vals)
    for row in rows:
        if row.get("created_at") and hasattr(row["created_at"], "isoformat"):
            row["created_at"] = row["created_at"].isoformat()
    return rows


def sync_get_activity_logs(
    limit: int = 50,
    *,
    type_filter: Optional[str] = None,
    target: Optional[str] = None,
) -> list:
    try:
        return _run_async(
            get_activity_logs(limit=limit, type_filter=type_filter, target=target)
        ) or []
    except Exception:
        return []


def sync_init_pool() -> None:
    """
    Initialise the asyncpg pool from synchronous code.
    Call this once at Flask app startup or agent startup.

    Example in Flask:
        with app.app_context():
            from db import sync_init_pool
            sync_init_pool()
    """
    _run_async(init_pool())
    _run_async(ensure_runtime_schema())


# ──────────────────────────────────────────────────────────────────────────────
# USER AUTH CRUD  (used by auth.py)
# ──────────────────────────────────────────────────────────────────────────────

from datetime import datetime


async def create_user(username: str, email: str, password_hash: str, role: str = "analyst") -> Optional[dict]:
    """
    Insert a new user and return the created row as dict.
    Returns None on duplicate or DB error.
    """
    pool = get_pool()
    if pool is None:
        return None
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO users (username, email, password_hash, role, created_at)
                VALUES ($1, $2, $3, $4, NOW())
                RETURNING id, username, email, role, is_active, created_at
                """,
                username, email, password_hash, role,
            )
        if row:
            result = dict(row)
            if result.get("created_at") and hasattr(result["created_at"], "isoformat"):
                result["created_at"] = result["created_at"].isoformat()
            return result
        return None
    except asyncpg.UniqueViolationError:
        log.warning(f"[DB] create_user duplicate — username={username} email={email}")
        return None
    except Exception as exc:
        log.error(f"[DB ERROR] create_user failed: {exc}")
        return None


async def get_user_by_email(email: str) -> Optional[dict]:
    """Fetch a user by email address."""
    return await _fetchone(
        "SELECT id, username, email, password_hash, role, is_active, created_at, last_login_at FROM users WHERE email = $1",
        email,
    )


async def get_user_by_username(username: str) -> Optional[dict]:
    """Fetch a user by username."""
    return await _fetchone(
        "SELECT id, username, email, password_hash, role, is_active, created_at, last_login_at FROM users WHERE username = $1",
        username,
    )


async def get_user_by_id(user_id: int) -> Optional[dict]:
    """Fetch a user by primary key."""
    return await _fetchone(
        "SELECT id, username, email, role, is_active, created_at, last_login_at FROM users WHERE id = $1",
        int(user_id),
    )


async def update_last_login(user_id: int) -> bool:
    """Update the last_login_at timestamp for a user."""
    return await _execute(
        "UPDATE users SET last_login_at = NOW() WHERE id = $1",
        int(user_id),
    )


# ── Sync wrappers for auth (Flask context) ───────────────────────────────────

def sync_create_user(username: str, email: str, password_hash: str, role: str = "analyst") -> Optional[dict]:
    try:
        return _run_async(create_user(username, email, password_hash, role))
    except Exception:
        return None


def sync_get_user_by_email(email: str) -> Optional[dict]:
    try:
        return _run_async(get_user_by_email(email))
    except Exception:
        return None


def sync_get_user_by_username(username: str) -> Optional[dict]:
    try:
        return _run_async(get_user_by_username(username))
    except Exception:
        return None


def sync_get_user_by_id(user_id: int) -> Optional[dict]:
    try:
        return _run_async(get_user_by_id(user_id))
    except Exception:
        return None


def sync_update_last_login(user_id: int) -> bool:
    try:
        return _run_async(update_last_login(user_id)) or False
    except Exception:
        return False

