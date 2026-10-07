"""ROASTROOM SQLite database layer.

Fresh production-style database:
- Creates all required tables automatically.
- Does NOT seed demo/example content.
- Does NOT migrate old/legacy demo data.
- Creates today's Daily Challenge automatically.
"""

import logging
import os
import re
import sqlite3
from datetime import datetime, timezone

log = logging.getLogger("roastroom.db")

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = (
    os.environ.get("DATABASE_PATH")
    or os.path.join(BASE_DIR, "roastroom.db")
)

TAGS = [
    "College",
    "Dating",
    "Confession",
    "Opinion",
    "Random",
    "Tech",
    "Life",
    "Relationships",
    "Other",
]

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,24}$")


# ---------------------------------------------------------------------------
# DAILY CHALLENGES
# ---------------------------------------------------------------------------

CHALLENGE_PROMPTS = [
    ("Describe your worst day in 10 words.", 10),
    ("Explain your last failed exam in 8 words.", 8),
    ("Your most embarrassing autocorrect moment, in 12 words.", 12),
    ("Write your brutally honest dating bio. 15 words max.", 15),
    ("Summarize your college life as a fake movie title.", 8),
    ("The dumbest reason you've ever been late, in 12 words.", 12),
    ("Describe your last group project in 10 words.", 10),
    ("Your worst 'seen' moment, in 10 words.", 10),
]


# ---------------------------------------------------------------------------
# DATABASE SCHEMA
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL UNIQUE COLLATE NOCASE,
    token_hash  TEXT,
    is_banned   INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen   TEXT
);

CREATE TABLE IF NOT EXISTS posts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title        TEXT NOT NULL,
    body         TEXT NOT NULL,
    tag          TEXT NOT NULL DEFAULT 'Other',
    legacy_likes INTEGER NOT NULL DEFAULT 0,
    removed      INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_posts_created
ON posts(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_posts_user
ON posts(user_id);


CREATE TABLE IF NOT EXISTS comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id    INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    removed    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_comments_post
ON comments(post_id, created_at);

CREATE INDEX IF NOT EXISTS idx_comments_user
ON comments(user_id);


CREATE TABLE IF NOT EXISTS likes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id    INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(post_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_likes_user
ON likes(user_id);


CREATE TABLE IF NOT EXISTS battles (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER REFERENCES users(id) ON DELETE SET NULL,
    prompt         TEXT NOT NULL,
    option_a       TEXT NOT NULL,
    option_b       TEXT NOT NULL,
    legacy_votes_a INTEGER NOT NULL DEFAULT 0,
    legacy_votes_b INTEGER NOT NULL DEFAULT 0,
    active         INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);


CREATE TABLE IF NOT EXISTS battle_votes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    battle_id  INTEGER NOT NULL REFERENCES battles(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    choice     TEXT NOT NULL CHECK(choice IN ('a', 'b')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(battle_id, user_id)
);


CREATE TABLE IF NOT EXISTS challenges (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    day        TEXT NOT NULL UNIQUE,
    prompt     TEXT NOT NULL,
    max_words  INTEGER NOT NULL DEFAULT 30,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);


CREATE TABLE IF NOT EXISTS challenge_submissions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    answer       TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(challenge_id, user_id)
);


CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    target_type TEXT NOT NULL
        CHECK(target_type IN ('post', 'comment', 'user')),
    target_key  TEXT NOT NULL,
    reason      TEXT NOT NULL,
    details     TEXT,
    status      TEXT NOT NULL DEFAULT 'open'
        CHECK(status IN ('open', 'resolved', 'dismissed')),
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at TEXT,
    UNIQUE(reporter_id, target_type, target_key)
);

CREATE INDEX IF NOT EXISTS idx_reports_status
ON reports(status, created_at DESC);


CREATE TABLE IF NOT EXISTS moderation_actions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id   INTEGER REFERENCES reports(id) ON DELETE SET NULL,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_key  TEXT,
    note        TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def utcnow():
    """Return current UTC time as a database-friendly string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def iso(ts):
    """Convert database timestamp into API ISO timestamp."""
    if not ts:
        return None

    ts = str(ts)

    if "T" in ts:
        if ts.endswith("Z") or "+" in ts[10:]:
            return ts
        return ts + "Z"

    return ts.replace(" ", "T") + "Z"


def connect():
    """Open a SQLite connection."""
    conn = sqlite3.connect(DB_PATH, timeout=15)

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON")

    return conn


def _table_exists(conn, table):
    """Check whether a table exists."""
    return (
        conn.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table'
            AND name = ?
            """,
            (table,),
        ).fetchone()
        is not None
    )


def _cols(conn, table):
    """Return table column names."""
    return [
        row["name"]
        for row in conn.execute(
            f'PRAGMA table_info("{table}")'
        )
    ]


def _ensure_column(conn, table, column, ddl):
    """Add a column if it doesn't exist."""
    if _table_exists(conn, table):
        if column not in _cols(conn, table):
            conn.execute(
                f'ALTER TABLE "{table}" ADD COLUMN {column} {ddl}'
            )


def _norm_tag(tag):
    """Normalize post tags."""
    for tag_name in TAGS:
        if str(tag or "").strip().lower() == tag_name.lower():
            return tag_name

    return "Other"


# ---------------------------------------------------------------------------
# USERNAME VALIDATION
# ---------------------------------------------------------------------------

def valid_username(username):
    """Return True when username matches ROASTROOM rules."""
    return bool(
        USERNAME_RE.fullmatch(
            str(username or "").strip()
        )
    )


# ---------------------------------------------------------------------------
# USER HELPERS
# ---------------------------------------------------------------------------

def get_or_create_user(conn, username):
    """Create a user if they don't already exist."""

    username = str(username or "").strip()

    if not valid_username(username):
        raise ValueError(
            "Username must be 3-24 characters and contain only "
            "letters, numbers, and underscores."
        )

    conn.execute(
        """
        INSERT OR IGNORE INTO users (username)
        VALUES (?)
        """,
        (username,),
    )

    return conn.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()


# ---------------------------------------------------------------------------
# DAILY CHALLENGE
# ---------------------------------------------------------------------------

def ensure_today_challenge(conn):
    """Create today's challenge if it doesn't already exist."""

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    existing = conn.execute(
        """
        SELECT *
        FROM challenges
        WHERE day = ?
        """,
        (today,),
    ).fetchone()

    if existing:
        return existing

    index = (
        datetime.now(timezone.utc).toordinal()
        % len(CHALLENGE_PROMPTS)
    )

    prompt, max_words = CHALLENGE_PROMPTS[index]

    conn.execute(
        """
        INSERT OR IGNORE INTO challenges
        (day, prompt, max_words)
        VALUES (?, ?, ?)
        """,
        (
            today,
            prompt,
            max_words,
        ),
    )

    conn.commit()

    return conn.execute(
        """
        SELECT *
        FROM challenges
        WHERE day = ?
        """,
        (today,),
    ).fetchone()


# ---------------------------------------------------------------------------
# NO DEMO SEEDING
# ---------------------------------------------------------------------------

def _seed(conn):
    """
    Demo/example data is intentionally disabled.

    ROASTROOM starts completely empty.

    Users, posts, comments, likes, battles and leaderboard
    entries are created only through actual user actions.
    """

    return


# ---------------------------------------------------------------------------
# DATABASE INITIALIZATION
# ---------------------------------------------------------------------------

def init_db():
    """Create a completely fresh ROASTROOM database structure."""

    os.makedirs(
        os.path.dirname(
            os.path.abspath(DB_PATH)
        ),
        exist_ok=True,
    )

    conn = connect()

    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")

        # Create tables.
        conn.executescript(SCHEMA)

        # Ensure required user columns exist.
        _ensure_column(
            conn,
            "users",
            "token_hash",
            "TEXT",
        )

        _ensure_column(
            conn,
            "users",
            "is_banned",
            "INTEGER NOT NULL DEFAULT 0",
        )

        _ensure_column(
            conn,
            "users",
            "last_seen",
            "TEXT",
        )

        _ensure_column(
            conn,
            "users",
            "created_at",
            "TEXT",
        )

        # Repair NULL created_at values from older databases.
        if (
            _table_exists(conn, "users")
            and "created_at" in _cols(conn, "users")
        ):
            conn.execute(
                """
                UPDATE users
                SET created_at = datetime('now')
                WHERE created_at IS NULL
                """
            )

        # IMPORTANT:
        # No legacy data migration.
        # No demo/example data migration.
        # No fake users.
        # No fake posts.
        # No fake battles.

        _seed(conn)

        conn.commit()

        # Daily Challenge is intentionally created.
        ensure_today_challenge(conn)

        log.info(
            "ROASTROOM database ready at %s",
            DB_PATH,
        )

    finally:
        conn.close()


# ---------------------------------------------------------------------------
# DIRECT EXECUTION
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO
    )

    init_db()

    print(
        f"Database initialized: {DB_PATH}"
    )