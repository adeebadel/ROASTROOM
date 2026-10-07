"""ROASTROOM API server (Flask + SQLite).

Run:  python backend/app.py        (from the project root)
Prod: gunicorn --chdir backend app:app --workers 1 --threads 4
"""
import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)


def load_env():
    """Tiny .env loader (no extra dependency). Real environment variables always win."""
    for folder in (ROOT_DIR, BASE_DIR):
        path = os.path.join(folder, ".env")
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env()

from flask import Flask, g, jsonify, request, send_from_directory  # noqa: E402
from flask_cors import CORS  # noqa: E402
from werkzeug.exceptions import HTTPException  # noqa: E402

from backend import moderation
from backend import roast_engine
from backend.database import TAGS, USERNAME_RE, iso  # noqa: E402
from backend import database

VERSION = "1.0.0"
PRODUCTION = os.environ.get("ROASTROOM_ENV", os.environ.get("FLASK_ENV", "")).lower() == "production"
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "").strip()
if not ADMIN_SECRET and not PRODUCTION:
    ADMIN_SECRET = secrets.token_urlsafe(12)
    print(f"\n  [ROASTROOM] ADMIN_SECRET not set. Temporary dev secret for /admin: {ADMIN_SECRET}\n"
          "  Set ADMIN_SECRET in .env to make it permanent.\n")

DEFAULT_ORIGINS = ",".join([
    "http://localhost:5000", "http://127.0.0.1:5000",
    "http://localhost:5500", "http://127.0.0.1:5500",
    "http://localhost:3000", "http://127.0.0.1:3000",
    "http://localhost:8000", "http://127.0.0.1:8000",
    "null",  # index.html opened straight from disk (file://) sends Origin: null
])
CORS_ORIGINS = [o.strip() for o in os.environ.get("CORS_ORIGINS", DEFAULT_ORIGINS).split(",") if o.strip()]

REPORT_REASONS = ["harassment", "spam", "hate", "sexual content", "self-harm", "violence", "other"]
RESERVED_NAMES = {"admin", "administrator", "moderator", "mod", "system", "support", "roastroom", "staff"}
SORTS = {
    "new": "p.created_at DESC, p.id DESC",
    "top": "likes DESC, p.created_at DESC",
    "discussed": "comments DESC, p.created_at DESC",
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("roastroom")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024
app.json.sort_keys = False
if os.environ.get("TRUST_PROXY") == "1":  # behind Render/Heroku/nginx: use X-Forwarded-For for the real client IP
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

CORS(
    app,
    resources={r"/api/*": {"origins": CORS_ORIGINS}},
    allow_headers=["Content-Type", "X-Username", "X-Token", "X-Admin-Secret"],
    methods=["GET", "POST", "PATCH", "OPTIONS"],
    max_age=600,
)

database.init_db()


# =========================================================================== plumbing
class ApiError(Exception):
    def __init__(self, message, status=400, code=None, **extra):
        super().__init__(message)
        self.message, self.status, self.code, self.extra = message, status, code, extra


@app.errorhandler(ApiError)
def handle_api_error(e):
    body = {"error": e.message}
    if e.code:
        body["code"] = e.code
    body.update(e.extra)
    resp = jsonify(body)
    resp.status_code = e.status
    if e.status == 429 and "retry_after" in e.extra:
        resp.headers["Retry-After"] = str(e.extra["retry_after"])
    return resp


@app.errorhandler(HTTPException)
def handle_http_error(e):
    if request.path.startswith("/api/"):
        messages = {404: "That doesn't exist.", 405: "Method not allowed.", 413: "That's too big to send."}
        return jsonify(error=messages.get(e.code, e.description)), e.code
    return e


@app.errorhandler(Exception)
def handle_unexpected(e):
    log.exception("Unhandled error on %s %s", request.method, request.path)
    return jsonify(error="Something broke on our side. Try again in a moment."), 500


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")
    elif resp.mimetype == "text/html":
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self' http://127.0.0.1:* http://localhost:*; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
    return resp


def db():
    if "db" not in g:
        g.db = database.connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def json_body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError("Send a JSON body.")
    return data


def int_arg(name, default, lo, hi):
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(lo, min(hi, value))


_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean(value, lo, hi, label, multiline=False):
    if not isinstance(value, str):
        raise ApiError(f"{label} is required.")
    value = _CTRL.sub("", value).strip()
    value = re.sub(r"\n{3,}", "\n\n", value) if multiline else re.sub(r"\s+", " ", value)
    if len(value) < lo:
        raise ApiError(f"{label} is required." if lo <= 1 else f"{label} needs at least {lo} characters.")
    if len(value) > hi:
        raise ApiError(f"{label} must be {hi} characters or fewer.")
    return value


def moderate(text):
    cleaned, error = moderation.screen(text)
    if error:
        raise ApiError(error, 422, code="moderation")
    return cleaned


def client_ip():
    return request.remote_addr or "unknown"


def rate_limit(bucket, limit, window, user_id=None):
    """Per-user limit (if known) plus a looser per-IP limit."""
    if user_id:
        ok, wait = moderation.limiter.allow((bucket, "u", user_id), limit, window)
        if not ok:
            raise ApiError(f"Slow down. Try again in {wait}s.", 429, code="rate_limited", retry_after=wait)
    ok, wait = moderation.limiter.allow((bucket, "ip", client_ip()), limit * 4, window)
    if not ok:
        raise ApiError(f"Too many requests from your network. Try again in {wait}s.", 429, code="rate_limited", retry_after=wait)


# =========================================================================== identity
def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _identity_headers():
    return request.headers.get("X-Username", "").strip(), request.headers.get("X-Token", "").strip()


def get_identity(conn):
    """Authenticate (and lazily register) the pseudonymous browser identity."""
    username, token = _identity_headers()
    if not USERNAME_RE.match(username) or not (16 <= len(token) <= 128):
        raise ApiError("Your identity is missing. Refresh the page.", 401, code="no_identity")
    th = hash_token(token)
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        conn.execute("INSERT OR IGNORE INTO users (username, token_hash, last_seen) VALUES (?,?,datetime('now'))", (username, th))
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row["token_hash"] is None:
        conn.execute("UPDATE users SET token_hash = ? WHERE id = ?", (th, row["id"]))
    elif not hmac.compare_digest(row["token_hash"], th):
        raise ApiError("That username already belongs to someone else.", 403, code="identity_conflict")
    if row["is_banned"]:
        raise ApiError("This identity has been suspended.", 403, code="banned")
    conn.execute("UPDATE users SET last_seen = datetime('now') WHERE id = ?", (row["id"],))
    conn.commit()
    return row


def viewer_id(conn):
    """Optional identity for read endpoints. Returns 0 when unknown (never raises)."""
    username, token = _identity_headers()
    if not USERNAME_RE.match(username) or len(token) < 16:
        return 0
    row = conn.execute("SELECT id, token_hash FROM users WHERE username = ?", (username,)).fetchone()
    if row and row["token_hash"] and hmac.compare_digest(row["token_hash"], hash_token(token)):
        return row["id"]
    return 0


def user_public(row):
    return {"username": row["username"], "joined": iso(row["created_at"])}


@app.post("/api/identity")
def register_identity():
    conn = db()
    rate_limit("identity", 30, 60)
    return jsonify(user=user_public(get_identity(conn)))


@app.post("/api/users/me/rename")
def rename_me():
    conn = db()
    data = json_body()
    user = get_identity(conn)
    rate_limit("rename", 5, 600, user["id"])
    new = clean(data.get("username"), 3, 24, "Username")
    if not USERNAME_RE.match(new):
        raise ApiError("Usernames are 3-24 characters: letters, numbers, underscore.")
    if new.lower() in RESERVED_NAMES or moderation.has_profanity(new):
        raise ApiError("Pick a different username.")
    taken = conn.execute("SELECT id FROM users WHERE username = ? AND id != ?", (new, user["id"])).fetchone()
    if taken:
        raise ApiError("That username is taken.", 409)
    conn.execute("UPDATE users SET username = ? WHERE id = ?", (new, user["id"]))
    conn.commit()
    return jsonify(user={"username": new, "joined": iso(user["created_at"])})


# =========================================================================== serialisation
POST_COLUMNS = """
    p.id, p.title, p.body, p.tag, p.created_at, u.username,
    ((SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) + p.legacy_likes) AS likes,
    (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id AND c.removed = 0) AS comments,
    EXISTS (SELECT 1 FROM likes l2 WHERE l2.post_id = p.id AND l2.user_id = :viewer) AS liked
"""


def post_dict(r):
    return {
        "id": r["id"], "title": r["title"], "body": r["body"], "tag": r["tag"],
        "username": r["username"], "created_at": iso(r["created_at"]),
        "likes": r["likes"], "comments": r["comments"], "liked": bool(r["liked"]),
    }


def fetch_post(conn, post_id, viewer):
    r = conn.execute(
        f"SELECT {POST_COLUMNS} FROM posts p JOIN users u ON u.id = p.user_id WHERE p.id = :id AND p.removed = 0",
        {"id": post_id, "viewer": viewer},
    ).fetchone()
    return post_dict(r) if r else None


def comment_dict(r):
    return {"id": r["id"], "post_id": r["post_id"], "username": r["username"], "body": r["body"], "created_at": iso(r["created_at"])}


# =========================================================================== health
@app.get("/api/health")
def health():
    db().execute("SELECT 1").fetchone()
    return jsonify(status="ok", service="roastroom", version=VERSION, db="ok", time=iso(database.utcnow()))


@app.get("/api/tags")
def tags():
    return jsonify(tags=TAGS, report_reasons=REPORT_REASONS)


# =========================================================================== posts
@app.get("/api/posts")
def list_posts():
    conn = db()
    sort = request.args.get("sort", "new")
    if sort not in SORTS:
        raise ApiError("Unknown sort.")
    tag = request.args.get("tag", "").strip()
    if tag and tag not in TAGS:
        raise ApiError("Unknown tag.")
    limit, offset = int_arg("limit", 20, 1, 50), int_arg("offset", 0, 0, 100000)
    where = "p.removed = 0" + (" AND p.tag = :tag" if tag else "")
    rows = conn.execute(
        f"SELECT {POST_COLUMNS} FROM posts p JOIN users u ON u.id = p.user_id WHERE {where} "
        f"ORDER BY {SORTS[sort]} LIMIT :limit OFFSET :offset",
        {"viewer": viewer_id(conn), "tag": tag, "limit": limit + 1, "offset": offset},
    ).fetchall()
    return jsonify(posts=[post_dict(r) for r in rows[:limit]], has_more=len(rows) > limit, sort=sort)


@app.post("/api/posts")
def create_post():
    conn = db()
    data = json_body()
    user = get_identity(conn)
    rate_limit("post", 4, 60, user["id"])
    title = moderate(clean(data.get("title"), 3, 120, "Title"))
    body = moderate(clean(data.get("body"), 5, 2000, "Story", multiline=True))
    tag = data.get("tag") or "Other"
    if tag not in TAGS:
        raise ApiError("Pick a valid tag.")
    dup = conn.execute(
        "SELECT 1 FROM posts WHERE user_id = ? AND lower(title) = lower(?) AND lower(body) = lower(?) "
        "AND created_at > datetime('now', '-1 day')", (user["id"], title, body)).fetchone()
    if dup:
        raise ApiError("You already posted that. Once is roastable enough.", 409, code="duplicate")
    cur = conn.execute("INSERT INTO posts (user_id, title, body, tag) VALUES (?,?,?,?)", (user["id"], title, body, tag))
    conn.commit()
    return jsonify(post=fetch_post(conn, cur.lastrowid, user["id"])), 201


@app.get("/api/posts/<int:post_id>")
def get_post(post_id):
    conn = db()
    post = fetch_post(conn, post_id, viewer_id(conn))
    if not post:
        raise ApiError("That post is gone (or never existed).", 404)
    return jsonify(post=post)


@app.post("/api/posts/<int:post_id>/like")
def like_post(post_id):
    conn = db()
    user = get_identity(conn)
    rate_limit("like", 40, 60, user["id"])
    if not conn.execute("SELECT 1 FROM posts WHERE id = ? AND removed = 0", (post_id,)).fetchone():
        raise ApiError("That post is gone.", 404)
    removed = conn.execute("DELETE FROM likes WHERE post_id = ? AND user_id = ?", (post_id, user["id"])).rowcount
    if not removed:
        conn.execute("INSERT INTO likes (post_id, user_id) VALUES (?,?)", (post_id, user["id"]))
    conn.commit()
    likes = conn.execute(
        "SELECT (SELECT COUNT(*) FROM likes WHERE post_id = ?) + legacy_likes AS n FROM posts WHERE id = ?",
        (post_id, post_id)).fetchone()["n"]
    return jsonify(post_id=post_id, liked=not removed, likes=likes)


# =========================================================================== comments
@app.get("/api/posts/<int:post_id>/comments")
def list_comments(post_id):
    conn = db()
    if not conn.execute("SELECT 1 FROM posts WHERE id = ? AND removed = 0", (post_id,)).fetchone():
        raise ApiError("That post is gone.", 404)
    rows = conn.execute(
        "SELECT c.id, c.post_id, c.body, c.created_at, u.username FROM comments c JOIN users u ON u.id = c.user_id "
        "WHERE c.post_id = ? AND c.removed = 0 ORDER BY c.created_at ASC, c.id ASC LIMIT 300", (post_id,)).fetchall()
    return jsonify(comments=[comment_dict(r) for r in rows], count=len(rows))


@app.post("/api/posts/<int:post_id>/comments")
def add_comment(post_id):
    conn = db()
    data = json_body()
    user = get_identity(conn)
    rate_limit("comment", 8, 60, user["id"])
    if not conn.execute("SELECT 1 FROM posts WHERE id = ? AND removed = 0", (post_id,)).fetchone():
        raise ApiError("That post is gone.", 404)
    body = moderate(clean(data.get("body"), 1, 500, "Comment", multiline=True))
    dup = conn.execute(
        "SELECT 1 FROM comments WHERE post_id = ? AND user_id = ? AND lower(body) = lower(?) "
        "AND created_at > datetime('now', '-10 minutes')", (post_id, user["id"], body)).fetchone()
    if dup:
        raise ApiError("You already said that. Try a fresher roast.", 409, code="duplicate")
    cur = conn.execute("INSERT INTO comments (post_id, user_id, body) VALUES (?,?,?)", (post_id, user["id"], body))
    conn.commit()
    row = conn.execute(
        "SELECT c.id, c.post_id, c.body, c.created_at, u.username FROM comments c JOIN users u ON u.id = c.user_id WHERE c.id = ?",
        (cur.lastrowid,)).fetchone()
    count = conn.execute("SELECT COUNT(*) AS n FROM comments WHERE post_id = ? AND removed = 0", (post_id,)).fetchone()["n"]
    return jsonify(comment=comment_dict(row), count=count), 201


# =========================================================================== trending
@app.get("/api/trending")
def trending():
    conn = db()
    rows = conn.execute(
        f"SELECT {POST_COLUMNS} FROM posts p JOIN users u ON u.id = p.user_id "
        "WHERE p.removed = 0 AND p.created_at > datetime('now', '-14 days') ORDER BY p.created_at DESC LIMIT 400",
        {"viewer": viewer_id(conn)},
    ).fetchall()
    now = datetime.now(timezone.utc)
    ranked = []
    for r in rows:
        created = datetime.strptime(r["created_at"][:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        age_hours = max(0.0, (now - created).total_seconds() / 3600)
        recency = max(0.0, 48 - age_hours)  # up to 48 bonus points, fading to 0 over two days
        score = r["likes"] * 3 + r["comments"] * 5 + recency
        item = post_dict(r)
        item["score"] = round(score, 1)
        ranked.append(item)
    ranked.sort(key=lambda p: (-p["score"], -p["id"]))
    top = ranked[: int_arg("limit", 15, 1, 30)]
    for i, p in enumerate(top, 1):
        p["rank"] = i
    return jsonify(posts=top)


# =========================================================================== battles
BATTLE_SQL = """
SELECT b.id, b.prompt, b.option_a, b.option_b, b.created_at, u.username AS author,
  ((SELECT COUNT(*) FROM battle_votes v WHERE v.battle_id = b.id AND v.choice = 'a') + b.legacy_votes_a) AS votes_a,
  ((SELECT COUNT(*) FROM battle_votes v WHERE v.battle_id = b.id AND v.choice = 'b') + b.legacy_votes_b) AS votes_b,
  (SELECT v.choice FROM battle_votes v WHERE v.battle_id = b.id AND v.user_id = :viewer) AS my_vote
FROM battles b LEFT JOIN users u ON u.id = b.user_id
"""


def battle_dict(r):
    a, b = r["votes_a"], r["votes_b"]
    total = a + b
    pct_a = round(100 * a / total) if total else 0
    winner = None if total == 0 else ("a" if a > b else "b" if b > a else "tie")
    return {
        "id": r["id"], "prompt": r["prompt"], "author": r["author"], "created_at": iso(r["created_at"]),
        "a": {"text": r["option_a"], "votes": a, "percent": pct_a},
        "b": {"text": r["option_b"], "votes": b, "percent": (100 - pct_a) if total else 0},
        "total": total, "winner": winner, "my_vote": r["my_vote"],
    }


def fetch_battle(conn, battle_id, viewer):
    r = conn.execute(BATTLE_SQL + " WHERE b.id = :id AND b.active = 1", {"id": battle_id, "viewer": viewer}).fetchone()
    return battle_dict(r) if r else None


@app.get("/api/battles")
def list_battles():
    conn = db()
    rows = conn.execute(BATTLE_SQL + " WHERE b.active = 1 ORDER BY b.id DESC LIMIT 30", {"viewer": viewer_id(conn)}).fetchall()
    return jsonify(battles=[battle_dict(r) for r in rows])


@app.post("/api/battles")
def create_battle():
    conn = db()
    data = json_body()
    user = get_identity(conn)
    rate_limit("battle_create", 3, 600, user["id"])
    prompt = moderate(clean(data.get("prompt") or "What's worse?", 3, 120, "Question"))
    a = moderate(clean(data.get("option_a"), 2, 80, "Option A"))
    b = moderate(clean(data.get("option_b"), 2, 80, "Option B"))
    if a.lower() == b.lower():
        raise ApiError("Both options can't be the same.")
    dup = conn.execute(
        "SELECT 1 FROM battles WHERE lower(option_a) = lower(?) AND lower(option_b) = lower(?) AND created_at > datetime('now', '-1 day')",
        (a, b)).fetchone()
    if dup:
        raise ApiError("That battle already exists. Go vote on it.", 409, code="duplicate")
    cur = conn.execute("INSERT INTO battles (user_id, prompt, option_a, option_b) VALUES (?,?,?,?)", (user["id"], prompt, a, b))
    conn.commit()
    return jsonify(battle=fetch_battle(conn, cur.lastrowid, user["id"])), 201


@app.post("/api/battles/<int:battle_id>/vote")
def vote_battle(battle_id):
    conn = db()
    data = json_body()
    user = get_identity(conn)
    rate_limit("vote", 30, 60, user["id"])
    choice = str(data.get("choice", "")).lower()
    if choice not in ("a", "b"):
        raise ApiError("Pick option A or B.")
    if not conn.execute("SELECT 1 FROM battles WHERE id = ? AND active = 1", (battle_id,)).fetchone():
        raise ApiError("That battle doesn't exist.", 404)
    try:
        conn.execute("INSERT INTO battle_votes (battle_id, user_id, choice) VALUES (?,?,?)", (battle_id, user["id"], choice))
        conn.commit()
    except sqlite3.IntegrityError:
        raise ApiError("You already voted on this one.", 409, code="duplicate")
    return jsonify(battle=fetch_battle(conn, battle_id, user["id"]))


# =========================================================================== daily challenge
def challenge_state(conn, viewer):
    ch = database.ensure_today_challenge(conn)
    rows = conn.execute(
        "SELECT s.id, s.answer, s.created_at, u.username FROM challenge_submissions s JOIN users u ON u.id = s.user_id "
        "WHERE s.challenge_id = ? ORDER BY s.created_at DESC, s.id DESC LIMIT 100", (ch["id"],)).fetchall()
    total = conn.execute("SELECT COUNT(*) AS n FROM challenge_submissions WHERE challenge_id = ?", (ch["id"],)).fetchone()["n"]
    mine = conn.execute(
        "SELECT answer FROM challenge_submissions WHERE challenge_id = ? AND user_id = ?", (ch["id"], viewer)).fetchone() if viewer else None
    ends = (datetime.now(timezone.utc) + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return {
        "id": ch["id"], "day": ch["day"], "prompt": ch["prompt"], "max_words": ch["max_words"],
        "ends_at": ends.strftime("%Y-%m-%dT%H:%M:%SZ"), "total": total,
        "my_answer": mine["answer"] if mine else None,
        "responses": [{"id": r["id"], "username": r["username"], "answer": r["answer"], "created_at": iso(r["created_at"])} for r in rows],
    }


@app.get("/api/challenges")
def get_challenge():
    conn = db()
    return jsonify(challenge=challenge_state(conn, viewer_id(conn)))


@app.post("/api/challenges")
def submit_challenge():
    conn = db()
    data = json_body()
    user = get_identity(conn)
    rate_limit("challenge", 5, 60, user["id"])
    ch = database.ensure_today_challenge(conn)
    answer = moderate(clean(data.get("answer"), 2, 200, "Answer"))
    words = len(answer.split())
    if words > ch["max_words"]:
        raise ApiError(f"Too wordy. {ch['max_words']} words max (you used {words}).")
    try:
        conn.execute("INSERT INTO challenge_submissions (challenge_id, user_id, answer) VALUES (?,?,?)", (ch["id"], user["id"], answer))
        conn.commit()
    except sqlite3.IntegrityError:
        raise ApiError("You already answered today's challenge. Come back tomorrow.", 409, code="duplicate")
    return jsonify(challenge=challenge_state(conn, user["id"])), 201


# =========================================================================== leaderboard / profiles
STATS_SQL = """
SELECT u.id, u.username, u.created_at,
  (SELECT COUNT(*) FROM posts p WHERE p.user_id = u.id AND p.removed = 0) AS posts,
  ((SELECT COUNT(*) FROM likes l JOIN posts p ON p.id = l.post_id
      WHERE p.user_id = u.id AND p.removed = 0 AND l.user_id != u.id)
   + (SELECT COALESCE(SUM(p.legacy_likes), 0) FROM posts p WHERE p.user_id = u.id AND p.removed = 0)) AS likes,
  (SELECT COUNT(*) FROM comments c WHERE c.user_id = u.id AND c.removed = 0) AS comments,
  (SELECT COUNT(*) FROM battle_votes bv WHERE bv.user_id = u.id) AS battles,
  (SELECT COUNT(*) FROM challenge_submissions cs WHERE cs.user_id = u.id) AS challenges
FROM users u WHERE u.is_banned = 0
"""


def stats_dict(r):
    score = r["likes"] * 3 + r["posts"] * 5 + r["comments"] * 2 + r["battles"] + r["challenges"] * 3
    return {
        "username": r["username"], "joined": iso(r["created_at"]),
        "posts": r["posts"], "likes": r["likes"], "comments": r["comments"],
        "battles": r["battles"], "challenges": r["challenges"], "roast_score": score,
    }


def ranked_users(conn):
    users = [stats_dict(r) for r in conn.execute(STATS_SQL).fetchall()]
    users = [u for u in users if u["roast_score"] > 0]
    users.sort(key=lambda u: (-u["roast_score"], u["username"].lower()))
    for i, u in enumerate(users, 1):
        u["rank"] = i
    return users


@app.get("/api/leaderboard")
def leaderboard():
    return jsonify(users=ranked_users(db())[: int_arg("limit", 25, 1, 100)])


@app.get("/api/users/<username>")
def user_profile(username):
    conn = db()
    if not USERNAME_RE.match(username):
        raise ApiError("No such user.", 404)
    row = conn.execute(STATS_SQL + " AND u.username = ?", (username,)).fetchone()
    if not row:
        raise ApiError("No such user.", 404)
    profile = stats_dict(row)
    rank = next((u["rank"] for u in ranked_users(conn) if u["username"].lower() == username.lower()), None)
    profile["rank"] = rank
    posts = conn.execute(
        f"SELECT {POST_COLUMNS} FROM posts p JOIN users u ON u.id = p.user_id "
        "WHERE p.removed = 0 AND p.user_id = :uid ORDER BY p.created_at DESC, p.id DESC LIMIT 10",
        {"viewer": viewer_id(conn), "uid": row["id"]}).fetchall()
    return jsonify(user=profile, posts=[post_dict(r) for r in posts])


# =========================================================================== search
def like_pattern(q):
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@app.get("/api/search")
def search():
    conn = db()
    rate_limit("search", 60, 60)
    q = _CTRL.sub("", request.args.get("q", "")).strip()[:60]
    if len(q) < 2:
        return jsonify(q=q, posts=[], users=[])
    pat = like_pattern(q)
    posts = conn.execute(
        f"SELECT {POST_COLUMNS} FROM posts p JOIN users u ON u.id = p.user_id WHERE p.removed = 0 AND "
        "(p.title LIKE :pat ESCAPE '\\' OR p.body LIKE :pat ESCAPE '\\' OR p.tag LIKE :pat ESCAPE '\\' OR u.username LIKE :pat ESCAPE '\\') "
        "ORDER BY p.created_at DESC LIMIT 20", {"viewer": viewer_id(conn), "pat": pat}).fetchall()
    users = conn.execute(STATS_SQL + " AND u.username LIKE ? ESCAPE '\\' ORDER BY u.username COLLATE NOCASE LIMIT 10", (pat,)).fetchall()
    return jsonify(q=q, posts=[post_dict(r) for r in posts], users=[stats_dict(r) for r in users])


# =========================================================================== reports / moderation
@app.post("/api/reports")
def create_report():
    conn = db()
    data = json_body()
    user = get_identity(conn)
    rate_limit("report", 6, 300, user["id"])
    target_type = str(data.get("target_type", "")).lower()
    reason = str(data.get("reason", "")).lower()
    if target_type not in ("post", "comment", "user"):
        raise ApiError("Unknown report target.")
    if reason not in REPORT_REASONS:
        raise ApiError("Pick a report reason.")
    details = clean(data["details"], 0, 300, "Details", multiline=True) if isinstance(data.get("details"), str) and data["details"].strip() else None
    raw_target = data.get("target_id")
    if target_type == "user":
        key = str(raw_target or "")
        row = conn.execute("SELECT id, username FROM users WHERE username = ?", (key,)).fetchone() if USERNAME_RE.match(key) else None
        if not row:
            raise ApiError("That user doesn't exist.", 404)
        if row["id"] == user["id"]:
            raise ApiError("You can't report yourself. (We admire the honesty, though.)")
        key = row["username"]
    else:
        try:
            tid = int(raw_target)
        except (TypeError, ValueError):
            raise ApiError("Missing target.")
        table = "posts" if target_type == "post" else "comments"
        if not conn.execute(f"SELECT 1 FROM {table} WHERE id = ? AND removed = 0", (tid,)).fetchone():
            raise ApiError("That content is already gone.", 404)
        key = str(tid)
    try:
        cur = conn.execute(
            "INSERT INTO reports (reporter_id, target_type, target_key, reason, details) VALUES (?,?,?,?,?)",
            (user["id"], target_type, key, reason, details))
        conn.commit()
    except sqlite3.IntegrityError:
        raise ApiError("You already reported this. We're on it.", 409, code="duplicate")
    return jsonify(ok=True, report_id=cur.lastrowid), 201


def require_admin():
    ok, wait = moderation.limiter.allow(("admin_auth", client_ip()), 15, 60)
    if not ok:
        raise ApiError("Too many attempts.", 429, retry_after=wait)
    supplied = request.headers.get("X-Admin-Secret", "")
    if not ADMIN_SECRET or not hmac.compare_digest(supplied.encode("utf-8"), ADMIN_SECRET.encode("utf-8")):
        raise ApiError("Admin access denied.", 403, code="admin_denied")


def describe_target(conn, target_type, key):
    if target_type == "post":
        r = conn.execute("SELECT p.id, p.title, p.body, p.removed, u.username FROM posts p JOIN users u ON u.id = p.user_id WHERE p.id = ?", (key,)).fetchone()
        if r:
            return {"type": "post", "id": r["id"], "title": r["title"], "body": r["body"], "username": r["username"], "removed": bool(r["removed"])}
    elif target_type == "comment":
        r = conn.execute("SELECT c.id, c.post_id, c.body, c.removed, u.username FROM comments c JOIN users u ON u.id = c.user_id WHERE c.id = ?", (key,)).fetchone()
        if r:
            return {"type": "comment", "id": r["id"], "post_id": r["post_id"], "body": r["body"], "username": r["username"], "removed": bool(r["removed"])}
    else:
        r = conn.execute("SELECT username, is_banned FROM users WHERE username = ?", (key,)).fetchone()
        if r:
            return {"type": "user", "username": r["username"], "banned": bool(r["is_banned"])}
    return {"type": target_type, "missing": True}


@app.get("/api/reports")
def list_reports():
    require_admin()
    conn = db()
    status = request.args.get("status", "open")
    if status not in ("open", "resolved", "dismissed", "all"):
        raise ApiError("Unknown status.")
    where, params = ("", ()) if status == "all" else ("WHERE r.status = ?", (status,))
    rows = conn.execute(
        "SELECT r.*, u.username AS reporter FROM reports r LEFT JOIN users u ON u.id = r.reporter_id "
        f"{where} ORDER BY r.created_at DESC, r.id DESC LIMIT 200", params).fetchall()
    out = [{
        "id": r["id"], "reason": r["reason"], "details": r["details"], "status": r["status"], "reporter": r["reporter"],
        "created_at": iso(r["created_at"]), "resolved_at": iso(r["resolved_at"]),
        "target": describe_target(conn, r["target_type"], r["target_key"]),
    } for r in rows]
    counts = {s: conn.execute("SELECT COUNT(*) AS n FROM reports WHERE status = ?", (s,)).fetchone()["n"] for s in ("open", "resolved", "dismissed")}
    return jsonify(reports=out, counts=counts)


def _target_author(conn, target_type, key):
    if target_type == "user":
        return conn.execute("SELECT id FROM users WHERE username = ?", (key,)).fetchone()
    table = "posts" if target_type == "post" else "comments"
    return conn.execute(f"SELECT user_id AS id FROM {table} WHERE id = ?", (key,)).fetchone()


@app.patch("/api/reports/<int:report_id>")
def update_report(report_id):
    require_admin()
    conn = db()
    action = str(json_body().get("action", "")).lower()
    if action not in ("resolve", "dismiss", "remove", "ban"):
        raise ApiError("Unknown action. Use resolve, dismiss, remove or ban.")
    r = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not r:
        raise ApiError("No such report.", 404)
    t_type, key = r["target_type"], r["target_key"]
    if action == "remove":
        if t_type == "user":
            raise ApiError("Users can't be removed. Use ban instead.")
        table = "posts" if t_type == "post" else "comments"
        conn.execute(f"UPDATE {table} SET removed = 1 WHERE id = ?", (key,))
    elif action == "ban":
        author = _target_author(conn, t_type, key)
        if not author:
            raise ApiError("Can't find that user.", 404)
        conn.execute("UPDATE users SET is_banned = 1 WHERE id = ?", (author["id"],))
    new_status = "dismissed" if action == "dismiss" else "resolved"
    conn.execute("UPDATE reports SET status = ?, resolved_at = datetime('now') WHERE id = ?", (new_status, report_id))
    if action in ("remove", "ban"):  # close sibling reports about the same thing
        conn.execute(
            "UPDATE reports SET status = 'resolved', resolved_at = datetime('now') WHERE target_type = ? AND target_key = ? AND status = 'open'",
            (t_type, key))
    conn.execute(
        "INSERT INTO moderation_actions (report_id, action, target_type, target_key) VALUES (?,?,?,?)", (report_id, action, t_type, key))
    conn.commit()
    return jsonify(ok=True, status=new_status)


# =========================================================================== AI roast
@app.post("/api/ai-roast")
def ai_roast():
    conn = db()
    data = json_body()
    rate_limit("roast", 10, 60, viewer_id(conn) or None)
    text = clean(data.get("text"), 5, 500, "Your story", multiline=True)
    flagged = moderation.roast_safety(text)
    if flagged:
        kind, message = flagged
        return jsonify(blocked=True, kind=kind, message=message)
    return jsonify(blocked=False, **roast_engine.generate_roast(text, str(data.get("intensity", "medium")).lower()))


# =========================================================================== frontend files
@app.get("/")
def index():
    return send_from_directory(ROOT_DIR, "index.html")


@app.get("/admin")
def admin_page():
    return send_from_directory(ROOT_DIR, "admin.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
