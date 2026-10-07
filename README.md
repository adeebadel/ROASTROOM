# ROASTROOM

> Post your problem. Let the internet make it worse.

Anonymous entertainment social platform. Vanilla HTML/CSS/JS frontend, Flask + SQLite backend. No build step, no heavy dependencies.

## Features
Home feed (sort, tag filter, load more), create post, anonymous persistent identity (rename allowed), comments, likes, trending, roast battles, daily challenge, leaderboard, profiles, debounced search, AI Roast (free local engine, pluggable provider), reports, admin dashboard, toasts, sharing, responsive layout with bottom nav on mobile.

## Project tree
```
ROASTROOM/
├── index.html
├── admin.html
├── README.md
├── requirements.txt
├── Procfile
├── render.yaml
├── .env.example
├── .gitignore
└── backend/
    ├── app.py
    ├── database.py          (auto-creates tables, safely migrates old data)
    ├── moderation.py
    ├── roast_engine.py
    ├── test_api.py
    └── roastroom.db         (created automatically on first run)
```

## Install and run
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate     Mac/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # Windows: copy .env.example .env
python backend/app.py
```
Open http://127.0.0.1:5000

Your existing `backend/roastroom.db` is kept. Old tables are renamed to `*_legacy` and their rows are copied into the new schema. Nothing is deleted.

## Admin dashboard
Open http://127.0.0.1:5000/admin and enter `ADMIN_SECRET` from `.env`. If unset in development, a temporary secret is printed in the terminal at startup.

## Tests
```bash
python backend/test_api.py
```

## AI Roast
Default is the free offline `local` engine. To plug in a model later, set in `.env`:
```
ROAST_PROVIDER=openai_compatible
ROAST_API_URL=https://api.groq.com/openai/v1/chat/completions
ROAST_API_KEY=...
ROAST_MODEL=llama-3.1-8b-instant
```
If the provider fails, it falls back to the local engine.

## Deploy on Render
1. Push to GitHub.
2. Render: New + > Blueprint > pick the repo (uses `render.yaml`).
3. Copy the generated `ADMIN_SECRET` from the Environment tab.

**SQLite limitation:** Render's free plan has an ephemeral disk, so data resets on redeploy or restart. Options: a paid plan with a disk (uncomment the `disk` block in `render.yaml` and set `DATABASE_PATH=/var/data/roastroom.db`), or move to Postgres. All database access goes through `backend/database.py`, so Postgres means replacing that module and the `?` placeholders.

## GitHub
```bash
git init
git add .
git commit -m "ROASTROOM"
git branch -M main
git remote add origin https://github.com/<you>/roastroom.git
git push -u origin main
```
`.gitignore` already excludes `.env` and `*.db`.

## Security notes
Parameterized SQL everywhere, HTML escaping on every render, input validation and length limits, per-user and per-IP rate limiting, token-hashed identities, CSP and security headers, CORS allowlist, admin secret via environment variable.
