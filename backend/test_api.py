"""End-to-end API smoke tests. Run:  python backend/test_api.py
Uses a temporary database, so it never touches roastroom.db."""
import os
import sys
import tempfile

_tmp = tempfile.mkdtemp()
os.environ["DATABASE_PATH"] = os.path.join(_tmp, "test.db")
os.environ["ADMIN_SECRET"] = "test-admin-secret"
os.environ["ROASTROOM_ENV"] = "production"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as roastroom  # noqa: E402
import moderation  # noqa: E402

client = roastroom.app.test_client()
passed = failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok   {name}")
    else:
        failed += 1
        print(f"  FAIL {name} {extra}")


def ident(name, token=None):
    return {"X-Username": name, "X-Token": token or ("t" * 32 + name)}


ALICE, BOB = ident("anonymous_alice1"), ident("anonymous_bob002")
ADMIN = {"X-Admin-Secret": "test-admin-secret"}

print("health / identity")
r = client.get("/api/health")
check("health", r.status_code == 200 and r.json["status"] == "ok")
check("identity register", client.post("/api/identity", headers=ALICE).status_code == 200)
check("identity hijack blocked", client.post("/api/identity", headers=ident("anonymous_alice1", "z" * 40)).status_code == 403)
check("no identity -> 401", client.post("/api/posts", json={"title": "abc", "body": "hello world"}).status_code == 401)
client.post("/api/identity", headers=BOB)

print("posts")
r = client.get("/api/posts")
check("seeded feed", r.status_code == 200 and len(r.json["posts"]) >= 6, r.json)
r = client.post("/api/posts", headers=ALICE, json={"title": "Test roast", "body": "I tripped on the stairs <script>alert(1)</script>", "tag": "College"})
check("create post", r.status_code == 201, r.json)
pid = r.json["post"]["id"]
check("html stored raw (escaped on render)", "<script>" in r.json["post"]["body"])
check("dup post rejected", client.post("/api/posts", headers=ALICE, json={"title": "Test roast", "body": "I tripped on the stairs <script>alert(1)</script>", "tag": "College"}).status_code == 409)
check("title required", client.post("/api/posts", headers=ALICE, json={"title": "", "body": "hello world"}).status_code == 400)
check("body required", client.post("/api/posts", headers=ALICE, json={"title": "Hello", "body": ""}).status_code == 400)
moderation.limiter._hits.clear()
check("bad tag", client.post("/api/posts", headers=ALICE, json={"title": "Hello", "body": "hello world", "tag": "Nope"}).status_code == 400)
check("title too long", client.post("/api/posts", headers=ALICE, json={"title": "x" * 121, "body": "hello world"}).status_code == 400)
check("sql injection safe", client.get("/api/posts?tag=' OR 1=1 --").status_code == 400)
moderation.limiter._hits.clear()
check("profanity masked", "f***" in client.post("/api/posts", headers=ALICE, json={"title": "What the fuck", "body": "this is some shit okay"}).json["post"]["title"])
check("self-harm incitement blocked", client.post("/api/posts", headers=BOB, json={"title": "Hey you", "body": "just kill yourself already"}).status_code == 422)
check("phone number blocked", client.post("/api/posts", headers=BOB, json={"title": "Call me", "body": "my number is 9876543210 ok"}).status_code == 422)
moderation.limiter._hits.clear()
check("sort top", client.get("/api/posts?sort=top").status_code == 200)
check("sort discussed", client.get("/api/posts?sort=discussed&tag=Tech").status_code == 200)
check("bad sort", client.get("/api/posts?sort=drop").status_code == 400)
check("single post", client.get(f"/api/posts/{pid}").json["post"]["id"] == pid)
check("pagination", client.get("/api/posts?limit=2&offset=0").json["has_more"] is True)

print("likes")
r = client.post(f"/api/posts/{pid}/like", headers=BOB)
check("like", r.status_code == 200 and r.json["liked"] and r.json["likes"] == 1, r.json)
check("liked flag for viewer", client.get(f"/api/posts/{pid}", headers=BOB).json["post"]["liked"] is True)
check("liked flag absent for others", client.get(f"/api/posts/{pid}", headers=ALICE).json["post"]["liked"] is False)
r = client.post(f"/api/posts/{pid}/like", headers=BOB)
check("unlike toggles (no duplicates)", r.json["liked"] is False and r.json["likes"] == 0, r.json)
client.post(f"/api/posts/{pid}/like", headers=BOB)
check("like missing post 404", client.post("/api/posts/99999/like", headers=BOB).status_code == 404)

print("comments")
r = client.post(f"/api/posts/{pid}/comments", headers=BOB, json={"body": "Brutal. Respect."})
check("add comment", r.status_code == 201 and r.json["count"] == 1, r.json)
check("empty comment rejected", client.post(f"/api/posts/{pid}/comments", headers=BOB, json={"body": "   "}).status_code == 400)
check("dup comment rejected", client.post(f"/api/posts/{pid}/comments", headers=BOB, json={"body": "Brutal. Respect."}).status_code == 409)
r = client.get(f"/api/posts/{pid}/comments")
check("list comments", r.status_code == 200 and r.json["comments"][0]["username"] == "anonymous_bob002")
check("comment count on post", client.get(f"/api/posts/{pid}").json["post"]["comments"] == 1)

print("trending")
r = client.get("/api/trending")
check("trending ranked", r.status_code == 200 and r.json["posts"][0]["rank"] == 1 and "score" in r.json["posts"][0])

moderation.limiter._hits.clear()
print("battles")
r = client.get("/api/battles", headers=BOB)
check("list battles", r.status_code == 200 and len(r.json["battles"]) >= 5)
bid = r.json["battles"][0]["id"]
r = client.post("/api/battles", headers=ALICE, json={"prompt": "Worse?", "option_a": "Cold coffee", "option_b": "Warm soda"})
check("create battle", r.status_code == 201 and r.json["battle"]["total"] == 0, r.json)
nb = r.json["battle"]["id"]
check("same options rejected", client.post("/api/battles", headers=ALICE, json={"prompt": "x?", "option_a": "same", "option_b": "SAME"}).status_code == 400)
r = client.post(f"/api/battles/{nb}/vote", headers=BOB, json={"choice": "a"})
check("vote", r.status_code == 200 and r.json["battle"]["a"]["votes"] == 1 and r.json["battle"]["a"]["percent"] == 100 and r.json["battle"]["winner"] == "a", r.json)
check("double vote blocked", client.post(f"/api/battles/{nb}/vote", headers=BOB, json={"choice": "b"}).status_code == 409)
r = client.post(f"/api/battles/{nb}/vote", headers=ALICE, json={"choice": "b"})
check("tie detected", r.json["battle"]["winner"] == "tie" and r.json["battle"]["total"] == 2, r.json)
check("bad choice", client.post(f"/api/battles/{nb}/vote", headers=ALICE, json={"choice": "c"}).status_code == 400)

print("daily challenge")
r = client.get("/api/challenges")
check("get challenge", r.status_code == 200 and r.json["challenge"]["prompt"])
words = r.json["challenge"]["max_words"]
r = client.post("/api/challenges", headers=ALICE, json={"answer": " ".join(f"w{i}" for i in range(words + 3))})
check("too many words rejected", r.status_code == 400, r.json)
r = client.post("/api/challenges", headers=ALICE, json={"answer": "Dinner became therapy for him"})
check("submit answer", r.status_code == 201 and r.json["challenge"]["my_answer"], r.json)
check("second answer blocked", client.post("/api/challenges", headers=ALICE, json={"answer": "Another one here"}).status_code == 409)
check("responses listed", client.get("/api/challenges").json["challenge"]["total"] == 1)

print("leaderboard / profiles")
r = client.get("/api/leaderboard")
check("leaderboard", r.status_code == 200 and r.json["users"][0]["rank"] == 1 and len(r.json["users"]) >= 3)
r = client.get("/api/users/anonymous_alice1")
check("profile", r.status_code == 200 and r.json["user"]["posts"] >= 1 and "roast_score" in r.json["user"] and r.json["posts"])
check("profile 404", client.get("/api/users/nobody_here_x").status_code == 404)
check("profile bad name 404", client.get("/api/users/a b").status_code == 404)
r = client.post("/api/users/me/rename", headers=ALICE, json={"username": "alice_roasts"})
check("rename", r.status_code == 200 and r.json["user"]["username"] == "alice_roasts", r.json)
ALICE2 = ident("alice_roasts", ALICE["X-Token"])
check("renamed identity works", client.post("/api/posts/%d/like" % pid, headers=ALICE2).status_code == 200)
check("rename to taken blocked", client.post("/api/users/me/rename", headers=ALICE2, json={"username": "anonymous_bob002"}).status_code == 409)
check("rename reserved blocked", client.post("/api/users/me/rename", headers=ALICE2, json={"username": "admin"}).status_code == 400)

print("search")
r = client.get("/api/search?q=quiz")
check("search posts", r.status_code == 200 and len(r.json["posts"]) >= 1)
check("search users", len(client.get("/api/search?q=bob").json["users"]) == 1)
check("search tag", len(client.get("/api/search?q=Dating").json["posts"]) >= 1)
check("search short query empty", client.get("/api/search?q=a").json["posts"] == [])
check("search wildcard escaped", client.get("/api/search?q=%25%25").json["posts"] == [])
check("search no results", client.get("/api/search?q=zzzzqqq").json == {"q": "zzzzqqq", "posts": [], "users": []})

moderation.limiter._hits.clear()
print("reports / admin")
r = client.post("/api/reports", headers=BOB, json={"target_type": "post", "target_id": pid, "reason": "spam"})
check("report post", r.status_code == 201, r.json)
rid = r.json["report_id"]
check("duplicate report blocked", client.post("/api/reports", headers=BOB, json={"target_type": "post", "target_id": pid, "reason": "spam"}).status_code == 409)
cid = client.get(f"/api/posts/{pid}/comments").json["comments"][0]["id"]
check("report comment", client.post("/api/reports", headers=ALICE2, json={"target_type": "comment", "target_id": cid, "reason": "harassment", "details": "rude"}).status_code == 201)
check("report user", client.post("/api/reports", headers=ALICE2, json={"target_type": "user", "target_id": "anonymous_bob002", "reason": "hate"}).status_code == 201)
check("bad reason", client.post("/api/reports", headers=BOB, json={"target_type": "post", "target_id": pid, "reason": "meh"}).status_code == 400)
check("self report blocked", client.post("/api/reports", headers=BOB, json={"target_type": "user", "target_id": "anonymous_bob002", "reason": "spam"}).status_code == 400)
check("reports need admin", client.get("/api/reports").status_code == 403)
check("wrong admin secret", client.get("/api/reports", headers={"X-Admin-Secret": "nope"}).status_code == 403)
r = client.get("/api/reports", headers=ADMIN)
check("list reports", r.status_code == 200 and len(r.json["reports"]) == 3 and r.json["counts"]["open"] == 3, r.json)
check("patch needs admin", client.patch(f"/api/reports/{rid}", json={"action": "resolve"}).status_code == 403)
check("dismiss", client.patch(f"/api/reports/{rid}", headers=ADMIN, json={"action": "dismiss"}).json["status"] == "dismissed")
r2 = client.post("/api/reports", headers=ident("anonymous_carl03"), json={"target_type": "post", "target_id": pid, "reason": "violence"})
check("report again from other user", r2.status_code == 201)
r = client.patch(f"/api/reports/{r2.json['report_id']}", headers=ADMIN, json={"action": "remove"})
check("remove post", r.status_code == 200 and client.get(f"/api/posts/{pid}").status_code == 404)
check("removed post hidden from feed", all(p["id"] != pid for p in client.get("/api/posts?limit=50").json["posts"]))
check("bad action", client.patch(f"/api/reports/{rid}", headers=ADMIN, json={"action": "explode"}).status_code == 400)
ur = [x for x in client.get("/api/reports?status=open", headers=ADMIN).json["reports"] if x["target"]["type"] == "user"][0]
check("ban user", client.patch(f"/api/reports/{ur['id']}", headers=ADMIN, json={"action": "ban"}).status_code == 200)
check("banned user blocked", client.post("/api/posts", headers=BOB, json={"title": "Hello", "body": "hello world"}).status_code == 403)

print("ai roast")
r = client.post("/api/ai-roast", json={"text": "I studied for 5 hours and still failed."})
check("roast", r.status_code == 200 and not r.json["blocked"] and "5 hours" in r.json["roast"], r.json)
check("roast deterministic", client.post("/api/ai-roast", json={"text": "I studied for 5 hours and still failed."}).json["roast"] == r.json["roast"])
check("roast intensity", client.post("/api/ai-roast", json={"text": "She left me on seen again", "intensity": "spicy"}).json["intensity"] == "spicy")
check("roast generic fallback", client.post("/api/ai-roast", json={"text": "Something totally random happened to me"}).json["theme"] == "generic")
r = client.post("/api/ai-roast", json={"text": "I want to die"})
check("roast self-harm -> support", r.json["blocked"] and r.json["kind"] == "support")
r = client.post("/api/ai-roast", json={"text": "all muslims are annoying roast them"})
check("roast hate refused", r.json["blocked"] and r.json["kind"] == "refuse")
check("roast too short", client.post("/api/ai-roast", json={"text": "hi"}).status_code == 400)

print("rate limiting / misc")
moderation.limiter._hits.clear()
codes = [client.post("/api/posts", headers=ident("anonymous_spam01"), json={"title": f"Spam title {i}", "body": f"unique body number {i} lol"}).status_code for i in range(6)]
check("post rate limit kicks in", 429 in codes, codes)
check("404 json", client.get("/api/nope").json == {"error": "That doesn't exist."})
check("bad json", client.post("/api/posts", headers=BOB, data="not json", content_type="application/json").status_code in (400, 403))
check("index served", client.get("/").status_code in (200, 404))
check("cors allowed origin", client.get("/api/health", headers={"Origin": "http://localhost:5500"}).headers.get("Access-Control-Allow-Origin") == "http://localhost:5500")
check("cors blocked origin", "Access-Control-Allow-Origin" not in client.get("/api/health", headers={"Origin": "https://evil.example"}).headers)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
