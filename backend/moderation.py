"""Moderation helpers: profanity masking, spam checks, safety screening, rate limiting."""
import re
import threading
import time
from collections import deque

# ------------------------------------------------------------------ profanity (masked, not blocked)
_PROFANITY = [
    "fuck", "shit", "bitch", "asshole", "bastard", "dickhead", "cunt", "piss", "bullshit", "motherfucker",
]
_PROFANITY_RE = re.compile(r"\b(" + "|".join(_PROFANITY) + r")(?:s|es|ed|ing|er|ers|y)?\b", re.I)


def mask_profanity(text):
    return _PROFANITY_RE.sub(lambda m: m.group(0)[0] + "*" * (len(m.group(0)) - 1), text)


def has_profanity(text):
    return bool(_PROFANITY_RE.search(text))


# ------------------------------------------------------------------ hard blocks (rejected)
_BLOCKED = [
    (re.compile(r"\bkill\s+your\s*self\b|\bkys\b|\bgo\s+(?:and\s+)?die\b|\bhang\s+yourself\b", re.I),
     "Telling people to hurt themselves isn't allowed here."),
    (re.compile(r"\bi(?:'ll|\s+will|\s+am\s+going\s+to|'m\s+going\s+to)\s+(?:kill|murder|stab|shoot|rape)\s+(?:you|u|him|her|them)\b", re.I),
     "Threats aren't allowed here."),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"),
     "Don't post email addresses. Keep it anonymous."),
    (re.compile(r"(?<![\d.])(?:\+?\d{1,3}[\s-]?)?\d{10}(?![\d.])"),
     "Don't post phone numbers. Keep it anonymous."),
]

_URL_RE = re.compile(r"(?:https?://|www\.)\S+", re.I)
_REPEAT_RE = re.compile(r"(.)\1{11,}")
_SPAM_PHRASES = re.compile(
    r"free\s+(?:money|followers|robux|v-?bucks)|click\s+(?:here|my\s+link)|dm\s+me\s+for|"
    r"telegram\s+(?:group|channel)|whatsapp\s+(?:me|group)|crypto\s+giveaway|earn\s+\$?\d+\s*(?:a|per)\s+day",
    re.I,
)


def screen(text):
    """Return (clean_text, error). `error` is a user-facing message or None."""
    for pattern, message in _BLOCKED:
        if pattern.search(text):
            return text, message
    if len(_URL_RE.findall(text)) > 2:
        return text, "Too many links. That looks like spam."
    if _REPEAT_RE.search(text) or _SPAM_PHRASES.search(text):
        return text, "That looks like spam. Try writing something real."
    words = text.lower().split()
    if len(words) >= 10 and len(set(words)) / len(words) < 0.3:
        return text, "That looks like spam. Try writing something real."
    return mask_profanity(text), None


# ------------------------------------------------------------------ AI roast safety
_SELF_HARM = re.compile(
    r"\b(?:kill\s+myself|suicid\w*|end\s+my\s+life|want\s+to\s+die|self[-\s]?harm|hurt\s+myself|cut\s+myself)\b", re.I)
_HATE = re.compile(
    r"\ball\s+(?:the\s+)?(?:muslims|christians|jews|hindus|sikhs|buddhists|blacks|whites|asians|gays|lesbians|"
    r"trans\s+people|women|men|immigrants|refugees|disabled\s+people)\s+(?:are|should|must)\b|"
    r"\b(?:roast|mock|make\s+fun\s+of)\b[^.]{0,30}\bmy\s+(?:race|religion|caste|skin\s*colou?r|disability|gender)\b",
    re.I)
_MINORS = re.compile(
    r"\b(?:child|children|kid|kids|minor|underage|teen|teenager|schoolgirl|schoolboy)\b.{0,60}\b(?:sex|sexual|nude|naked|porn|hookup)\b|"
    r"\b(?:sex|sexual|nude|naked|porn|hookup)\b.{0,60}\b(?:child|children|kid|kids|minor|underage|teen|teenager|schoolgirl|schoolboy)\b",
    re.I)
_DANGEROUS = re.compile(
    r"\bhow\s+to\s+(?:make|build|cook|synthesi[sz]e)\b.{0,30}\b(?:bomb|explosive|meth|poison|weapon)\b", re.I)

SUPPORT_MESSAGE = (
    "That sounds heavy, and it's not roast material. If you're thinking about hurting yourself, please talk to "
    "someone you trust or a helpline right now. In India you can call Tele-MANAS at 14416. "
    "Elsewhere, findahelpline.com lists free local lines. You matter more than any joke."
)
REFUSE_MESSAGE = "Roasts go after situations and bad decisions, never identities, threats, or anything harmful. Try a different story."


def roast_safety(text):
    """Return None if fine, else (kind, message). kind is 'support' or 'refuse'."""
    if _SELF_HARM.search(text):
        return "support", SUPPORT_MESSAGE
    if _HATE.search(text) or _MINORS.search(text) or _DANGEROUS.search(text):
        return "refuse", REFUSE_MESSAGE
    for pattern, _ in _BLOCKED[:2]:
        if pattern.search(text):
            return "refuse", REFUSE_MESSAGE
    return None


# ------------------------------------------------------------------ rate limiting
class RateLimiter:
    """Small in-memory sliding-window limiter. Fine for one process; use Redis for many."""

    def __init__(self):
        self._hits = {}
        self._lock = threading.Lock()
        self._last_prune = time.monotonic()

    def allow(self, key, limit, window):
        now = time.monotonic()
        with self._lock:
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False, int(window - (now - q[0])) + 1
            q.append(now)
            if now - self._last_prune > 300:
                self._last_prune = now
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] > 3600]:
                    del self._hits[k]
            return True, 0


limiter = RateLimiter()
