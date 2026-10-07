"""AI Roast engine with a pluggable provider architecture.

Default provider: `local` is a free, deterministic, offline roast generator. No API key, no cost.

To plug in a real model later, set in .env:
    ROAST_PROVIDER=openai_compatible
    ROAST_API_URL=https://api.groq.com/openai/v1/chat/completions   (or OpenRouter, Ollama, OpenAI...)
    ROAST_API_KEY=...
    ROAST_MODEL=llama-3.1-8b-instant
Any failure in a remote provider silently falls back to the local engine, so the feature never breaks.
"""
import hashlib
import json
import logging
import os
import re
import urllib.request

log = logging.getLogger("roastroom.roast")

INTENSITIES = ("mild", "medium", "spicy")

VERDICTS = [
    "Certified L 🧾", "Skill issue, but make it iconic", "Emotional damage: critical",
    "Main character (in the blooper reel)", "Respectfully cooked 🍳", "Absolute cinema (of errors)",
]

# (theme, regex, {intensity: [templates]}). {effort} is replaced by a detected quantity.
THEMES = [
    ("exam", r"\b(study|studied|studying|exam|exams|quiz|test|failed|fail|backlog|marks|grades?|cgpa|viva|semester|syllabus)\b", {
        "mild": ["Bro studied for {effort} and the exam still showed up like a plot twist. 📚",
                 "Respect for the effort. The paper, however, has no respect for you."],
        "medium": ["Bro studied for {effort} just to unlock a new achievement:\nacademic damage 💀",
                   "You didn't fail the exam. The exam just had a very different vision for your future."],
        "spicy": ["{effort} of studying and the result was a thriller where nobody survives. Your brain filed a silent protest.",
                  "That syllabus saw you coming three chapters away and chose violence."]}),
    ("dating", r"\b(date|dating|crush|ghost\w*|left on read|on read|seen|situationship|rizz|texted|girlfriend|boyfriend|ex|breakup|rejected)\b", {
        "mild": ["That text didn't get left on read. It got a full pilot episode and no season two. 📱",
                 "Your rizz is loading… and has been since 2021."],
        "medium": ["You didn't get ghosted, you got archived. Gently. With a little 'thanks for your service.' 💀",
                   "Bro really treated 'seen' like a love language."],
        "spicy": ["Your situationship ended before it was legally allowed to be called a situationship.",
                  "Even the typing bubbles left you hanging. That's character development, king."]}),
    ("tech", r"\b(code|coding|bug|bugs|deploy\w*|git|python|react|server|compile\w*|stack overflow|production|merge|commit|api|javascript|html|css|sql)\b", {
        "mild": ["It works on your machine. Production politely disagrees. 💻",
                 "Debugged for {effort} and the culprit was a missing semicolon. Classic."],
        "medium": ["You didn't write a bug. You shipped a limited edition feature nobody asked for. 🐛",
                   "That commit said 'final fix'. The universe laughed, then pushed to main."],
        "spicy": ["Your code isn't spaghetti. Spaghetti has structure.",
                  "Stack Overflow saw your question and closed it as 'please don't.'"]}),
    ("gym", r"\b(gym|workout|protein|lift\w*|diet|abs|cardio|treadmill|gains)\b", {
        "mild": ["Day 1 of the gym arc. The arc has a 4-day season. 💪",
                 "Protein shake in one hand, motivation in the other. Only one is empty."],
        "medium": ["Your workout was 90% mirror selfies and 10% sighing at the leg press. 💀",
                   "Your gym streak has the commitment of a free trial."],
        "spicy": ["The treadmill saw you coming and said 'not today.'",
                  "Your abs aren't hidden. They're on a sabbatical with your discipline."]}),
    ("sleep", r"\b(sleep|alarm|woke|insomnia|snooze|8 ?am|morning class|overslept|nap)\b", {
        "mild": ["Your sleep schedule is just vibes with bad Wi-Fi. 😴",
                 "The alarm was a suggestion. You treated it like a tiny, loud cousin."],
        "medium": ["Bro hit snooze like it owed him money. ⏰",
                   "You and your 8 AM class have a healthy relationship: it shows up, you don't."],
        "spicy": ["Your sleep schedule isn't broken, it just moved to a timezone that doesn't exist.",
                  "The sun and you haven't spoken in months. It's not you, it's literally everyone else."]}),
    ("money", r"\b(broke|money|salary|rent|upi|paid|loan|emi|wallet|balance|payday|₹|rs\.?)\b", {
        "mild": ["Your wallet isn't empty. It's minimalist. 💸",
                 "Payday arrived, stayed for twenty minutes, and left without saying goodbye."],
        "medium": ["Your bank balance and your dreams have one thing in common: both are in single digits.",
                   "Bro checked the balance and the app said 'we should talk.'"],
        "spicy": ["Your UPI history reads like a crime novel where you're the victim and the chai is the culprit.",
                  "You're not broke. You're aggressively pre-wealthy."]}),
    ("job", r"\b(placement|interview|resume|internship|job|jobs|linkedin|recruiter|hr|offer letter|applied)\b", {
        "mild": ["Your resume has potential. Your confidence in it has an internship.",
                 "Another rejection mail? At least this one was polite. 📨"],
        "medium": ["The recruiter opened your resume, whispered 'maybe next year,' and closed it forever. 💀",
                   "Applied to 80 jobs and got 80 exciting new ways to hear 'we'll keep your profile.'"],
        "spicy": ["LinkedIn says 'open to work.' The market says 'open to your hopes, closed to your application.'",
                  "Even the ATS said 'we'll pass,' and it reads everything."]}),
    ("social", r"\b(awkward|embarrass\w*|cringe|party|presentation|speech|stage|laughed|stumbled|tripped|waved|friends?|crowd)\b", {
        "mild": ["That wasn't embarrassing. That was a limited-time live performance. 🎭",
                 "You didn't trip. You tested gravity on behalf of the public."],
        "medium": ["Bro became the main character, but in the blooper reel. 💀",
                   "That moment will replay in your brain at 2 AM for the next five years. Free of charge."],
        "spicy": ["The whole room saw that and unanimously decided to pretend they didn't. Be grateful.",
                  "Your cringe was so strong it made the awkward silence uncomfortable."]}),
    ("food", r"\b(biryani|food|mess|cooked|maggi|ate|eating|hungry|dinner|lunch|canteen|hostel food)\b", {
        "mild": ["Mess food and your plans have one thing in common: both are questionable. 🍛",
                 "That meal had no right to look like that and still call itself dinner."],
        "medium": ["Bro ate hostel food and then wondered why the night felt like a boss fight. 💀",
                   "You trusted the canteen biryani. Bold. Reckless. Educational."],
        "spicy": ["That food didn't just fail the vibe check. It filed a complaint against your stomach.",
                  "Your digestive system just sent a strongly worded email to your decisions."]}),
    ("phone", r"\b(phone|screen time|reels|instagram|scroll\w*|battery|youtube|tiktok|notifications?)\b", {
        "mild": ["Screen time: 9 hours. Productivity: also loading. 📱",
                 "Your battery dies faster than your New Year's resolutions."],
        "medium": ["You opened Instagram 'for 2 minutes' and came back in a different decade. 💀",
                   "Your thumb has done more cardio than your legs this year."],
        "spicy": ["Your attention span called. It went to voicemail. It's been seven reels.",
                  "The algorithm knows you better than your friends. Both are concerned."]}),
]

GENERIC = {
    "mild": ["Honestly? Respect for the honesty. The universe, however, was not taking notes. 🔥",
             "That's a certified L, but you carried it with style."],
    "medium": ["Bro said 'here's my problem' and the internet said 'allow us to make it a hobby.' 💀",
               "This story has main-character energy. The chapter is titled 'Why.'"],
    "spicy": ["You could've kept this to yourself. Instead you made it a public service announcement. Iconic.",
              "Plot twist: the problem was the plan the whole time. We love that for you."],
}

_QUANTITY = re.compile(
    r"(\d+(?:\.\d+)?)\s*(hours?|hrs?|minutes?|mins?|days?|weeks?|months?|years?|times|texts?|messages?|attempts?|tries)", re.I)


def _digest(text, salt=""):
    return int(hashlib.sha256((salt + text).encode("utf-8")).hexdigest(), 16)


def _detect_theme(lowered):
    best, best_hits = None, 0
    for name, pattern, templates in THEMES:
        hits = len(re.findall(pattern, lowered, re.I))
        if hits > best_hits:
            best, best_hits = (name, templates), hits
    return best


class RoastProvider:
    name = "base"

    def roast(self, text, intensity="medium"):
        raise NotImplementedError


class LocalRoastProvider(RoastProvider):
    """Free, deterministic, offline. Same input + intensity gives the same roast."""
    name = "local-roast-v1"

    def roast(self, text, intensity="medium"):
        lowered = text.lower()
        theme = _detect_theme(lowered)
        theme_name, templates = (theme if theme else ("generic", GENERIC))
        pool = templates.get(intensity) or templates["medium"]
        line = pool[_digest(text, intensity) % len(pool)]
        m = _QUANTITY.search(text)
        effort = f"{m.group(1)} {m.group(2).lower()}" if m else "a suspicious amount of time"
        return {"roast": line.replace("{effort}", effort), "theme": theme_name}


class OpenAICompatibleProvider(RoastProvider):
    """Works with any OpenAI-style chat completions endpoint (Groq, OpenRouter, Ollama, OpenAI...)."""
    name = "openai-compatible"

    SYSTEM = (
        "You write short, witty, harmless roasts (max 2 sentences, 1 emoji at most) of a person's own embarrassing story. "
        "Roast the situation and the decision, never identity. Never mention race, religion, caste, gender, sexuality, "
        "disability, or nationality. No threats, no sexual content, no harassment of third parties. "
        "Intensity levels: mild = gentle, medium = playful, spicy = sharper but still kind underneath."
    )

    def roast(self, text, intensity="medium"):
        url, key = os.environ.get("ROAST_API_URL"), os.environ.get("ROAST_API_KEY", "")
        if not url:
            raise RuntimeError("ROAST_API_URL not set")
        payload = {
            "model": os.environ.get("ROAST_MODEL", "llama-3.1-8b-instant"),
            "messages": [
                {"role": "system", "content": self.SYSTEM},
                {"role": "user", "content": f"Intensity: {intensity}\nStory: {text}"},
            ],
            "max_tokens": 120,
            "temperature": 0.9,
        }
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:  # nosec: URL comes from operator config
            data = json.loads(resp.read().decode("utf-8"))
        content = data["choices"][0]["message"]["content"].strip()
        if not content:
            raise RuntimeError("empty completion")
        return {"roast": content[:400], "theme": "ai"}


PROVIDERS = {"local": LocalRoastProvider, "openai_compatible": OpenAICompatibleProvider}


def register_provider(key, cls):
    PROVIDERS[key] = cls


def generate_roast(text, intensity="medium"):
    intensity = intensity if intensity in INTENSITIES else "medium"
    chosen = os.environ.get("ROAST_PROVIDER", "local").strip().lower()
    provider_cls = PROVIDERS.get(chosen, LocalRoastProvider)
    try:
        result = provider_cls().roast(text, intensity)
        provider = provider_cls.name
    except Exception as exc:  # remote model down / misconfigured -> free local fallback
        log.warning("Roast provider %s failed (%s); using local engine.", chosen, exc)
        result = LocalRoastProvider().roast(text, intensity)
        provider = LocalRoastProvider.name
    h = _digest(text, "damage" + intensity)
    return {
        "roast": result["roast"],
        "theme": result["theme"],
        "intensity": intensity,
        "provider": provider,
        "damage": 55 + h % 45,
        "verdict": VERDICTS[h % len(VERDICTS)],
    }
