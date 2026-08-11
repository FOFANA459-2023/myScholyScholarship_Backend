"""Site assistant backed by the Google Gemini API.

The API key lives only in the server-side environment (``GEMINI_API_KEY`` in
``.env``); the frontend talks to our own ``/api/assistant/chat/`` endpoint and
never sees the key. Calls use the plain REST surface via urllib so no new
dependency is needed.

Every request is grounded with the site's current live scholarships that match
the visitor's question, so answers cite real listings instead of inventing
them. No user-identifying data is ever sent to the provider - only the
visitor's question text and public scholarship rows.
"""

import base64
import hashlib
import html
import ipaddress
import json
import logging
import re
import socket
import urllib.error
import urllib.parse
import urllib.request

from django.conf import settings
from django.core.cache import cache as django_cache
from django.utils import timezone

from .cache import NS_SCHOLARSHIPS, get_version
from .models import Scholarship

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Provider-call cache
# ---------------------------------------------------------------------------
# Identical inputs never reach Gemini twice: replies are stored (Redis in
# production) and served back for repeat requests. Keys include the
# scholarship cache version wherever the reply is grounded on board data, so
# any admin write invalidates them instantly, plus today's date wherever the
# prompt embeds it. Only successful replies are stored - failures always
# retry. This protects the free-tier quota without ever serving stale advice.

AI_CACHE_TTL = 24 * 3600


def _ai_cached(kind, parts, producer, ttl=AI_CACHE_TTL):
    raw = json.dumps([kind, parts], sort_keys=True, default=str)
    key = f"myscholy:ai:{kind}:{hashlib.sha256(raw.encode()).hexdigest()}"
    hit = django_cache.get(key)
    if hit is not None:
        return hit["value"]
    value = producer()
    # Envelope so a legitimately-None result is still a cache hit.
    django_cache.set(key, {"value": value}, ttl)
    return value

GEMINI_ENDPOINT = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)

# How many scholarships to hand the model as context. Covers the whole board
# at its current size, so the assistant genuinely knows every live listing.
MAX_CONTEXT_SCHOLARSHIPS = 25
MAX_HISTORY_TURNS = 10

# Bump whenever SYSTEM_PROMPT or the context format changes: it is part of the
# reply-cache key, so cached answers written under the old prompt are dropped.
PROMPT_VERSION = 2

SYSTEM_PROMPT = """\
You are the myScholy assistant, a friendly helper embedded on every page of
myscholy.pages.dev - a free scholarship board that lists fully funded
scholarships, fellowships, summits and programs worldwide. You know the whole
site; guide visitors to the exact page that helps them.

THE SITE, PAGE BY PAGE:
- Home (/): hero, university carousel, roadmap of how myScholy helps, and the
  FAQ section (/#faq). The hero has a "Join our community" button that opens
  the myScholy WhatsApp community.
- Scholarship board (/scholarships): every live listing as cards. Visitors can
  search by name, country or degree level, filter by region (Africa, Europe,
  Asia, United States, Canada, Australia) and by degree level (Undergraduate,
  Graduate, Postgraduate, Non-degree), and sort by newest, deadline or name.
  Filters live in the URL, so a filtered view can be shared as a link.
- Scholarship detail (/scholarships/<slug>): the full description, who can
  apply (eligibility), what's covered (benefits), the deadline with a
  countdown, an "Apply on the official page" button, and a strip of similar
  scholarships that are still open.
- Eligibility assessment (/assessment): a short quiz; the site then suggests
  live scholarships that fit the visitor's profile.
- Consulting (/consulting) and myScholy Academy (/academy): the site's
  services pages.
- Contact (/contact): a form (name, email, subject, message) that reaches the
  myScholy team directly; the team replies by email from the myScholy address
  using the visitor's own subject line. The page also shows the team email
  (myscholy@gmail.com) and a WhatsApp link.
- WhatsApp community (/whatsapp): free real-time scholarship alerts and
  application tips; signing in unlocks the invite link.
- Accounts: sign up (/signup) and log in (/login) are free. Signed-in students
  receive a recurring email digest of live scholarships they can still apply
  for. Password reset lives at /forgot-password - it emails a single-use link
  that expires after one hour.
- Everything on myScholy is free: free to browse, free to apply, no fees ever.

RULES:
- Answer questions about myScholy, the scholarships listed below, studying
  abroad, and scholarship applications in general. For unrelated topics, say
  you can only help with myScholy and scholarships.
- When recommending scholarships, use ONLY the listings provided below - never
  invent scholarships, deadlines or links. If nothing below fits, say so and
  point the visitor to /scholarships to browse or /contact to ask the team.
- Link every scholarship you mention to its page on the site using its
  "Details" path (e.g. [Chevening Scholarship](/scholarships/chevening)), so
  the visitor reads it on myScholy first. Only give the official "Apply" URL
  when the visitor asks how or where to apply.
- FORMAT for readability: short paragraphs (1-3 sentences), markdown bullet
  lists when comparing or listing options, **bold** for scholarship names and
  deadlines, and markdown links written as [text](url). Never use headings,
  tables or code blocks - this renders in a small chat window.
- Never ask for passwords or personal details.

Today's date is {today}.

LIVE SCHOLARSHIPS ON THE BOARD RIGHT NOW ({count} open listings):
{context}
"""


class AssistantError(Exception):
    """Provider failure the view can translate into a friendly response."""

    def __init__(self, message, *, retryable=False):
        super().__init__(message)
        self.retryable = retryable


def _summ(text, limit=180):
    flat = " ".join(str(text or "").split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def _context_scholarships(message):
    """Every live listing, with the ones matching the question listed first.

    The board is small enough to hand the model in full, so the assistant is
    aware of every open scholarship - the keyword match only orders them so
    the most relevant rows sit at the top of the context. Returns
    ``(count, text)``.
    """
    live = list(
        Scholarship.objects.active().open_for_application().order_by("deadline")
    )

    words = [w.strip(".,!?()\"'").lower() for w in message.split()]
    words = [w for w in words if len(w) >= 4]

    def relevance(row):
        haystack = f"{row.name} {row.host_country} {row.degree_level}".lower()
        return -sum(1 for word in words if word in haystack)

    rows = sorted(live, key=relevance)[:MAX_CONTEXT_SCHOLARSHIPS]
    if not rows:
        return 0, "  (no live scholarships at the moment)"

    text = "\n".join(
        f"- {row.name} | Country: {row.host_country} | Degree: {row.degree_level}"
        f" | Deadline: {row.deadline:%d %b %Y}"
        f" | Details: /scholarships/{row.slug}"
        f" | Apply: {row.link}"
        f" | About: {_summ(row.description)}"
        for row in rows
    )
    return len(rows), text


# ---------------------------------------------------------------------------
# Providers: Gemini primary, Groq fallback, automatic back-and-forth
# ---------------------------------------------------------------------------
# When one provider answers 429 (its per-minute limit), it is put on a
# 60-second cooldown and requests flow to the other; when the cooldown lapses
# traffic flows back. Both keys live only in the server-side .env.

GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
PROVIDER_COOLDOWN_SECONDS = 60

BUSY_MESSAGE = (
    "Too many users are performing this action at the same time. "
    "Please try again in a minute."
)
UNREACHABLE_MESSAGE = (
    "The assistant could not be reached. Please try again shortly."
)


class ProviderError(Exception):
    """One provider failed; the router decides what happens next."""

    def __init__(self, message, *, rate_limited=False, unsupported=False):
        super().__init__(message)
        self.rate_limited = rate_limited
        self.unsupported = unsupported


def _post_json(url, headers, payload, provider):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            # Groq sits behind Cloudflare, which rejects the default Python
            # urllib signature (error 1010); a normal client string passes.
            "User-Agent": "myScholy-backend/1.0",
            **headers,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:500]
        logger.warning("%s API error %s: %s", provider, exc.code, body)
        raise ProviderError(
            f"{provider} error {exc.code}", rate_limited=exc.code == 429
        ) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        logger.warning("%s API unreachable: %s", provider, exc)
        raise ProviderError(f"{provider} unreachable") from exc


def _gemini_call(system, messages, temperature, max_tokens, json_schema):
    contents = []
    for message in messages:
        parts = []
        if message.get("pdf") is not None:
            parts.append(
                {
                    "inline_data": {
                        "mime_type": "application/pdf",
                        "data": base64.b64encode(message["pdf"]).decode(),
                    }
                }
            )
        if message.get("text"):
            parts.append({"text": message["text"]})
        contents.append({"role": message["role"], "parts": parts})

    generation = {"temperature": temperature, "maxOutputTokens": max_tokens}
    if json_schema is not None:
        generation["responseMimeType"] = "application/json"
        generation["responseSchema"] = json_schema

    payload = {"contents": contents, "generationConfig": generation}
    if system:
        payload["system_instruction"] = {"parts": [{"text": system}]}

    data = _post_json(
        GEMINI_ENDPOINT.format(model=settings.GEMINI_MODEL),
        {"x-goog-api-key": settings.GEMINI_API_KEY},
        payload,
        "Gemini",
    )
    try:
        parts = data["candidates"][0]["content"]["parts"]
        return "".join(part.get("text", "") for part in parts).strip()
    except (KeyError, IndexError):
        return ""


def _groq_call(system, messages, temperature, max_tokens, json_schema):
    if any(message.get("pdf") is not None for message in messages):
        # Groq's chat API has no PDF input; only Gemini can serve those.
        raise ProviderError("Groq cannot read PDFs", unsupported=True)

    system_text = system or ""
    if json_schema is not None:
        # Groq's json_object mode needs the schema described in the prompt.
        system_text += (
            "\n\nRespond only with a valid JSON object matching this schema: "
            + json.dumps(json_schema)
        )

    chat = []
    if system_text.strip():
        chat.append({"role": "system", "content": system_text})
    for message in messages:
        chat.append(
            {
                "role": "assistant" if message["role"] == "model" else "user",
                "content": message.get("text", ""),
            }
        )

    payload = {
        "model": settings.GROQ_MODEL,
        "messages": chat,
        "temperature": temperature,
        "max_completion_tokens": max_tokens,
    }
    if json_schema is not None:
        payload["response_format"] = {"type": "json_object"}

    data = _post_json(
        GROQ_ENDPOINT,
        {"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
        payload,
        "Groq",
    )
    try:
        return (data["choices"][0]["message"]["content"] or "").strip()
    except (KeyError, IndexError):
        return ""


# Function names, resolved at call time so tests can patch the callables.
_PROVIDERS = (
    ("gemini", "GEMINI_API_KEY", "_gemini_call"),
    ("groq", "GROQ_API_KEY", "_groq_call"),
)


def _cooldown_key(name):
    return f"myscholy:ai:cooldown:{name}"


def _generate(system, messages, *, temperature, max_tokens, json_schema=None):
    """Route one generation through the first available provider.

    Gemini first; a rate-limited provider sits out for 60 seconds while the
    other takes the traffic, then rejoins automatically. When every configured
    provider is rate-limited at once the caller gets the busy message.
    """
    any_rate_limited = False
    for name, key_setting, func_name in _PROVIDERS:
        if not getattr(settings, key_setting, ""):
            continue
        if django_cache.get(_cooldown_key(name)):
            any_rate_limited = True
            continue
        call = globals()[func_name]
        try:
            return call(system, messages, temperature, max_tokens, json_schema)
        except ProviderError as exc:
            if exc.rate_limited:
                django_cache.set(
                    _cooldown_key(name), True, PROVIDER_COOLDOWN_SECONDS
                )
                any_rate_limited = True
            # unsupported or transient: fall through to the next provider.
            continue

    raise AssistantError(
        BUSY_MESSAGE if any_rate_limited else UNREACHABLE_MESSAGE,
        retryable=any_rate_limited,
    )


def ask(message, history):
    """One assistant turn. ``history`` is [{'role': 'user'|'model', 'text': str}].

    Cached: the same question with the same conversation history reuses the
    stored reply until the board changes or the day rolls over.
    """
    return _ai_cached(
        "chat",
        [
            PROMPT_VERSION,
            get_version(NS_SCHOLARSHIPS),
            str(timezone.now().date()),
            message.strip().lower(),
            history,
        ],
        lambda: _ask(message, history),
    )


def _ask(message, history):
    count, context = _context_scholarships(message)
    system = SYSTEM_PROMPT.format(
        today=f"{timezone.now().date():%d %B %Y}",
        count=count,
        context=context,
    )

    messages = [
        {"role": turn["role"], "text": turn["text"]}
        for turn in history[-MAX_HISTORY_TURNS:]
    ]
    messages.append({"role": "user", "text": message})

    reply = _generate(system, messages, temperature=0.4, max_tokens=800)

    if not reply:
        # Safety block or empty candidate - treat as a soft failure.
        raise AssistantError(
            "The assistant could not answer that one. Try rephrasing, or ask "
            "the team via the contact page."
        )
    return reply


# ---------------------------------------------------------------------------
# Admin: extract scholarship fields from pasted text
# ---------------------------------------------------------------------------

EXTRACT_FIELDS = (
    "name",
    "description",
    "deadline",
    "host_country",
    "degree_level",
    "benefits",
    "eligibility",
    "link",
)

EXTRACT_PROMPT = """\
You extract structured scholarship data for the myScholy admin posting form.
The user pastes a scholarship announcement (copied from a website, email or
PDF). Fill each field from the text ONLY - never invent or guess information
that is not there. If a field is not present in the text, return an empty
string for it.

Field rules:
- name: the scholarship's official name/title.
- description: a thorough description drawn from the announcement's own
  information - at least 4-5 full sentences whenever the source provides
  enough material. Cover what the scholarship is, who offers it, who it is
  for, where the study takes place and what makes it notable. Do not shorten
  a rich announcement into a summary; preserve its substance.
- deadline: the application deadline as YYYY-MM-DD. Empty if no full date is
  given. Today is {today} - use it only to resolve which year a stated
  deadline like "15 March" falls in (never as the deadline itself).
- host_country: the country where the study takes place, in English
  (e.g. "United Kingdom", "China").
- degree_level: the level of study, normalised to wording like "Bachelors",
  "Masters", "PhD", "Masters, PhD" when several apply.
- benefits: what the scholarship covers, ONE benefit per line, no bullet
  characters.
- eligibility: the requirements, ONE requirement per line, no bullet
  characters.
- link: the official application or information URL if one appears in the
  text, otherwise empty.
"""

EXTRACT_SCHEMA = {
    "type": "OBJECT",
    "properties": {field: {"type": "STRING"} for field in EXTRACT_FIELDS},
    "required": list(EXTRACT_FIELDS),
}


MAX_FETCH_BYTES = 8 * 1024 * 1024  # 8 MB cap for fetched pages/PDFs


def _assert_public_host(url):
    """Refuse URLs that resolve to private/internal addresses (SSRF guard)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise AssistantError("Enter a full http(s) link to the scholarship page.")
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as exc:
        raise AssistantError("That address could not be found.") from exc
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if not address.is_global:
            raise AssistantError("That address cannot be fetched.")


# Some WAFs reject anything without a browser User-Agent; others do the
# opposite and reject a browser User-Agent whose TLS fingerprint does not
# match a real browser (DAAD's, for one). No single header set satisfies
# both camps, hence the honest-first-then-browser retry in fetch_url.
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "application/pdf,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

FETCH_ERROR = "That page could not be fetched. Copy the text and paste it instead."


def _fetch(url, headers):
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=15) as response:
        content_type = (response.headers.get("Content-Type") or "").lower()
        body = response.read(MAX_FETCH_BYTES)
    return content_type, body


def fetch_url(url):
    """Download a scholarship page. Returns ('pdf', bytes) or ('text', str)."""
    _assert_public_host(url)

    try:
        content_type, body = _fetch(
            url, {"User-Agent": "Mozilla/5.0 (myScholy admin helper)"}
        )
    except urllib.error.HTTPError as exc:
        if exc.code not in (401, 403, 406, 503):
            raise AssistantError(FETCH_ERROR) from exc
        try:
            content_type, body = _fetch(url, BROWSER_HEADERS)
        except (urllib.error.URLError, TimeoutError, ValueError) as retry_exc:
            raise AssistantError(FETCH_ERROR) from retry_exc
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise AssistantError(FETCH_ERROR) from exc

    if "pdf" in content_type or body[:5] == b"%PDF-":
        return "pdf", body
    return "text", _html_to_text(body.decode("utf-8", errors="replace"))


def _html_to_text(markup):
    """Crude but dependency-free HTML -> text for the extraction prompt."""
    markup = re.sub(
        r"<(script|style|noscript)\b.*?</\1>", " ", markup, flags=re.S | re.I
    )
    markup = re.sub(r"<br\s*/?>|</p>|</div>|</li>|</h[1-6]>", "\n", markup, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", markup)
    text = html.unescape(text)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()


def extract_scholarship(text=None, pdf_bytes=None):
    """Extract posting-form fields from pasted text or an uploaded PDF.

    Returns a dict with every EXTRACT_FIELDS key, values '' when the source
    does not contain that piece of information. PDFs go to the model as-is
    (Gemini reads them natively, scanned pages included).

    Cached by content hash: re-submitting the same announcement or document
    reuses the stored extraction.
    """
    digest = hashlib.sha256(
        pdf_bytes if pdf_bytes is not None else (text or "").encode()
    ).hexdigest()
    return _ai_cached(
        "extract",
        [str(timezone.now().date()), "pdf" if pdf_bytes is not None else "text", digest],
        lambda: _extract_scholarship(text=text, pdf_bytes=pdf_bytes),
    )


def _extract_scholarship(text=None, pdf_bytes=None):
    if pdf_bytes is not None:
        messages = [
            {
                "role": "user",
                "pdf": pdf_bytes,
                "text": "Extract the scholarship details from this document.",
            }
        ]
    else:
        messages = [{"role": "user", "text": text}]

    reply = _generate(
        EXTRACT_PROMPT.format(today=f"{timezone.now().date():%Y-%m-%d}"),
        messages,
        temperature=0,
        max_tokens=2000,
        json_schema=EXTRACT_SCHEMA,
    )

    try:
        data = json.loads(reply)
    except (TypeError, json.JSONDecodeError) as exc:
        logger.warning("Extraction returned non-JSON output")
        raise AssistantError(
            "The text could not be analysed. Try pasting a cleaner copy of "
            "the announcement."
        ) from exc

    return {
        field: str(data.get(field) or "").strip() for field in EXTRACT_FIELDS
    }


# ---------------------------------------------------------------------------
# Public: personalized assessment result
# ---------------------------------------------------------------------------

ASSESSMENT_KEYS = ("age", "level", "stage", "essay", "cv", "region")

ASSESSMENT_LEVEL_KEYWORDS = {
    "undergraduate": ("bachelor", "undergrad"),
    "graduate": ("master", "graduate"),
    "postgraduate": ("phd", "doctor", "postdoc", "fellow", "master"),
}

ASSESSMENT_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "headline": {"type": "STRING"},
        "summary": {"type": "STRING"},
        "next_steps": {"type": "ARRAY", "items": {"type": "STRING"}},
        "scholarship_ids": {"type": "ARRAY", "items": {"type": "INTEGER"}},
    },
    "required": ["headline", "summary", "next_steps", "scholarship_ids"],
}

ASSESSMENT_PROMPT = """\
You are myScholy's friendly assessment coach. A visitor answered the site's
fit-assessment quiz; write them a personalized result.

Their answers (level = the study level they are applying for; region = WHERE
THEY WANT TO STUDY, not where they live; stage = how far along they are;
essay/cv = the state of their application materials):
{answers}

Today's date: {today}.

Live scholarships currently on the myScholy board (id | name | country |
degree level | deadline):
{rows}

Produce:
- headline: a short, encouraging title tailored to their situation.
- summary: 3-5 sentences speaking directly to them ("you"), reflecting their
  study level, how far along they are, and their essay/CV answers. Mention
  that myScholy Consulting (coming soon) can support the steps they are
  weakest on. Plain text, no markdown.
- next_steps: 3-5 concrete, personalized actions in priority order, phrased
  as imperatives. If deadlines are close for them, order accordingly.
- scholarship_ids: ids of listings from the table above that fit their study
  level, best first. When many fit, pick only the best 3 to 5 - the summary
  should point them at the scholarships page for the rest. Prefer listings in
  their preferred region, but when that region has none, include the best
  fits from other regions - students routinely consider them. Be generous:
  include a listing unless its degree level clearly does not match. Only ids
  from the table - never invent. Empty list only when truly nothing fits.
"""


def personalized_assessment(answers):
    """Personalized quiz result grounded with matching live scholarships.

    ``answers`` is a dict of quiz answers (ASSESSMENT_KEYS). Returns
    {'headline', 'summary', 'next_steps', 'scholarships'} where scholarships
    are real rows resolved from the model's picks.

    Cached: the answer space is small, so identical answer sets reuse the
    stored plan until the board changes or the day rolls over.
    """
    return _ai_cached(
        "assessment",
        [
            get_version(NS_SCHOLARSHIPS),
            str(timezone.now().date()),
            sorted(answers.items()),
        ],
        lambda: _personalized_assessment(answers),
    )


def _personalized_assessment(answers):
    keywords = ASSESSMENT_LEVEL_KEYWORDS.get(answers.get("level"), ())
    live = Scholarship.objects.active().open_for_application().order_by("deadline")
    if keywords:
        from django.db.models import Q

        query = Q()
        for keyword in keywords:
            query |= Q(degree_level__icontains=keyword)
        matched = list(live.filter(query)[:20])
        # A sparse board should still produce recommendations to consider.
        if len(matched) < 5:
            seen = {row.pk for row in matched}
            matched += [row for row in live[:20] if row.pk not in seen][: 20 - len(matched)]
    else:
        matched = list(live[:20])

    rows = "\n".join(
        f"{row.pk} | {row.name} | {row.host_country} | {row.degree_level}"
        f" | {row.deadline}"
        for row in matched
    ) or "(the board has no live scholarships right now)"

    answer_lines = "\n".join(
        f"- {key}: {answers.get(key) or '-'}" for key in ASSESSMENT_KEYS
    )

    reply = _generate(
        None,
        [
            {
                "role": "user",
                "text": ASSESSMENT_PROMPT.format(
                    answers=answer_lines,
                    today=f"{timezone.now().date():%d %B %Y}",
                    rows=rows,
                ),
            }
        ],
        temperature=0.5,
        max_tokens=1200,
        json_schema=ASSESSMENT_SCHEMA,
    )

    try:
        data = json.loads(reply)
    except (TypeError, json.JSONDecodeError) as exc:
        raise AssistantError(
            "The personalized result could not be generated right now."
        ) from exc

    by_id = {row.pk: row for row in matched}
    picks = []
    for pk in data.get("scholarship_ids") or []:
        row = by_id.get(pk)
        if row:
            picks.append(
                {
                    "id": row.pk,
                    "slug": row.slug,
                    "name": row.name,
                    "host_country": row.host_country,
                    "degree_level": row.degree_level,
                    "deadline": f"{row.deadline:%d %b %Y}",
                }
            )

    return {
        "headline": str(data.get("headline") or "").strip() or "Your personalized plan",
        "summary": str(data.get("summary") or "").strip(),
        "next_steps": [
            str(step).strip() for step in (data.get("next_steps") or []) if str(step).strip()
        ][:5],
        "scholarships": picks[:5],
    }


# Generic words that would match half the board; only distinctive name words
# should select duplicate candidates.
DUPLICATE_STOPWORDS = {
    "scholarship",
    "scholarships",
    "fellowship",
    "fellowships",
    "programme",
    "program",
    "award",
    "awards",
    "grant",
    "grants",
    "international",
    "university",
    "college",
    "academy",
    "foundation",
    "fully",
    "funded",
    "study",
    "students",
}


def find_possible_duplicate(fields):
    """Advisory duplicate check for a freshly extracted scholarship.

    Cheap by construction: a DB query on distinctive name words picks at most
    five candidates, and only when candidates exist does one small Gemini call
    (a few hundred tokens, ~50 output tokens) decide whether any is the same
    scholarship. Returns {'name', 'status': 'live'|'archived'} or None; any
    failure returns None - this must never break extraction itself.
    """
    name = (fields.get("name") or "").strip()
    if not name:
        return None

    return _ai_cached(
        "duplicate",
        [
            get_version(NS_SCHOLARSHIPS),
            {key: fields.get(key) or "" for key in ("name", "host_country", "degree_level", "deadline", "link")},
        ],
        lambda: _find_possible_duplicate(fields, name),
    )


def _find_possible_duplicate(fields, name):
    words = [w.strip(".,()'\"") for w in name.split()]
    words = [
        w
        for w in words
        if len(w) >= 4 and w.lower() not in DUPLICATE_STOPWORDS and not w.isdigit()
    ]
    if not words:
        return None

    from django.db.models import Q

    query = Q()
    for word in words[:6]:
        query |= Q(name__icontains=word)
    candidates = list(Scholarship.objects.filter(query).order_by("-created_at")[:5])
    if not candidates:
        return None

    new_row = " | ".join(
        f"{key}: {fields.get(key) or '-'}"
        for key in ("name", "host_country", "degree_level", "deadline", "link")
    )
    existing_rows = "\n".join(
        f"id {row.pk}: {row.name} | {row.host_country} | {row.degree_level}"
        f" | deadline {row.deadline}"
        for row in candidates
    )
    prompt = (
        "You check a scholarship board for duplicates. Is the NEW scholarship "
        "the same scholarship as any EXISTING row? A different year or cohort "
        "of the same scholarship counts as the same. Reply with the matching "
        "row's id, or 0 if none match.\n\n"
        f"NEW: {new_row}\n\nEXISTING:\n{existing_rows}"
    )

    try:
        reply = _generate(
            None,
            [{"role": "user", "text": prompt}],
            temperature=0,
            max_tokens=50,
            json_schema={
                "type": "OBJECT",
                "properties": {"match_id": {"type": "INTEGER"}},
                "required": ["match_id"],
            },
        )
        match_id = int(json.loads(reply).get("match_id") or 0)
    except (AssistantError, ValueError, TypeError, json.JSONDecodeError):
        return None

    for row in candidates:
        if row.pk == match_id:
            is_live = row.is_active and row.deadline >= timezone.now().date()
            return {"name": row.name, "status": "live" if is_live else "archived"}
    return None
