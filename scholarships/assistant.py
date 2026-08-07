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
from django.utils import timezone

from .models import Scholarship

logger = logging.getLogger(__name__)

GEMINI_ENDPOINT = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)

# How many scholarships to hand the model as context. Kept small so free-tier
# token budgets last; the list endpoint remains the place to browse everything.
MAX_CONTEXT_SCHOLARSHIPS = 8
MAX_HISTORY_TURNS = 10

SYSTEM_PROMPT = """\
You are the MyScholy assistant, a friendly helper embedded on myscholy.pages.dev,
a free scholarship board that lists fully funded scholarships worldwide.

About the site, so you can guide visitors:
- Home page: highlights and a FAQ section (/#faq).
- Scholarships page (/scholarships): browse every live listing; filter by host
  country and degree level, search by name, and sort by deadline. Each listing
  links to the official application page.
- Services: Consulting (/consulting) and myScholy Academy (/academy).
- Contact page (/contact): a form that reaches the MyScholy team directly.
- Accounts: students can sign up (/signup) and log in (/login) for free.
  Password reset is available at /forgot-password - it emails a single-use
  link that expires after one hour.
- Everything is free: free to browse, free to apply.

Rules:
- Answer questions about MyScholy, the scholarships listed below, studying
  abroad, and scholarship applications in general. For unrelated topics, say
  you can only help with MyScholy and scholarships.
- When recommending scholarships, use ONLY the listings provided below - never
  invent scholarships, deadlines or links. If nothing below fits, say so and
  point the visitor to /scholarships to browse or /contact to ask the team.
- Be concise: a few sentences or a short list. Plain text only, no markdown.
- Never ask for passwords or personal details.

Today's date is {today}.

Current live scholarships matching the visitor's question:
{context}
"""


class AssistantError(Exception):
    """Provider failure the view can translate into a friendly response."""

    def __init__(self, message, *, retryable=False):
        super().__init__(message)
        self.retryable = retryable


def _context_scholarships(message):
    """Live listings that look relevant to the question, nearest deadline first.

    Cheap keyword matching is enough here: the model does the actual reasoning,
    it just needs real rows to reason over. Falls back to the soonest-closing
    listings when nothing matches so the model always has genuine data.
    """
    live = Scholarship.objects.active().open_for_application().order_by("deadline")

    words = [w.strip(".,!?()\"'") for w in message.split()]
    words = [w for w in words if len(w) >= 4]

    matches = []
    seen = set()
    if words:
        from django.db.models import Q

        query = Q()
        for word in words:
            query |= (
                Q(name__icontains=word)
                | Q(host_country__icontains=word)
                | Q(degree_level__icontains=word)
            )
        for row in live.filter(query)[:MAX_CONTEXT_SCHOLARSHIPS]:
            matches.append(row)
            seen.add(row.pk)

    for row in live[: MAX_CONTEXT_SCHOLARSHIPS - len(matches)]:
        if row.pk not in seen:
            matches.append(row)

    if not matches:
        return "  (no live scholarships at the moment)"

    return "\n".join(
        f"- {row.name} | Country: {row.host_country} | Degree: {row.degree_level}"
        f" | Deadline: {row.deadline:%d %b %Y} | Apply: {row.link}"
        for row in matches[:MAX_CONTEXT_SCHOLARSHIPS]
    )


def _generate(payload):
    """POST a generateContent payload; return the reply text ('' if empty)."""
    url = GEMINI_ENDPOINT.format(model=settings.GEMINI_MODEL)
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": settings.GEMINI_API_KEY,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            data = json.load(response)
    except urllib.error.HTTPError as exc:
        # 429 = free-tier quota exhausted; anything else is logged for us.
        body = exc.read().decode(errors="replace")[:500]
        logger.warning("Gemini API error %s: %s", exc.code, body)
        raise AssistantError(
            "The assistant is taking a break right now. Please try again in a "
            "few minutes, or reach us through the contact page.",
            retryable=exc.code == 429,
        ) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        logger.warning("Gemini API unreachable: %s", exc)
        raise AssistantError(
            "The assistant could not be reached. Please try again shortly."
        ) from exc

    try:
        parts = data["candidates"][0]["content"]["parts"]
        return "".join(part.get("text", "") for part in parts).strip()
    except (KeyError, IndexError):
        return ""


def ask(message, history):
    """One assistant turn. ``history`` is [{'role': 'user'|'model', 'text': str}]."""
    system = SYSTEM_PROMPT.format(
        today=f"{timezone.now().date():%d %B %Y}",
        context=_context_scholarships(message),
    )

    contents = [
        {"role": turn["role"], "parts": [{"text": turn["text"]}]}
        for turn in history[-MAX_HISTORY_TURNS:]
    ]
    contents.append({"role": "user", "parts": [{"text": message}]})

    reply = _generate(
        {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": contents,
            "generationConfig": {"temperature": 0.4, "maxOutputTokens": 800},
        }
    )

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
You extract structured scholarship data for the MyScholy admin posting form.
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


def fetch_url(url):
    """Download a scholarship page. Returns ('pdf', bytes) or ('text', str)."""
    _assert_public_host(url)

    request = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (MyScholy admin helper)"}
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            content_type = (response.headers.get("Content-Type") or "").lower()
            body = response.read(MAX_FETCH_BYTES)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise AssistantError(
            "That page could not be fetched. Copy the text and paste it instead."
        ) from exc

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
    """
    if pdf_bytes is not None:
        parts = [
            {
                "inline_data": {
                    "mime_type": "application/pdf",
                    "data": base64.b64encode(pdf_bytes).decode(),
                }
            },
            {"text": "Extract the scholarship details from this document."},
        ]
    else:
        parts = [{"text": text}]

    reply = _generate(
        {
            "system_instruction": {
                "parts": [
                    {
                        "text": EXTRACT_PROMPT.format(
                            today=f"{timezone.now().date():%Y-%m-%d}"
                        )
                    }
                ]
            },
            "contents": [{"role": "user", "parts": parts}],
            "generationConfig": {
                "temperature": 0,
                "maxOutputTokens": 2000,
                "responseMimeType": "application/json",
                "responseSchema": EXTRACT_SCHEMA,
            },
        }
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
- scholarship_ids: ids of up to 5 listings from the table above that fit
  their study level, best first. Prefer listings in their preferred region,
  but when that region has none, include the best fits from other regions -
  students routinely consider them. Be generous: include a listing unless its
  degree level clearly does not match. Only ids from the table - never
  invent. Empty list only when truly nothing fits.
"""


def personalized_assessment(answers):
    """Personalized quiz result grounded with matching live scholarships.

    ``answers`` is a dict of quiz answers (ASSESSMENT_KEYS). Returns
    {'headline', 'summary', 'next_steps', 'scholarships'} where scholarships
    are real rows resolved from the model's picks.
    """
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
        {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": ASSESSMENT_PROMPT.format(
                                answers=answer_lines,
                                today=f"{timezone.now().date():%d %B %Y}",
                                rows=rows,
                            )
                        }
                    ],
                }
            ],
            "generationConfig": {
                "temperature": 0.5,
                "maxOutputTokens": 1200,
                "responseMimeType": "application/json",
                "responseSchema": ASSESSMENT_SCHEMA,
            },
        }
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
            {
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0,
                    "maxOutputTokens": 50,
                    "responseMimeType": "application/json",
                    "responseSchema": {
                        "type": "OBJECT",
                        "properties": {"match_id": {"type": "INTEGER"}},
                        "required": ["match_id"],
                    },
                },
            }
        )
        match_id = int(json.loads(reply).get("match_id") or 0)
    except (AssistantError, ValueError, TypeError, json.JSONDecodeError):
        return None

    for row in candidates:
        if row.pk == match_id:
            is_live = row.is_active and row.deadline >= timezone.now().date()
            return {"name": row.name, "status": "live" if is_live else "archived"}
    return None
