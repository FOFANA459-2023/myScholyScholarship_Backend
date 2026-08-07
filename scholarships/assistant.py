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

import json
import logging
import urllib.error
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
- description: 2-4 sentences summarising what the scholarship is and who it is
  for, written from the announcement's own information.
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


def extract_scholarship(text):
    """Extract posting-form fields from pasted announcement text.

    Returns a dict with every EXTRACT_FIELDS key, values '' when the text does
    not contain that piece of information.
    """
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
            "contents": [{"role": "user", "parts": [{"text": text}]}],
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
