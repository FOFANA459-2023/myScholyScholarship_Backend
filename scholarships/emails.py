"""Transactional email for myScholy.

Templates are authored with React Email in the top-level ``emails/`` workspace
and exported to ``scholarships/templates/emails/*.html`` (run ``npm run
export`` there after editing). The ``.txt`` fallbacks next to them are
hand-written Django templates. Both are rendered here with Django's template
engine, so every ``{{ variable }}`` is auto-escaped in the HTML part - user
supplied content (names, contact messages) can never inject markup.

Delivery goes through the Resend API when ``RESEND_API_KEY`` is configured.
Without a key - i.e. local development - it falls back to Django's configured
email backend, which prints to the console unless SMTP credentials are set.
The API key itself lives only in the server-side environment (``.env``, never
committed); nothing in this module logs or returns it.

All public helpers are fire-and-forget: they spawn a daemon thread so an HTTP
request never waits on a network round trip to the email provider, and a
delivery failure is logged rather than surfaced to the caller.
"""

import logging
import threading

import resend
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils import timezone

logger = logging.getLogger(__name__)


def _humanize_seconds(seconds):
    """3600 -> '1 hour', 7200 -> '2 hours', 900 -> '15 minutes'."""
    if seconds >= 3600 and seconds % 3600 == 0:
        hours = seconds // 3600
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    minutes = max(1, seconds // 60)
    return f"{minutes} minute" if minutes == 1 else f"{minutes} minutes"


def _render(template, context):
    ctx = {
        "frontend_url": settings.FRONTEND_URL,
        "year": timezone.now().year,
        **context,
    }
    html = render_to_string(f"emails/{template}.html", ctx)
    text = render_to_string(f"emails/{template}.txt", ctx)
    return html, text


def _deliver(*, to, subject, template, context, reply_to=None):
    html, text = _render(template, context)

    if settings.RESEND_API_KEY:
        resend.api_key = settings.RESEND_API_KEY
        params = {
            "from": settings.DEFAULT_FROM_EMAIL,
            "to": to,
            "subject": subject,
            "html": html,
            "text": text,
        }
        if reply_to:
            params["reply_to"] = reply_to
        resend.Emails.send(params)
        return

    # Local development fallback: Django's backend (console unless SMTP is
    # configured), still with the same rendered HTML + text parts.
    message = EmailMultiAlternatives(
        subject=subject,
        body=text,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=to,
        reply_to=reply_to,
    )
    message.attach_alternative(html, "text/html")
    message.send()


def _deliver_async(description, **kwargs):
    """Send off the request thread; log failures instead of raising."""

    def run():
        try:
            _deliver(**kwargs)
        except Exception:
            # Never log the recipient-facing kwargs wholesale: the reset link
            # contains a live token.
            logger.exception("%s email failed", description)

    threading.Thread(target=run, daemon=True).start()


def send_welcome_email(user):
    _deliver_async(
        "welcome",
        to=[user.email],
        subject="Welcome to myScholy",
        template="welcome",
        context={"first_name": user.first_name or user.username},
    )


def send_password_reset_email(user, reset_link):
    _deliver_async(
        "password reset",
        to=[user.email],
        subject="Reset your myScholy password",
        template="password-reset",
        context={
            "first_name": user.first_name or user.username,
            "reset_link": reset_link,
            "expires_in": _humanize_seconds(settings.PASSWORD_RESET_TIMEOUT),
        },
    )


def send_admin_welcome_email(user):
    """Sent when an existing admin adds a new administrator account."""
    _deliver_async(
        "admin welcome",
        to=[user.email],
        subject="Welcome to the myScholy admin team",
        template="admin-welcome",
        context={
            "first_name": user.first_name or user.username,
            "username": user.username,
        },
    )


def send_scholarship_digest_email(*, to, first_name, scholarships):
    """One digest email: 5 randomly picked live scholarships.

    Synchronous by design - it is called from the ``send_scholarship_digest``
    management command, where fire-and-forget threads could be killed when the
    process exits. The command handles failures per recipient.
    """
    _deliver(
        to=[to],
        subject="myScholy: Scholarships you can still apply for!",
        template="scholarship-digest",
        context={"first_name": first_name, "scholarships": scholarships},
    )


def send_contact_notification(message):
    _deliver_async(
        "contact notification",
        to=[settings.CONTACT_INBOX],
        subject=f"myScholy contact form: {message.name}",
        template="contact-notification",
        context={
            "name": message.name,
            "email": message.email,
            "received_at": f"{message.created_at:%d %b %Y %H:%M} UTC",
            "message": message.message,
        },
        # Hitting reply goes to the person who wrote in, not to ourselves.
        reply_to=[message.email],
    )
