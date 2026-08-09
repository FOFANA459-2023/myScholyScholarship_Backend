"""Send the recurring scholarship digest.

Picks 5 random live scholarships (active AND still open for application) and
emails them to every active student account. Scheduling lives outside Django:
the systemd timer in ``deploy/oracle/myscholy-digest.timer`` runs this command
every 15 hours on the production VM (see ORACLE_DEPLOY.md).

A ``DigestRun`` row is written for every full send, and the command skips
when one exists inside ``MIN_HOURS_BETWEEN_RUNS``. The row lives in the
shared database, so a second scheduler (a stray timer, the Render backup, a
manual run) cannot email every student twice - it sees the first run and
exits. ``--to`` and ``--dry-run`` bypass the guard and never record a run.

Sending is synchronous on purpose - a management command exits when ``handle``
returns, which would kill the fire-and-forget threads the request-path email
helpers use. A failure for one recipient is logged and never blocks the rest.
"""

import logging
from datetime import timedelta

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.utils import timezone

from ...emails import send_scholarship_digest_email
from ...models import DigestRun, Scholarship

logger = logging.getLogger(__name__)

DIGEST_SIZE = 5

# The timer fires every 15 hours; anything sooner than this since the last
# recorded run is a duplicate trigger, not the next scheduled one. The hour
# of slack absorbs timer jitter so legitimate runs are never skipped.
MIN_HOURS_BETWEEN_RUNS = 14


class Command(BaseCommand):
    help = (
        "Email every active student 5 randomly picked live scholarships "
        "(name + myScholy detail-page link) with a nudge to explore the "
        "board. Skips if a digest already went out in the last "
        f"{MIN_HOURS_BETWEEN_RUNS} hours."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--to",
            action="append",
            default=None,
            metavar="EMAIL",
            help=(
                "Send only to this address (repeatable). For testing the "
                "template without emailing the whole user base."
            ),
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print what would be sent without sending anything.",
        )

    def handle(self, *args, **options):
        test_run = bool(options["to"]) or options["dry_run"]
        if not test_run:
            cutoff = timezone.now() - timedelta(hours=MIN_HOURS_BETWEEN_RUNS)
            last = DigestRun.objects.filter(sent_at__gte=cutoff).first()
            if last is not None:
                self.stdout.write(
                    self.style.WARNING(
                        f"Digest already sent at {last.sent_at:%Y-%m-%d %H:%M} "
                        f"UTC (less than {MIN_HOURS_BETWEEN_RUNS}h ago) - "
                        "skipping to avoid a duplicate."
                    )
                )
                return

        scholarships = list(
            Scholarship.objects.active()
            .open_for_application()
            .order_by("?")[:DIGEST_SIZE]
        )
        if not scholarships:
            self.stdout.write("No live scholarships on the board - nothing to send.")
            return

        if options["to"]:
            recipients = [(address, "there") for address in options["to"]]
        else:
            rows = (
                User.objects.filter(is_active=True, student__isnull=False)
                .exclude(email="")
                .values_list("email", "first_name", "username")
                .iterator(chunk_size=500)
            )
            recipients = [
                (email, first_name or username) for email, first_name, username in rows
            ]

        self.stdout.write(
            f"Digest: {len(scholarships)} scholarships -> "
            f"{len(recipients)} recipient(s)"
        )
        for scholarship in scholarships:
            self.stdout.write(f"  * {scholarship.name} (id={scholarship.pk})")

        if options["dry_run"]:
            self.stdout.write("Dry run - no emails sent.")
            return

        # Recorded before the loop so a concurrent trigger on the other
        # server skips immediately; a mid-send crash then errs on the side
        # of some students missing one digest rather than anyone getting two.
        run = None
        if not test_run:
            run = DigestRun.objects.create()

        sent = failed = 0
        for address, first_name in recipients:
            try:
                send_scholarship_digest_email(
                    to=address, first_name=first_name, scholarships=scholarships
                )
                sent += 1
            except Exception:
                failed += 1
                logger.exception("Digest email to %s failed", address)

        if run is not None:
            run.recipient_count = sent
            run.save(update_fields=["recipient_count"])

        self.stdout.write(self.style.SUCCESS(f"Sent {sent}, failed {failed}."))
