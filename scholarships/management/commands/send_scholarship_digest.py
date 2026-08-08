"""Send the recurring scholarship digest.

Picks 5 random live scholarships (active AND still open for application) and
emails them to every active student account. Scheduling lives outside Django:
the systemd timer in ``deploy/oracle/myscholy-digest.timer`` runs this command
every 10 hours on the production VM (see ORACLE_DEPLOY.md).

Sending is synchronous on purpose - a management command exits when ``handle``
returns, which would kill the fire-and-forget threads the request-path email
helpers use. A failure for one recipient is logged and never blocks the rest.
"""

import logging

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from ...emails import send_scholarship_digest_email
from ...models import Scholarship

logger = logging.getLogger(__name__)

DIGEST_SIZE = 5


class Command(BaseCommand):
    help = (
        "Email every active student 5 randomly picked live scholarships "
        "(name + link) with a nudge to explore the board."
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
            self.stdout.write(f"  * {scholarship.name} ({scholarship.link})")

        if options["dry_run"]:
            self.stdout.write("Dry run - no emails sent.")
            return

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

        self.stdout.write(self.style.SUCCESS(f"Sent {sent}, failed {failed}."))
