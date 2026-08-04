"""Cache invalidation wiring.

Any write to a cached model bumps its namespace version, so the next read
recomputes instead of serving stale data.
"""

from django.contrib.auth.models import User
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .cache import invalidate_scholarships, invalidate_users
from .models import Admin, Scholarship, Student


@receiver(post_save, sender=Scholarship)
@receiver(post_delete, sender=Scholarship)
def _scholarship_changed(**kwargs):
    invalidate_scholarships()


@receiver(post_save, sender=User)
@receiver(post_delete, sender=User)
@receiver(post_save, sender=Student)
@receiver(post_delete, sender=Student)
@receiver(post_save, sender=Admin)
@receiver(post_delete, sender=Admin)
def _user_changed(**kwargs):
    # Statistics and the admin roster both derive from these tables, as do the
    # per-request "is this user an admin?" permission lookups.
    invalidate_users()
