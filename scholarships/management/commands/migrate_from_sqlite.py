from django.core.management.base import BaseCommand
from django.db import transaction, IntegrityError, connections
from django.contrib.auth.models import User
from scholarships.models import Scholarship, Student, Admin

class Command(BaseCommand):
    help = "Migrate users and app data from the 'sqlite' DB alias into the default DB using the ORM."

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true', help='Run without writing to default DB')
        parser.add_argument('--overwrite', action='store_true', help='Overwrite existing records in default DB when matched by username or primary key')

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        overwrite = options['overwrite']

        # Ensure the sqlite alias exists
        if 'sqlite' not in connections.databases:
            self.stderr.write(self.style.ERROR("'sqlite' database alias not configured in settings.DATABASES"))
            return

        summary = {
            'users_created': 0,
            'users_updated': 0,
            'students_created': 0,
            'students_skipped': 0,
            'admins_created': 0,
            'admins_skipped': 0,
            'scholarships_created': 0,
            'scholarships_skipped': 0,
        }

        # Wrap in a transaction for atomicity
        @transaction.atomic
        def migrate():
            # 1) Users
            for u in User.objects.using('sqlite').all().order_by('id'):
                defaults = {
                    'email': u.email,
                    'first_name': u.first_name,
                    'last_name': u.last_name,
                    'is_staff': u.is_staff,
                    'is_active': u.is_active,
                    'is_superuser': u.is_superuser,
                    'date_joined': u.date_joined,
                    'last_login': u.last_login,
                    'password': u.password,  # already hashed
                }
                obj = None
                created = False

                # Prefer match by username
                try:
                    obj = User.objects.get(username=u.username)
                    if overwrite:
                        for k, v in defaults.items():
                            setattr(obj, k, v)
                        obj.save()
                        summary['users_updated'] += 1
                except User.DoesNotExist:
                    try:
                        # Preserve PK if possible
                        obj = User(id=u.id, username=u.username, **defaults)
                        obj.save(force_insert=True)
                        created = True
                    except IntegrityError:
                        # Fallback: let DB assign a new PK
                        obj = User(username=u.username, **defaults)
                        obj.save()
                        created = True
                if created:
                    summary['users_created'] += 1

            # 2) Students (OneToOne -> User)
            for s in Student.objects.using('sqlite').select_related('user').all().order_by('id'):
                try:
                    user = User.objects.get(username=s.user.username)
                except User.DoesNotExist:
                    # Skip if user missing
                    summary['students_skipped'] += 1
                    continue
                if Student.objects.filter(user=user).exists() and not overwrite:
                    summary['students_skipped'] += 1
                    continue
                # Create or update
                stu_obj, created = Student.objects.get_or_create(user=user, defaults={
                    'phone': s.phone,
                    'date_of_birth': s.date_of_birth,
                    'country': s.country,
                })
                if not created and overwrite:
                    stu_obj.phone = s.phone
                    stu_obj.date_of_birth = s.date_of_birth
                    stu_obj.country = s.country
                    stu_obj.save()
                if created:
                    summary['students_created'] += 1

            # 3) Admins (OneToOne -> User)
            for a in Admin.objects.using('sqlite').select_related('user').all().order_by('id'):
                try:
                    user = User.objects.get(username=a.user.username)
                except User.DoesNotExist:
                    summary['admins_skipped'] += 1
                    continue
                if Admin.objects.filter(user=user).exists() and not overwrite:
                    summary['admins_skipped'] += 1
                    continue
                adm_obj, created = Admin.objects.get_or_create(user=user, defaults={
                    'is_super_admin': a.is_super_admin,
                })
                # Ensure user.is_staff for admins
                if not user.is_staff:
                    user.is_staff = True
                    user.save()
                if not created and overwrite:
                    adm_obj.is_super_admin = a.is_super_admin
                    adm_obj.save()
                if created:
                    summary['admins_created'] += 1

            # 4) Scholarships (FK-free of Users, so simple copy)
            for sch in Scholarship.objects.using('sqlite').all().order_by('id'):
                # Try to preserve name uniqueness; if a row with same name and link exists, skip
                exists_qs = Scholarship.objects.filter(name=sch.name, link=sch.link)
                if exists_qs.exists() and not overwrite:
                    summary['scholarships_skipped'] += 1
                    continue
                try:
                    obj = Scholarship(
                        id=sch.id,
                        name=sch.name,
                        description=sch.description,
                        deadline=sch.deadline,
                        host_country=sch.host_country,
                        benefits=sch.benefits,
                        eligibility=sch.eligibility,
                        degree_level=sch.degree_level,
                        link=sch.link,
                        author=sch.author,
                        created_at=sch.created_at,
                        updated_at=sch.updated_at,
                        is_active=sch.is_active,
                    )
                    obj.save(force_insert=True)
                    summary['scholarships_created'] += 1
                except IntegrityError:
                    # Conflict on PK; either update or create without preserving PK
                    if overwrite and exists_qs.exists():
                        obj = exists_qs.first()
                        obj.description = sch.description
                        obj.deadline = sch.deadline
                        obj.host_country = sch.host_country
                        obj.benefits = sch.benefits
                        obj.eligibility = sch.eligibility
                        obj.degree_level = sch.degree_level
                        obj.author = sch.author
                        obj.is_active = sch.is_active
                        obj.save()
                        summary['scholarships_created'] += 1
                    else:
                        obj = Scholarship(
                            name=sch.name,
                            description=sch.description,
                            deadline=sch.deadline,
                            host_country=sch.host_country,
                            benefits=sch.benefits,
                            eligibility=sch.eligibility,
                            degree_level=sch.degree_level,
                            link=sch.link,
                            author=sch.author,
                            is_active=sch.is_active,
                        )
                        obj.save()
                        summary['scholarships_created'] += 1

        if dry_run:
            self.stdout.write(self.style.WARNING('Dry run enabled; no changes will be written.'))
            # Still execute to count what would happen, but rollback at the end
            try:
                with transaction.atomic():
                    migrate()
                    raise RuntimeError('DRY_RUN_ROLLBACK')
            except RuntimeError:
                pass
        else:
            migrate()

        # Print summary
        self.stdout.write(self.style.SUCCESS('Migration complete. Summary:'))
        for k, v in summary.items():
            self.stdout.write(f"- {k}: {v}")
