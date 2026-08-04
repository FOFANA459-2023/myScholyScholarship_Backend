"""API serializers.

Validation lives here rather than only in the React forms: the browser checks
are a convenience for the person typing, but the API is public and must assume
any payload can arrive. Every message is written to tell the user what to do
next ("Enter a phone number like +231 770 123 456"), not to name the rule that
failed, because these strings are shown verbatim under the offending field.
"""

import re

from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from rest_framework import serializers

from .models import Admin, ContactMessage, Scholarship, Student

# Permissive on purpose: digits, spaces, dashes, brackets and an optional
# leading +. Real-world numbers vary far too much to pin down further, and a
# rejected valid number is worse than an accepted odd one.
PHONE_RE = re.compile(r"^\+?[\d\s\-()]{7,20}$")
NAME_RE = re.compile(r"^[^\d<>@]{1,60}$")


def _clean(value):
    return (value or "").strip()


class ScholarshipListSerializer(serializers.ModelSerializer):
    """Card-sized payload for the board. Omits the three large TEXT columns,
    which cuts the typical list response by roughly an order of magnitude."""

    is_open = serializers.SerializerMethodField()

    class Meta:
        model = Scholarship
        fields = (
            "id",
            "name",
            "deadline",
            "host_country",
            "degree_level",
            "author",
            "link",
            "created_at",
            "is_active",
            "is_open",
        )
        read_only_fields = fields

    def get_is_open(self, obj):
        # Compare against a date resolved once per request rather than per row.
        today = self.context.get("today") or timezone.now().date()
        return obj.deadline >= today


class ScholarshipSerializer(serializers.ModelSerializer):
    """Full record, used for detail views and all writes."""

    is_open = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Scholarship
        fields = "__all__"
        read_only_fields = ("id", "created_at", "updated_at")

    def get_is_open(self, obj):
        today = self.context.get("today") or timezone.now().date()
        return obj.deadline >= today

    def validate_name(self, value):
        value = _clean(value)
        if len(value) < 3:
            raise serializers.ValidationError(
                "Enter the full scholarship name (at least 3 characters)."
            )
        return value

    def validate_deadline(self, value):
        # Only enforced on create; existing records may legitimately be past.
        if self.instance is None and value < timezone.now().date():
            raise serializers.ValidationError(
                "The deadline has already passed. Choose a future date."
            )
        return value

    def validate_link(self, value):
        value = _clean(value)
        if not value.lower().startswith(("http://", "https://")):
            raise serializers.ValidationError(
                "Enter the full application URL, starting with https://"
            )
        return value

    def validate_description(self, value):
        value = value.strip()
        if len(value) < 20:
            raise serializers.ValidationError(
                "Describe the scholarship in a little more detail "
                "(at least 20 characters) so students know what it covers."
            )
        return value

    def validate_host_country(self, value):
        value = _clean(value)
        if len(value) < 2:
            raise serializers.ValidationError("Enter the host country.")
        return value

    def validate_degree_level(self, value):
        value = _clean(value)
        if not value:
            raise serializers.ValidationError(
                "Enter the degree level, e.g. Masters. This powers the board filter."
            )
        return value


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    first_name = serializers.CharField(required=True, allow_blank=False)
    last_name = serializers.CharField(required=True, allow_blank=False)
    email = serializers.EmailField(
        required=True,
        error_messages={
            "invalid": "That doesn't look like a valid email address - check for typos.",
            "blank": "Enter your email address.",
            "required": "Enter your email address.",
        },
    )

    class Meta:
        model = User
        fields = ("id", "username", "email", "first_name", "last_name", "password")

    def _validate_name(self, value, label):
        value = _clean(value)
        if not value:
            raise serializers.ValidationError(f"Enter your {label}.")
        if not NAME_RE.match(value):
            raise serializers.ValidationError(
                f"Enter a valid {label} - letters only, no digits or symbols."
            )
        return value

    def validate_first_name(self, value):
        return self._validate_name(value, "first name")

    def validate_last_name(self, value):
        return self._validate_name(value, "last name")

    def validate_email(self, value):
        value = _clean(value).lower()
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError(
                "An account with this email already exists. Try signing in "
                "instead, or reset your password if you've forgotten it."
            )
        return value

    def validate_username(self, value):
        value = _clean(value).lower()
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError(
                "An account with this email already exists. Try signing in "
                "instead, or reset your password if you've forgotten it."
            )
        return value

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError(
                "Your password needs at least 8 characters."
            )
        # Django's validators cover common passwords, all-numeric passwords and
        # similarity to the username/email. Their messages are already
        # user-facing, so they are passed through unchanged.
        try:
            validate_password(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(list(exc.messages)) from exc
        return value

    def create(self, validated_data):
        password = validated_data.pop("password")
        # create_user hashes the password and saves once. ModelSerializer's
        # default create() would store the raw string - never remove this.
        return User.objects.create_user(password=password, **validated_data)


class StudentSerializer(serializers.ModelSerializer):
    """Registration payload.

    Citizenship, residence and education level are required here even though
    the model columns allow blank: eligibility for most scholarships turns on
    them, and the model stays permissive so existing rows and admin-created
    profiles are not invalidated.
    """

    user = UserSerializer()
    country_of_citizenship = serializers.CharField(
        required=True,
        allow_blank=False,
        error_messages={
            "blank": "Enter your country of citizenship.",
            "required": "Enter your country of citizenship.",
        },
    )
    country_of_residence = serializers.CharField(
        required=True,
        allow_blank=False,
        error_messages={
            "blank": "Enter your country of residence.",
            "required": "Enter your country of residence.",
        },
    )
    education_level = serializers.ChoiceField(
        choices=Student.EducationLevel.choices,
        required=True,
        allow_blank=False,
        # An empty string arrives as invalid_choice rather than blank, so both
        # messages have to stand on their own.
        error_messages={
            "invalid_choice": "Select your education level - "
            "high school, undergraduate or graduate.",
            "blank": "Select your education level - "
            "high school, undergraduate or graduate.",
            "required": "Select your education level - "
            "high school, undergraduate or graduate.",
        },
    )

    class Meta:
        model = Student
        fields = "__all__"

    def validate_phone(self, value):
        value = _clean(value)
        if value and not PHONE_RE.match(value):
            raise serializers.ValidationError(
                "Enter a phone number like +231 770 123 456."
            )
        return value

    def _validate_country(self, value, label):
        value = _clean(value)
        if len(value) < 2:
            raise serializers.ValidationError(f"Enter your {label}.")
        return value

    def validate_country_of_citizenship(self, value):
        return self._validate_country(value, "country of citizenship")

    def validate_country_of_residence(self, value):
        return self._validate_country(value, "country of residence")

    def validate_date_of_birth(self, value):
        if value and value > timezone.now().date():
            raise serializers.ValidationError(
                "Your date of birth can't be in the future."
            )
        return value

    def create(self, validated_data):
        user_data = validated_data.pop("user")
        user = UserSerializer().create(user_data)
        return Student.objects.create(user=user, **validated_data)


class AdminSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = Admin
        fields = "__all__"

    def create(self, validated_data):
        user_data = validated_data.pop("user")
        user = UserSerializer().create(user_data)
        user.is_staff = True
        user.save(update_fields=["is_staff"])
        return Admin.objects.create(user=user, **validated_data)


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(
        error_messages={
            "blank": "Enter the email or username you signed up with.",
            "required": "Enter the email or username you signed up with.",
        }
    )
    password = serializers.CharField(
        style={"input_type": "password"},
        error_messages={
            "blank": "Enter your password to sign in.",
            "required": "Enter your password to sign in.",
        },
    )

    def validate_username(self, value):
        return _clean(value)


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(
        error_messages={
            "invalid": "That doesn't look like a valid email address - check for typos.",
            "blank": "Enter the email you signed up with.",
            "required": "Enter the email you signed up with.",
        }
    )


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(
        style={"input_type": "password"},
        error_messages={
            "blank": "Enter a new password.",
            "required": "Enter a new password.",
        },
    )
    # Full password validation happens in the view, where the resolved user is
    # available for UserAttributeSimilarityValidator.

    def validate_new_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError(
                "Your password needs at least 8 characters."
            )
        return value


class ContactMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactMessage
        fields = ("id", "name", "email", "message", "created_at")
        read_only_fields = ("id", "created_at")
        extra_kwargs = {
            "name": {
                "error_messages": {
                    "blank": "Enter your name.",
                    "required": "Enter your name.",
                }
            },
            "email": {
                "error_messages": {
                    "invalid": "That doesn't look like a valid email address - "
                    "we need it to reply.",
                    "blank": "Enter your email address.",
                    "required": "Enter your email address.",
                }
            },
        }

    def validate_name(self, value):
        value = _clean(value)
        if len(value) < 2:
            raise serializers.ValidationError("Enter your name.")
        if not NAME_RE.match(value):
            raise serializers.ValidationError(
                "Enter a valid name - letters only, no digits or symbols."
            )
        return value

    def validate_email(self, value):
        return _clean(value).lower()

    def validate_message(self, value):
        value = value.strip()
        if len(value) < 10:
            raise serializers.ValidationError(
                "Please give us a little more detail (at least 10 characters)."
            )
        if len(value) > 5000:
            raise serializers.ValidationError(
                "That message is too long (5000 characters maximum). "
                "Please shorten it or email us directly."
            )
        return value
