from allauth.account import app_settings as allauth_settings
from allauth.account.adapter import get_adapter
from allauth.account.forms import default_token_generator
from allauth.account.utils import (
    filter_users_by_email,
    setup_user_email,
    url_str_to_user_pk,
    user_pk_to_url_str,
    user_username,
)
from allauth.utils import email_address_exists, get_username_max_length
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, password_validation
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ValidationError as DjangoValidationError
from django.urls import reverse
from django.urls.exceptions import NoReverseMatch
from django.utils.encoding import force_str
from rest_framework import serializers
from rest_framework.request import Request

User = get_user_model()


class AllauthLoginSerializer(serializers.Serializer):
    """Deserializer for login data using allauth.

    Uses email + password or username + password depending on allauth settings.
    Store authentication user instance in validated data.
    Raise ValidationError if not able to login for any reason.
    """

    if (
        allauth_settings.AUTHENTICATION_METHOD
        == allauth_settings.AuthenticationMethod.USERNAME
    ):
        username = serializers.CharField()
    elif (
        allauth_settings.AUTHENTICATION_METHOD
        == allauth_settings.AuthenticationMethod.EMAIL
    ):
        email = serializers.CharField()
    else:
        username = serializers.CharField(required=False, allow_blank=True)
        email = serializers.CharField(required=False, allow_blank=True)

    password = serializers.CharField(write_only=True, trim_whitespace=False)

    def validate(self, attrs: dict) -> dict:
        username = attrs.get("username")
        email = attrs.get("email")
        password = attrs.get("password")
        request = self.context["request"]

        # Validate credentials
        if (
            allauth_settings.AUTHENTICATION_METHOD
            == allauth_settings.AuthenticationMethod.USERNAME_EMAIL
        ):
            if not (email and password) and not (username and password):
                raise serializers.ValidationError(
                    "Must include `email`/`username` and `password`."
                )

        # Will authentication using email, username or either of this depending on `AUTHENTICATION_METHOD`
        # using `allauth.account.auth_backends.AuthenticationBackend``
        try:
            user = authenticate(
                request, username=username, email=email, password=password
            )
        except NoReverseMatch:
            # When `is_active` of a user is set to False, allauth tries to return template html
            raise serializers.ValidationError("User account is disabled.")

        if not user:
            raise serializers.ValidationError(
                "Unable to login with provided credentials."
            )

        if user.is_active is False:
            raise serializers.ValidationError("User account is disabled.")

        # Validate email verification
        if (
            allauth_settings.EMAIL_VERIFICATION
            == allauth_settings.EmailVerificationMethod.MANDATORY
        ):
            email_address = user.emailaddress_set.get(email=user.email)
            if not email_address.verified:
                raise serializers.ValidationError("Email address is not verified.")

        attrs["user"] = user
        return attrs


class UserSerializer(serializers.ModelSerializer):
    """User serializer for retrieving and update."""

    def validate_username(self, username: str) -> str:
        return get_adapter().clean_username(username)

    class Meta:
        model = User
        fields = []
        read_only_fields = []

        if allauth_settings.USER_MODEL_USERNAME_FIELD:
            fields.append("username")
            read_only_fields.append("username")

        if allauth_settings.USER_MODEL_EMAIL_FIELD:
            fields.append("email")
            read_only_fields.append("email")


class AllauthRegisterSerializer(serializers.Serializer):
    """Registration serializer using email/username + password via allauth.

    Controlled via allauth's settings.
    """

    if allauth_settings.USER_MODEL_USERNAME_FIELD:
        username = serializers.CharField(
            max_length=get_username_max_length(),
            min_length=allauth_settings.USERNAME_MIN_LENGTH,
        )
    if allauth_settings.USER_MODEL_EMAIL_FIELD:
        email = serializers.EmailField()

    password = serializers.CharField(write_only=True, trim_whitespace=False)

    def save(self, request: Request) -> User:
        adapter = get_adapter()
        user = adapter.new_user(request)
        cleaned_data = self.get_cleaned_data()
        self.cleaned_data = cleaned_data
        user = adapter.save_user(request, user, self, commit=False)

        if "password1" in cleaned_data:
            try:
                adapter.clean_password(cleaned_data["password1"], user=user)
            except DjangoValidationError as exc:
                raise serializers.ValidationError(
                    detail=serializers.as_serializer_error(exc)
                )

        user.save()
        setup_user_email(request, user, [])

        return user

    def get_cleaned_data(self) -> dict:
        # NOTE: allauth's save_user expects `email`/`username` and `password1` to be in data
        return {
            "email": self.validated_data.get("email", ""),
            "username": self.validated_data.get("username", ""),
            "password1": self.validated_data.get("password", ""),
        }

    def validate_email(self, email: str) -> str:
        email = get_adapter().clean_email(email)
        if allauth_settings.UNIQUE_EMAIL:
            if email and email_address_exists(email):
                raise serializers.ValidationError(
                    "This email address is already taken."
                )
        return email

    def validate_username(self, username: str) -> str:
        return get_adapter().clean_username(username)

    def validate_password(self, password: str) -> str:
        return get_adapter().clean_password(password)


# Password


class PasswordResetSerializer(serializers.Serializer):
    """Serializer for resetting user password using email."""

    email = serializers.EmailField()

    def validate(self, attrs):
        return attrs

    def validate_email(self, email):
        return get_adapter().clean_email(email)

    def save(self):
        request = self.context.get("request")
        current_site = get_current_site(request)
        email = self.validated_data.get("email")
        token_generator = default_token_generator

        # Should be only a single user
        users = filter_users_by_email(email=email, is_active=True)

        for user in users:
            uid = user_pk_to_url_str(user)
            temp_key = token_generator.make_token(user)

            # Password reset template context
            context = {
                "request": request,
                "current_site": current_site,
                "user": user,
                "password_reset_url": settings.KNOX_ALLAUTH_PASSWORD_RESET_URL.format(
                    uid=uid, key=temp_key
                ),
            }

            if (
                allauth_settings.AUTHENTICATION_METHOD
                != allauth_settings.AuthenticationMethod.EMAIL
            ):
                context["username"] = user_username(user)

            # Send email for password resetting
            get_adapter(request).send_mail(
                template_prefix="account/email/password_reset_key",
                email=email,
                context=context,
            )


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for changing password without entering the old password using email uid and token."""

    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(
        max_length=128,
        trim_whitespace=False,
        help_text=password_validation.password_validators_help_text_html(),
    )

    def validate(self, attrs):
        # Decode the uid to uid to get user object
        try:
            uid = force_str(url_str_to_user_pk(attrs["uid"]))
            self.user = User._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError(
                {"uid": ["Invalid encoded user id value."]}
            )

        if not default_token_generator.check_token(self.user, attrs["token"]):
            raise serializers.ValidationError({"token": ["Invalid user token."]})

        # Run password validation (None if valid, DjangoValidationError if invalid)
        new_password = attrs.get("new_password")
        password_validation.validate_password(new_password, self.user)

        return attrs

    def save(self):
        """Set new validated password and save changes."""
        new_password = self.validated_data["new_password"]
        self.user.set_password(new_password)
        self.user.save()
        return self.user


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128)
    new_password = serializers.CharField(max_length=128)

    def validate_old_password(self, old_password):
        user = self.context["request"].user
        if not user.check_password(old_password):
            raise serializers.ValidationError(
                "Your old password was entered incorrectly. Please enter it again."
            )

        return old_password

    def validate_new_password(self, new_password):
        user = self.context["request"].user
        password_validation.validate_password(new_password, user)

        return new_password

    def save(self):
        """Set new validated password and save changes."""
        user = self.context["request"].user
        new_password = self.validated_data["new_password"]
        user.set_password(new_password)
        user.save()
        return user


# Email


class EmailVerifySerializer:
    pass


class EmailResendVerificationSerializer:
    pass


# Social


class SocialLoginSerializer:
    pass


class SocialAccountSerializer:
    pass


class SocialConnectSerializer:
    pass
