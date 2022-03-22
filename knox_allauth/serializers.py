from allauth.account import app_settings as allauth_settings
from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email
from allauth.utils import email_address_exists, get_username_max_length
from django.contrib.auth import authenticate, get_user_model
from django.core.exceptions import ValidationError as DjangoValidationError
from django.urls.exceptions import NoReverseMatch
from rest_framework import serializers
from rest_framework.request import Request

User = get_user_model()


class AllauthLoginSerializer(serializers.Serializer):
    """Deserializer for login data using allauth.

    Uses email + password or username + password depending on allauth settings.
    Store authentication user instance in validated data.
    Raise ValidationError if not able to login for any reason.
    """

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
            == allauth_settings.AuthenticationMethod.EMAIL
        ):
            if not (email and password):
                raise serializers.ValidationError(
                    "Must include `email` and `password`."
                )
        elif (
            allauth_settings.AUTHENTICATION_METHOD
            == allauth_settings.AuthenticationMethod.USERNAME
        ):
            if not (username and password):
                raise serializers.ValidationError(
                    "Must include `username` and `password`."
                )
        else:
            if not (email and password) and not (username and password):
                raise serializers.ValidationError(
                    "Must include `email` or `username` and `password`."
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
        fields = ["email", "username"]
        read_only_fields = ["email", "username"]


class AllauthRegisterSerializer(serializers.Serializer):
    """Registration serializer using email/username + password via allauth.

    Controlled via allauth's settings.
    """

    username = serializers.CharField(
        max_length=get_username_max_length(),
        min_length=allauth_settings.USERNAME_MIN_LENGTH,
        required=allauth_settings.USERNAME_REQUIRED,
    )
    email = serializers.EmailField(required=allauth_settings.EMAIL_REQUIRED)
    password = serializers.CharField(write_only=True, trim_whitespace=False)

    def save(self, request: Request) -> User:
        adapter = get_adapter()
        user = adapter.new_user(request)
        cleaned_data = self.get_cleaned_data()
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


class PasswordResetSerializer:
    pass


class PasswordResetConfirmSerializer:
    pass


class PasswordChangeSerializer:
    pass


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
