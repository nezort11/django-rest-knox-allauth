from allauth.account import app_settings as allauth_settings
from allauth.account.models import (
    EmailAddress,
    EmailConfirmation,
    EmailConfirmationHMAC,
)
from allauth.account.utils import complete_signup
from django.contrib.auth.signals import user_logged_in
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters
from drf_spectacular.utils import OpenApiResponse, extend_schema, inline_serializer
from knox.models import AuthToken
from knox.settings import knox_settings
from knox.views import LogoutAllView as KnoxLogoutAllView
from knox.views import LogoutView as KnoxLogoutView
from rest_framework import serializers, status
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.generics import CreateAPIView, RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.serializers import DateTimeField
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from .serializers import (
    AllauthLoginSerializer,
    AllauthRegisterSerializer,
    EmailResendVerificationSerializer,
    EmailVerifySerializer,
    PasswordChangeSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetSerializer,
    UserSerializer,
)


class LoginView(APIView):
    """Check the credentials from the request data and return a session token.

    Similar to knox's `LoginView` but uses allauth authentication backend instead of
    another API authentication method (basic/session auth).
    """

    authentication_classes = []
    permission_classes = [AllowAny]

    @sensitive_post_parameters("password")
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    @extend_schema(
        request=AllauthLoginSerializer,
        responses={
            200: inline_serializer(
                "AuthTokenSerializer",
                {
                    "expiry": serializers.DateTimeField(),
                    "token": serializers.CharField(),
                    "user": UserSerializer(),
                },
            )
        },
    )
    def post(self, *args, **kwargs):
        # Authentication request (get user instance) using AllauthLoginSerializer
        serializer = AllauthLoginSerializer(
            data=self.request.data, context=self.get_serializer_context()
        )
        serializer.is_valid(raise_exception=True)
        self.user = serializer.validated_data["user"]

        self.check_token_limit()

        instance, token = AuthToken.objects.create(user=self.user)
        user_logged_in.send(
            sender=self.user.__class__, request=self.request, user=self.user
        )
        user_serializer = UserSerializer(instance=self.user)
        data = {
            "expiry": self.format_expiry_datetime(instance.expiry),
            "token": token,
            "user": user_serializer.data,
        }
        return Response(data)

    def check_token_limit(self):
        """Check user limit on created tokens."""
        token_limit_per_user = self.get_token_limit_per_user()
        if token_limit_per_user is not None:
            now = timezone.now()
            token = self.user.auth_token_set.filter(expiry__gt=now)
            if token.count() >= token_limit_per_user:
                raise PermissionDenied(
                    detail="Maximum amount of tokens allowed per user exceeded."
                )

    def get_serializer_context(self):
        """Extra context provided to the serializer class."""
        return {"request": self.request, "format": self.format_kwarg, "view": self}

    def get_token_limit_per_user(self):
        return knox_settings.TOKEN_LIMIT_PER_USER

    def get_expiry_datetime_format(self):
        return knox_settings.EXPIRY_DATETIME_FORMAT

    def format_expiry_datetime(self, expiry):
        datetime_format = self.get_expiry_datetime_format()
        return DateTimeField(format=datetime_format).to_representation(expiry)


class UserView(RetrieveUpdateAPIView):
    """ViewSet for retrieving and updating current user instance."""

    serializer_class = UserSerializer  # For 400 or 404 responses
    permission_classes = [IsAuthenticated]  # For 403 or 404 responses

    def get_object(self):
        return self.request.user


class RegisterView(APIView):
    """Register a new user using provided credentials via allauth."""

    @sensitive_post_parameters("password")
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    @extend_schema(request=AllauthRegisterSerializer, responses={201: None})
    def post(self, *args, **kwargs):
        serializer = AllauthRegisterSerializer(
            self.request.data,
            context={
                "request": self.request,
                "format": self.format_kwarg,
                "view": self,
            },
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.save(self.request)
        complete_signup(self.request, user, allauth_settings.EMAIL_VERIFICATION, None)

        if (
            allauth_settings.EMAIL_VERIFICATION
            == allauth_settings.EmailVerificationMethod.MANDATORY
        ):
            data = {"detail": "Verification e-mail sent."}
        else:
            data = UserSerializer(instance=user).data

        return Response(data, status=status.HTTP_201_CREATED)


@extend_schema(request=None, responses=None)
class LogoutView(KnoxLogoutView):
    """Delete the session token associated with the incoming authenticated request."""

    pass


@extend_schema(request=None, responses=None)
class LogoutAllView(KnoxLogoutAllView):
    """Delete all session tokens associated with the authenticated user."""

    pass


# Email


class EmailVerifyView(APIView):
    """Verify email address using random key sent in confirmation email."""

    authentication_classes = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["email"],
        request=EmailVerifySerializer,
        responses={
            200: inline_serializer(
                "EmailIsVerified",
                fields={
                    "detail": serializers.CharField(
                        default="E-mail verification is successful."
                    )
                },
            ),
            404: OpenApiResponse(description="Invalid confrimation key."),
        },
    )
    def post(self, *args, **kwargs):
        serializer = EmailVerifySerializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        key = serializer.validated_data["key"]

        emailconfirmation = EmailConfirmationHMAC.from_key(key)

        if not emailconfirmation:
            try:
                emailconfirmation = (
                    EmailConfirmation.objects.all_valid()
                    .select_related("email_address__user")
                    .get(key=key.lower())
                )
            except EmailConfirmation.DoesNotExist:
                raise NotFound

        emailconfirmation.confirm(self.request)

        return Response({"detail": "E-mail verification is successful."})


class EmailResendVerificationView(APIView):
    """Resend email verification to the passed email (if it exists and is not verified already)."""

    authentication_classes = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["email"],
        request=EmailResendVerificationSerializer,
        responses={
            200: inline_serializer(
                "EmailResendVerificationView",
                fields={
                    "detail": serializers.CharField(default="Verification e-mail sent.")
                },
            ),
        },
    )
    def post(self, *args, **kwargs):
        serializer = EmailResendVerificationSerializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        email_address = EmailAddress.objects.filter(email=email).first()
        if email_address and not email_address.verified:
            email_address.send_confirmation(self.request)

        return Response({"detail": "Verification e-mail sent."})


# Password


class PasswordResetView(APIView):
    """Request password reset via email."""

    authentication_classes = []
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["password"],
        request=PasswordResetSerializer,
        responses={
            200: inline_serializer(
                "PasswordResetView",
                fields={
                    "detail": serializers.CharField(
                        default="Password reset e-mail has been sent."
                    )
                },
            ),
        },
    )
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetSerializer(
            data=request.data,
            context={
                "request": self.request,
                "format": self.format_kwarg,
                "view": self,
            },
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        # Return the success message with OK HTTP status
        return Response(
            {"detail": "Password reset e-mail has been sent."},
        )


class PasswordResetConfirmView(APIView):
    """Reset password using uid and key sent in email."""

    authentication_classes = []
    permission_classes = [AllowAny]

    @method_decorator(sensitive_post_parameters("new_password"))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    @extend_schema(
        tags=["password"],
        request=PasswordResetConfirmSerializer,
        responses={
            200: inline_serializer(
                "PasswordResetConfirmView",
                fields={
                    "detail": serializers.CharField(
                        default="Password has been reset with the new password."
                    )
                },
            ),
        },
    )
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetConfirmSerializer(
            data=request.data,
            context={
                "request": self.request,
                "format": self.format_kwarg,
                "view": self,
            },
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Password has been reset with the new password."})


class PasswordChangeView(APIView):
    """Change password using active session token and old password."""

    permission_classes = [IsAuthenticated]

    @method_decorator(sensitive_post_parameters("old_password", "new_password"))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    @extend_schema(
        tags=["password"],
        request=PasswordChangeSerializer,
        responses={
            200: inline_serializer(
                "PasswordChangeView",
                fields={
                    "detail": serializers.CharField(
                        default="New password has been saved."
                    )
                },
            ),
        },
    )
    def post(self, request, *args, **kwargs):
        serializer = PasswordChangeSerializer(
            data=request.data,
            context={
                "request": self.request,
                "format": self.format_kwarg,
                "view": self,
            },
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "New password has been saved."})


# Social


class SocialLoginView:
    pass


class SocialConnectView:
    pass


class SocialAccountListView:
    pass


class SocialAccountDisconnectView:
    pass
