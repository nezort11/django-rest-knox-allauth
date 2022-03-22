from allauth import app_settings as allauth_settings
from allauth.account.utils import complete_signup
from django.contrib.auth.signals import user_logged_in
from django.utils import timezone
from django.views.decorators.debug import sensitive_post_parameters
from knox.models import AuthToken
from knox.settings import knox_settings
from knox.views import LogoutAllView as KnoxLogoutAllView
from knox.views import LogoutView as KnoxLogoutView
from rest_framework import status
from rest_framework.exceptions import PermissionDenied
from rest_framework.generics import CreateAPIView, RetrieveUpdateAPIView
from rest_framework.mixins import RetrieveModelMixin, UpdateModelMixin
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.serializers import DateTimeField
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from .serializers import (
    AllauthLoginSerializer,
    AllauthRegisterSerializer,
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


class LogoutView(KnoxLogoutView):
    """Delete the session token associated with the incoming authenticated request."""

    pass


class LogoutAllView(KnoxLogoutAllView):
    """Delete all session tokens associated with the authenticated user."""

    pass


# Password management


class PasswordResetView:
    pass


class PasswordResetConfirmView:
    pass


class PasswordChangeView:
    pass


# Email management


class EmailVerifyView:
    pass


class EmailResendVerificationView:
    pass


# Social authentication/management


class SocialLoginView:
    pass


class SocialConnectView:
    pass


class SocialAccountListView:
    pass


class SocialAccountDisconnectView:
    pass
