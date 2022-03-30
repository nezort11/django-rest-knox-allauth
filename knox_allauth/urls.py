from django.urls import path, re_path

from .views import (
    EmailResendVerificationView,
    EmailVerifyView,
    LoginView,
    LogoutAllView,
    LogoutView,
    RegisterView,
    UserView,
)

urlpatterns = [
    path(r"login/", LoginView.as_view(), name="rest_login"),
    path(r"me/", UserView.as_view(), name="rest_user"),
    path(r"register/", RegisterView.as_view(), name="rest_register"),
    path(r"logout/", LogoutView.as_view(), name="rest_logout"),
    path(r"logout/all/", LogoutAllView.as_view(), name="rest_logout_all"),
    # Email
    path(r"email/verify/", EmailVerifyView.as_view(), name="rest_email_verify"),
    path(
        r"email/resend/",
        EmailResendVerificationView.as_view(),
        name="rest_email_resend",
    ),
    # Password
    path(r"password/reset/", lambda: None, name="rest_password_reset"),
    path(r"password/reset/confirm/", lambda: None, name="rest_password_reset_confirm"),
    path(r"password/change/", lambda: None, name="rest_password_change"),
    # Social (Google)
    # ...
]
