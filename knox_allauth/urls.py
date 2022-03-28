from django.urls import path, re_path

from .views import LoginView, LogoutAllView, LogoutView, RegisterView, UserView

urlpatterns = [
    path(r"login/", LoginView.as_view(), name="rest_login"),
    path(r"me/", UserView.as_view(), name="rest_user"),
    path(r"register/", RegisterView.as_view(), name="rest_register"),
    path(r"logout/", LogoutView.as_view(), name="rest_logout"),
    path(r"logout/all/", LogoutAllView.as_view(), name="rest_logout_all"),
    # Password management
    path(r"password/reset/", lambda: None, name="rest_password_reset"),
    path(r"password/reset/confirm/", lambda: None, name="rest_password_reset_confirm"),
    path(r"password/change/", lambda: None, name="rest_password_change"),
    # Email verification
    path(r"email/verify/", lambda: None, name="rest_email_verify"),
    re_path(
        r"email/confirm/(?P<key>[-:\w]+)/$", lambda: None, name="rest_email_confirm"
    ),
    path(r"email/verify/sent/", lambda: None, name="rest_email_verify_sent"),
    # Social authentication
    # ...
]
