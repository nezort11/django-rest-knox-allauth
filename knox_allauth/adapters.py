from allauth.account.adapter import DefaultAccountAdapter
from django.conf import settings


class AccountAdapter(DefaultAccountAdapter):
    def get_email_confirmation_url(self, request, emailconfirmation):
        """Constructs the email confirmation (activation) url send together with email.

        The email confirmation will be handled on the frontend-side via API.
        """
        return settings.KNOX_ALLAUTH_CONFIRMATION_URL.format(key=emailconfirmation.key)

    def respond_email_verification_sent(self, request, user):
        """If the email verification was send - do nothing (don't redirect anywhere)."""
        return None

    def respond_user_inactive(self, request, user):
        """If the user is inactive - do nothing."""
        return None
