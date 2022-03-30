from drf_spectacular.extensions import OpenApiAuthenticationExtension
from drf_spectacular.plumbing import build_bearer_security_scheme_object
from knox.settings import knox_settings


class KnoxSessionTokenScheme(OpenApiAuthenticationExtension):
    target_class = "knox.auth.TokenAuthentication"
    name = "tokenAuth"
    match_subclasses = True
    priority = -1

    def get_security_definition(self, auto_schema):
        return build_bearer_security_scheme_object(
            header_name="Authorization",
            token_prefix=knox_settings.AUTH_HEADER_PREFIX,
        )
