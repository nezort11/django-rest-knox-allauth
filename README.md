# django-rest-knox-allauth

Inspired by dj-rest-auth.

This can be used as an installed package or to take inspiration (code snippets
into your project).

A package that combines together:

**Package that integrates**

- django

- django-allauth

- django-rest-framework

- django-rest-knox

... and provides default API endpoints.

It support all the allauth functionality:

- authentication

- account management

- account confirmation

- social authentication

Supported functionality (API endpoints):

- Local and social registration

- Email-address management

- Password management

- Email-address verification

It provides nothing special just a boilerplate:

- serializers

- views

- urls

which all can be customized if you copy the app directly (not installing).

It tries to be smaller endpoints than dj-rest-auth.

## Alternatives

Alternative endpoints:

- django-rest-auth (not maintained)

- djoser / django-rest-knox (no registration endpoints - allauth integration)

- dj-rest-auth (doesn't support django-rest-knox)

Alternative backends:

- ...

## Installation

Either install using pip or include the app directly into your project under
source control (for customization).

The are 2 way to use this package:

1. Include it as part of your project (for customization purposes). Copy
   `knox_allauth` folder into the root of your project (near `manage.py`).

2. Install it as `pip install knox_allauth`

# Django REST knox auth

[dj-rest-auth](https://github.com/iMerica/dj-rest-auth) but only for
[django-rest-knox](https://github.com/James1345/django-rest-knox) authentication
backend.

## Problem

The problem this package is trying to solve is:

- `django-rest-knox` doesn't provide default registration serializers, views,
  urls (because registration is a very complex thing, and can be either email or
  social). You need to implement registration for it to work!

- `djnago-allauth` provides registration views, templates, models but only for
  Django not django-rest-framework's token auth. You need to add additional
  serializers, views and urls for it to work!

I need both registration (email/social) and a reliable token authentication
backend.

## Development

Create virtual environment

```sh
~/.pyenv/versions/3.10.0/bin/python -m venv .venv
source .venv/bin/activate

pip install -U pip
pip install -r requirements.txt
```

## Configuration

Configuration is the same as for allauth (settings) + for django, rest framework
and knox.

Add allauth's login backend:
`allauth.account.auth_backends.AuthenticationBackend`.

Add knox's `TokenAuthentication`, it turns request with `Authorization` header
into

## Setup

Add `allauth` and `allauth.account` to `INSTALLED_APPS`.
`allauth.social_account` is optional for social authentication (will add
additional email model).

```py
INSTALLED_APPS = [
    # For allauth
    "django.contrib.sites",
    "django.contrib.messages",
    "django.contrib.auth",
    # ...
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.google",
    "rest_framework",
    "knox",
    "knox_allauth",
    # ...
]

SITE_ID = 1
```

Add allauth's authentication backend for login management:

```py
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",  # for django.contrib.admin
    "allauth.account.auth_backends.AuthenticationBackend",
]
```

Add knox's API authentication class as default:

```py
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["knox.auth.TokenAuthentication"],
    # ...
}
```

Include knox-auth's authentication endpoints url patterns:

```py
urls = [
  path(r"api/auth/", include("knox_allauth.urls")),
]
```

In order to make allauth suitable for API user our patched account adapter:

```py
ACCOUNT_ADAPTER = "knox_allauth.adapters.AccountAdapter"
```

## Email confirmation & password reset

In order for email confirmation to work, you will need to set a frontend URL
setting (e.g. `https://frontend.com/confirm/email/{key}`). It will be formatted
with confirmation `key` and included in the confirmation message.

```py
KNOX_ALLAUTH_EMAIL_CONFIRMATION_URL = env(
    "DJANGO_KNOX_ALLAUTH_EMAIL_CONFIRMATION_URL",
    default="http://example.com/confirm/email/{key}",
)
KNOX_ALLAUTH_PASSWORD_RESET_URL = env(
    "DJANGO_KNOX_ALLAUTH_PASSWORD_RESET_URL",
    default="http://example.com/reset/password/{uid}/{key}",
)
```

Example email confirmation message:

```
Content-Type: text/plain; charset="utf-8"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Subject: [example.com] Please Confirm Your E-mail Address
From: webmaster@localhost
To: nezort@gmail.com
Date: Tue, 29 Mar 2022 08:34:10 -0000
Message-ID: <164854285092.3212.17637242588782667486@macbook-air.sknt.ru>

Hello from example.com!

You're receiving this e-mail because user nezort@gmail.com has given your e-mail address to register an account on example.com.

To confirm this is correct, go to http://example.com/confirm/email/Ng:1nZ7Io:DJvc6AMzsbprct2TqJIrouJLc2aQlgr2d64kwY0nEDg

Thank you for using example.com!
example.com
```

## Boilerplate settings

django-allauth:

```py
ACCOUNT_ADAPTER = "apps.users.adapters.AccountAdapter"
SOCIALACCOUNT_ADAPTER = "apps.users.adapters.SocialAccountAdapter"
ACCOUNT_ALLOW_REGISTRATION = env.bool("DJANGO_ACCOUNT_ALLOW_REGISTRATION", True)
ACCOUNT_AUTHENTICATION_METHOD = "email"
ACCOUNT_USER_MODEL_EMAIL_FIELD = "email"
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_EMAIL_VERIFICATION = "none"  # TODO: set to "mandatory"
ACCOUNT_USERNAME_REQUIRED = True
ACCOUNT_USERNAME_MIN_LENGTH = 2
```

django-rest-knox:

```py
from datetime import timedelta
from rest_framework.settings import api_settings

# django-rest-knox
#
REST_KNOX = {
    "AUTH_HEADER_PREFIX": "Token",
    "TOKEN_TTL": timedelta(hours=24),
    "SECURE_HASH_ALGORITHM": "cryptography.hazmat.primitives.hashes.SHA512",
    "AUTH_TOKEN_CHARACTER_LENGTH": 64,
    "TOKEN_LIMIT_PER_USER": None,
    "AUTO_REFRESH": False,
}
```

## Documentation

All API endpoints are inline documenting using `drf-spectacular`, so it's
required to install it. Here is some boilerplate settings:

```py
# drf-spectacular
#
SPECTACULAR_SETTINGS = {
    "TITLE": "Address API",
    "DESCRIPTION": "Documentation of API endpoints of Address",
    "VERSION": "1.0.0",
    "SCHEMA_PATH_PREFIX": "/api",
}
```

## Social API endpoints

Include `knox` in the setting for adding `AuthToken` database model.

### Example Google API

`allauth.socialaccount.providers.google`

## Customize

Customize serializers
