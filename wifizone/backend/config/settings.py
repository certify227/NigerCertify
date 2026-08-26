"""
Configuration Django pour WiFiZone Pro — SaaS de gestion hotspot MikroTik.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv(
    "DJANGO_SECRET_KEY",
    "django-insecure-dev-only-change-in-production",
)
DEBUG = os.getenv("DJANGO_DEBUG", "true").lower() == "true"
ALLOWED_HOSTS = [
    h.strip() for h in os.getenv("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "corsheaders",
    "drf_spectacular",
    "accounts",
    "billing",
    "routers",
    "hotspots",
    "dashboard",
    "api",
    "core",
    "support",
    "realtime",
    "channels",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "accounts.middleware.TOTPVerificationMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "billing.context_processors.subscription_context",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [
                os.getenv("CHANNEL_LAYER_URL", os.getenv("CELERY_BROKER_URL", "redis://redis:6379/1")),
            ],
        },
    },
}

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

if os.getenv("DATABASE_URL"):
    import dj_database_url

    DATABASES["default"] = dj_database_url.parse(os.getenv("DATABASE_URL"))

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "fr-fr"
TIME_ZONE = "Africa/Niamey"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "accounts.User"

LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "dashboard:home"
LOGOUT_REDIRECT_URL = "dashboard:landing"

# MikroTik — mode mock pour démo sans routeur réel
MIKROTIK_MOCK_MODE = os.getenv("MIKROTIK_MOCK_MODE", "false").lower() == "true"
MIKROTIK_DEFAULT_PORT = 8728

# Chiffrement des identifiants routeur
FERNET_KEY = os.getenv("FERNET_KEY", "")

if not ALLOWED_HOSTS or ALLOWED_HOSTS == [""]:
    ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

if DEBUG:
    ALLOWED_HOSTS += ["testserver", "0.0.0.0"]

# Email (configurer en production pour reset MDP)
EMAIL_BACKEND = os.getenv(
    "EMAIL_BACKEND",
    "django.core.mail.backends.console.EmailBackend",
)
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", "noreply@wifizone.local")

# Alertes abonnement (jours avant expiration)
SUBSCRIPTION_WARNING_DAYS = int(os.getenv("SUBSCRIPTION_WARNING_DAYS", "7"))

# REST Framework + JWT
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {"anon": "60/min", "user": "300/min"},
}

from datetime import timedelta

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=12),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=30),
}

CORS_ALLOWED_ORIGINS = os.getenv(
    "CORS_ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000",
).split(",")
CORS_ALLOW_CREDENTIALS = True

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/0")
CELERY_BEAT_SCHEDULE = {
    "check-routers-health": {
        "task": "core.tasks.check_routers_health",
        "schedule": 300.0,
    },
    "check-subscription-expiring": {
        "task": "core.tasks.check_subscription_expiring",
        "schedule": 86400.0,
    },
}

SPECTACULAR_SETTINGS = {
    "TITLE": "WiFiZone Pro API",
    "DESCRIPTION": "API REST opérateurs hotspot MikroTik",
    "VERSION": "1.0.0",
}

SMS_BACKEND = os.getenv("SMS_BACKEND", "console")
SMS_API_URL = os.getenv("SMS_API_URL", "")
SMS_API_KEY = os.getenv("SMS_API_KEY", "")
SMS_SENDER_ID = os.getenv("SMS_SENDER_ID", "WiFiZone")

# Email SMTP (production)
EMAIL_HOST = os.getenv("EMAIL_HOST", "")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "true").lower() == "true"
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")

# ---------------------------------------------------------------------------
# Production — sécurité renforcée (DJANGO_DEBUG=false)
# ---------------------------------------------------------------------------
if not DEBUG:
    from django.core.exceptions import ImproperlyConfigured

    _insecure_markers = ("django-insecure", "change-me", "dev-only")
    if any(m in SECRET_KEY.lower() for m in _insecure_markers) or len(SECRET_KEY) < 50:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY invalide pour la production. "
            "Générez une clé avec deploy/production/scripts/generate-secrets.sh"
        )
    if not FERNET_KEY:
        raise ImproperlyConfigured(
            "FERNET_KEY obligatoire en production (chiffrement mots de passe routeurs)."
        )

    SECURE_SSL_REDIRECT = os.getenv("SECURE_SSL_REDIRECT", "true").lower() == "true"
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    CSRF_COOKIE_SECURE = True
    CSRF_COOKIE_HTTPONLY = True
    SECURE_HSTS_SECONDS = int(os.getenv("SECURE_HSTS_SECONDS", "31536000"))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = "DENY"
    SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
    SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"

    CSRF_TRUSTED_ORIGINS = [
        o.strip() for o in os.getenv("CSRF_TRUSTED_ORIGINS", "").split(",") if o.strip()
    ]
    if not CSRF_TRUSTED_ORIGINS:
        raise ImproperlyConfigured(
            "CSRF_TRUSTED_ORIGINS requis en production (ex: https://votre-domaine.com)."
        )

    CORS_ALLOWED_ORIGINS = [
        o.strip() for o in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()
    ]

    for _internal in ("127.0.0.1", "web", "localhost"):
        if _internal not in ALLOWED_HOSTS:
            ALLOWED_HOSTS.append(_internal)

    SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"] = timedelta(
        hours=int(os.getenv("JWT_ACCESS_HOURS", "4"))
    )
    SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"] = timedelta(
        days=int(os.getenv("JWT_REFRESH_DAYS", "7"))
    )
    REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"] = {
        "anon": os.getenv("API_THROTTLE_ANON", "30/min"),
        "user": os.getenv("API_THROTTLE_USER", "120/min"),
    }

    LOGGING = {
        "version": 1,
        "disable_existing_loggers": False,
        "handlers": {
            "console": {"class": "logging.StreamHandler"},
        },
        "root": {"handlers": ["console"], "level": "WARNING"},
        "loggers": {
            "django.security": {"handlers": ["console"], "level": "WARNING", "propagate": False},
        },
    }
