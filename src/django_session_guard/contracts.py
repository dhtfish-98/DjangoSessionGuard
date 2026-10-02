"""Fixed Django 5.2 static projection contract and hard resource ceilings."""
from dataclasses import dataclass, fields

DEFAULTS = {
    "MIDDLEWARE": (), "INSTALLED_APPS": (),
    "SESSION_ENGINE": "django.contrib.sessions.backends.db",
    "SESSION_COOKIE_SECURE": False, "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SAMESITE": "Lax", "CSRF_USE_SESSIONS": False,
    "CSRF_COOKIE_SECURE": False, "CSRF_COOKIE_HTTPONLY": False,
    "CSRF_COOKIE_SAMESITE": "Lax",
}
SESSION = "django.contrib.sessions.middleware.SessionMiddleware"
CSRF = "django.middleware.csrf.CsrfViewMiddleware"
AUTH = "django.contrib.auth.middleware.AuthenticationMiddleware"
LOGIN = "django.contrib.auth.middleware.LoginRequiredMiddleware"
REMOTE = "django.contrib.auth.middleware.RemoteUserMiddleware"
PERSISTENT = "django.contrib.auth.middleware.PersistentRemoteUserMiddleware"
COMMON = "django.middleware.common.CommonMiddleware"
KNOWN_MIDDLEWARE = frozenset((SESSION, CSRF, AUTH, LOGIN, REMOTE, PERSISTENT, COMMON,
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.gzip.GZipMiddleware",
    "django.middleware.http.ConditionalGetMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django.middleware.cache.UpdateCacheMiddleware",
    "django.middleware.cache.FetchFromCacheMiddleware"))
SESSION_APPS = frozenset(("django.contrib.sessions", "django.contrib.sessions.apps.SessionsConfig"))
KNOWN_APPS = SESSION_APPS | frozenset(("django.contrib.admin", "django.contrib.auth",
    "django.contrib.contenttypes", "django.contrib.messages", "django.contrib.staticfiles",
    "django.contrib.admin.apps.AdminConfig", "django.contrib.auth.apps.AuthConfig",
    "django.contrib.contenttypes.apps.ContentTypesConfig",
    "django.contrib.messages.apps.MessagesConfig", "django.contrib.staticfiles.apps.StaticFilesConfig"))
KNOWN_ENGINES = frozenset("django.contrib.sessions.backends." + x for x in
    ("db", "cached_db", "cache", "file", "signed_cookies"))

@dataclass(frozen=True)
class Limits:
    file_bytes: int = 262144
    tokens: int = 20000
    token_bytes: int = 8192
    nodes: int = 20000
    depth: int = 32
    items: int = 512
    bindings: int = 1024
    steps: int = 50000
    findings: int = 100
    report_bytes: int = 65536

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or not 1 <= value <= field.default:
                raise ValueError("limits must be positive integers within hard ceilings")
        if self.report_bytes < 2048:
            raise ValueError("report budget must be at least 2048 bytes")

class ReviewError(Exception):
    def __init__(self, code, location=None, findings=None):
        self.code, self.location, self.findings = code, location, findings
        super().__init__(code)
