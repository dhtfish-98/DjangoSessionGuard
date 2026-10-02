"""Selected session/CSRF policies. Findings never contain source values."""
from .bindings import UNKNOWN
from .contracts import (SESSION, CSRF, AUTH, LOGIN, REMOTE, PERSISTENT, COMMON,
    SESSION_APPS, KNOWN_APPS, KNOWN_MIDDLEWARE, KNOWN_ENGINES, ReviewError)

def evaluate(values, locations, diagnostics, limits):
    findings = []
    complete = not diagnostics

    def add(rule, status, setting, reason, related=()):
        nonlocal complete
        if status == "OPEN":
            complete = False
        item = {"rule": rule, "status": status, "setting": setting, "reason": reason,
                "location": locations.get(setting, {"origin": "Django-5.2-default"})}
        if related:
            item["related_locations"] = [locations.get(name, {"origin": "Django-5.2-default"}) for name in related]
        if len(findings) >= limits.findings:
            raise ReviewError("finding_budget", locations.get(setting), findings + [item])
        findings.append(item)

    def sequence(name, known):
        value = values[name]
        if value.kind not in ("list", "tuple"):
            add(name.lower() + "_shape", "OPEN", name, "static_sequence_required")
            return [], False
        entries = [item.data for item in value.data if item.kind == "str"]
        understood = len(entries) == len(value.data) and all(entry in known for entry in entries)
        if not understood:
            add(name.lower() + "_components", "OPEN", name, "custom_or_unknown_component")
        # Core duplicate checks are a configuration policy, not a Django syntax error.
        if name == "MIDDLEWARE" and any(entries.count(entry) > 1 for entry in
                (SESSION, CSRF, AUTH, LOGIN, REMOTE, PERSISTENT)):
            add("middleware_duplicate", "FAIL", name, "duplicate_selected_core_middleware")
        return entries, understood

    middleware, middleware_complete = sequence("MIDDLEWARE", KNOWN_MIDDLEWARE)
    apps, apps_complete = sequence("INSTALLED_APPS", KNOWN_APPS)

    def presence(component, entries, understood):
        return True if component in entries else False if understood else None

    session = presence(SESSION, middleware, middleware_complete)
    csrf = presence(CSRF, middleware, middleware_complete)
    session_app = True if any(app in SESSION_APPS for app in apps) else False if apps_complete else None
    active = True if session is True or session_app is True else False if session is False and session_app is False else None

    def flag(name, rule):
        value = values[name]
        status = "PASS" if value.kind == "bool" and value.data is True else "FAIL" if value.kind == "bool" else "OPEN"
        add(rule, status, name, "enabled_boolean" if status == "PASS" else
            "disabled_boolean" if status == "FAIL" else "literal_boolean_required")

    def same_site(name, rule):
        value = values[name]
        if value.kind == "str" and value.data.lower() in ("lax", "strict"):
            status, reason = "PASS", "lax_or_strict_attribute"
        elif value.kind == "str" and value.data.lower() == "none":
            status, reason = "OPEN", "cross_site_intent_and_browser_deployment_unverified"
        elif value.kind == "NoneType" or (value.kind == "bool" and value.data is False) or (value.kind == "str" and value.data == ""):
            status, reason = "OPEN", "samesite_attribute_omitted"
        else:
            status, reason = "OPEN", "unsupported_samesite_value"
        add(rule, status, name, reason)

    if active is True:
        flag("SESSION_COOKIE_SECURE", "session_secure")
        flag("SESSION_COOKIE_HTTPONLY", "session_httponly")
        same_site("SESSION_COOKIE_SAMESITE", "session_samesite")
    else:
        add("session_cookie_activity", "NA" if active is False else "OPEN", "MIDDLEWARE",
            "selected_session_components_absent" if active is False else "session_activity_unknown")

    if csrf is True:
        add("csrf_middleware", "PASS", "MIDDLEWARE", "global_csrf_middleware_listed")
    else:
        add("csrf_middleware", "OPEN", "MIDDLEWARE", "view_decorators_and_custom_protection_unverified")

    use = values["CSRF_USE_SESSIONS"]
    if use.kind != "bool":
        add("csrf_storage_mode", "OPEN", "CSRF_USE_SESSIONS", "literal_boolean_required")
    elif use.data:
        add("csrf_cookie_flags", "NA", "CSRF_USE_SESSIONS", "csrf_secret_stored_in_session")
    elif csrf is True:
        flag("CSRF_COOKIE_SECURE", "csrf_secure")
        same_site("CSRF_COOKIE_SAMESITE", "csrf_samesite")
        http = values["CSRF_COOKIE_HTTPONLY"]
        if http.kind == "bool" and http.data is False:
            add("csrf_httponly", "PASS", "CSRF_COOKIE_HTTPONLY", "supported_cookie_token_access")
        else:
            add("csrf_httponly", "OPEN", "CSRF_COOKIE_HTTPONLY", "dom_token_integration_unverified" if http.kind == "bool" else "literal_boolean_required")

    def before(required, dependent, rule):
        dependent_presence = presence(dependent, middleware, middleware_complete)
        if dependent_presence is False:
            return
        required_presence = presence(required, middleware, middleware_complete)
        if dependent_presence is None or required_presence is None:
            add(rule, "OPEN", "MIDDLEWARE", "middleware_dependency_unknown")
        elif required_presence is False:
            add(rule, "FAIL", "MIDDLEWARE", "required_core_middleware_missing")
        elif not middleware_complete:
            add(rule, "OPEN", "MIDDLEWARE", "custom_middleware_may_change_dependency_semantics")
        elif middleware.index(required) < middleware.index(dependent):
            add(rule, "PASS", "MIDDLEWARE", "required_core_precedes_dependent")
        else:
            add(rule, "FAIL", "MIDDLEWARE", "required_core_follows_dependent")

    before(SESSION, AUTH, "session_before_auth")
    before(AUTH, LOGIN, "auth_before_login_required")
    for dependent, label in ((REMOTE, "remote"), (PERSISTENT, "persistent_remote")):
        before(AUTH, dependent, "auth_before_" + label)
        before(CSRF, dependent, "csrf_before_" + label)
    if use.kind == "bool" and use.data:
        if csrf is True:
            before(SESSION, CSRF, "session_before_session_csrf")
        before(SESSION, COMMON, "session_before_common_error_views")
        if session is not True:
            add("csrf_session_dependency", "FAIL" if session is False else "OPEN", "CSRF_USE_SESSIONS",
                "session_middleware_required", ("MIDDLEWARE",))

    if active is True:
        engine = values["SESSION_ENGINE"]
        if engine.kind != "str" or engine.data not in KNOWN_ENGINES:
            add("session_backend", "OPEN", "SESSION_ENGINE", "custom_or_unknown_session_backend")
        elif engine.data.endswith((".db", ".cached_db")):
            add("session_backend_app", "PASS" if session_app is True else "FAIL" if session_app is False else "OPEN",
                "INSTALLED_APPS", "database_session_app_dependency", ("SESSION_ENGINE",))
        else:
            add("session_backend_app", "NA", "SESSION_ENGINE", "selected_backend_has_no_database_app_dependency")

    for diagnostic in diagnostics:
        if len(findings) >= limits.findings:
            raise ReviewError("finding_budget", diagnostic.get("location"), findings)
        findings.append({"rule": "static_coverage", "status": "OPEN", "reason": diagnostic["code"],
                         "location": diagnostic.get("location")})
    return findings, complete
