import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import builtins
import stat
from contextlib import redirect_stderr
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch
from django_session_guard import Limits, review_settings
from django_session_guard.contracts import SESSION, CSRF, AUTH, LOGIN, REMOTE, COMMON, DEFAULTS
from django_session_guard.review import serialize

SAFE = {"MIDDLEWARE": [SESSION, CSRF, AUTH], "INSTALLED_APPS": ["django.contrib.sessions"],
        "SESSION_COOKIE_SECURE": True, "CSRF_COOKIE_SECURE": True}

class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "settings.py"
    def tearDown(self):
        self.temporary.cleanup()
    def run_source(self, source, **kwargs):
        self.path.write_text(source, encoding="utf-8")
        before = self.path.read_bytes()
        result = review_settings(self.path, django_version="5.2", **kwargs)
        self.assertEqual(before, self.path.read_bytes())
        return result
    def settings(self, overrides=None, **kwargs):
        settings = SAFE | (overrides or {})
        return self.run_source("\n".join(name + " = " + repr(value) for name, value in settings.items()), **kwargs)
    def rule(self, report, name):
        return next(item for item in report["findings"] if item["rule"] == name)
    def test_safe_static_projection(self):
        report = self.settings()
        self.assertEqual((report["status"], report["complete"]), ("PASS", True))
        self.assertEqual(report["runtime_deployment"], "OPEN")
        self.assertEqual(report["cvp_eligibility"], "OPEN")
    def test_frozen_defaults(self):
        report = self.run_source("MIDDLEWARE=" + repr([SESSION, CSRF]) + "\nINSTALLED_APPS=['django.contrib.sessions']")
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(self.rule(report, "session_secure")["location"], {"origin": "Django-5.2-default"})
        self.assertEqual(self.rule(report, "session_httponly")["status"], "PASS")
        self.assertEqual(self.rule(report, "csrf_secure")["status"], "FAIL")
    def test_session_boolean_flags(self):
        for field in ("SESSION_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY"):
            with self.subTest(field=field):
                report = self.settings({field: False})
                self.assertEqual(report["status"], "FAIL")
        for value in (1, 0, "True", None):
            with self.subTest(value=value):
                report = self.settings({"SESSION_COOKIE_SECURE": value})
                self.assertEqual(self.rule(report, "session_secure")["status"], "OPEN")
    def test_same_site_case_insensitive(self):
        for value in ("lax", "LaX", "STRICT"):
            with self.subTest(value=value):
                self.assertEqual(self.settings({"SESSION_COOKIE_SAMESITE": value})["status"], "PASS")
    def test_same_site_omission_and_cross_site(self):
        for value in (False, None, "", "None", "nOnE", True, 1, "typo"):
            with self.subTest(value=value):
                report = self.settings({"SESSION_COOKIE_SAMESITE": value})
                self.assertEqual(self.rule(report, "session_samesite")["status"], "OPEN")
        report = self.settings({"SESSION_COOKIE_SECURE": False, "SESSION_COOKIE_SAMESITE": "None"})
        self.assertEqual((report["status"], report["complete"]), ("FAIL", False))
    def test_csrf_httponly_is_not_mandatory(self):
        self.assertEqual(self.rule(self.settings(), "csrf_httponly")["status"], "PASS")
        report = self.settings({"CSRF_COOKIE_HTTPONLY": True})
        self.assertEqual(self.rule(report, "csrf_httponly")["reason"], "dom_token_integration_unverified")
        self.assertEqual(report["status"], "OPEN")
    def test_csrf_cookie_modes(self):
        report = self.settings({"CSRF_USE_SESSIONS": True, "CSRF_COOKIE_SECURE": False,
                                "CSRF_COOKIE_HTTPONLY": True, "CSRF_COOKIE_SAMESITE": False})
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(self.rule(report, "csrf_cookie_flags")["status"], "NA")
        self.assertEqual(self.rule(report, "session_before_session_csrf")["status"], "PASS")
        self.assertEqual(self.settings({"CSRF_USE_SESSIONS": None})["status"], "OPEN")
    def test_no_global_csrf_leaves_view_coverage_open(self):
        report = self.settings({"MIDDLEWARE": [SESSION, AUTH]})
        self.assertEqual(report["status"], "OPEN")
        self.assertEqual(self.rule(report, "csrf_middleware")["reason"], "view_decorators_and_custom_protection_unverified")
    def test_session_csrf_order_and_missing_session(self):
        for middleware in ([CSRF, SESSION], [CSRF]):
            with self.subTest(middleware=middleware):
                report = self.settings({"MIDDLEWARE": middleware, "CSRF_USE_SESSIONS": True})
                self.assertEqual(report["status"], "FAIL")
    def test_session_common_error_view_order(self):
        report = self.settings({"MIDDLEWARE": [COMMON, SESSION, CSRF], "CSRF_USE_SESSIONS": True})
        self.assertEqual(self.rule(report, "session_before_common_error_views")["status"], "FAIL")
        report = self.settings({"MIDDLEWARE": [SESSION, COMMON, CSRF], "CSRF_USE_SESSIONS": True})
        self.assertEqual(report["status"], "PASS")
    def test_auth_dependency(self):
        for middleware in ([AUTH, SESSION, CSRF], [CSRF, AUTH]):
            with self.subTest(middleware=middleware):
                self.assertEqual(self.rule(self.settings({"MIDDLEWARE": middleware}), "session_before_auth")["status"], "FAIL")
    def test_login_dependency(self):
        report = self.settings({"MIDDLEWARE": [SESSION, CSRF, LOGIN, AUTH]})
        self.assertEqual(self.rule(report, "auth_before_login_required")["status"], "FAIL")
        self.assertEqual(self.settings({"MIDDLEWARE": [SESSION, CSRF, AUTH, LOGIN]})["status"], "PASS")
    def test_remote_user_dependencies(self):
        self.assertEqual(self.settings({"MIDDLEWARE": [SESSION, CSRF, AUTH, REMOTE]})["status"], "PASS")
        report = self.settings({"MIDDLEWARE": [SESSION, AUTH, REMOTE, CSRF]})
        self.assertEqual(self.rule(report, "csrf_before_remote")["status"], "FAIL")
        report = self.settings({"MIDDLEWARE": [SESSION, CSRF, REMOTE, AUTH]})
        self.assertEqual(self.rule(report, "auth_before_remote")["status"], "FAIL")
    def test_duplicate_middleware(self):
        report = self.settings({"MIDDLEWARE": [SESSION, SESSION, CSRF, AUTH]})
        self.assertEqual(self.rule(report, "middleware_duplicate")["status"], "FAIL")
    def test_engine_app_dependencies(self):
        for engine in ("db", "cached_db"):
            with self.subTest(engine=engine):
                report = self.settings({"INSTALLED_APPS": [], "SESSION_ENGINE": "django.contrib.sessions.backends." + engine})
                self.assertEqual(self.rule(report, "session_backend_app")["status"], "FAIL")
        for engine in ("cache", "file", "signed_cookies"):
            with self.subTest(engine=engine):
                report = self.settings({"INSTALLED_APPS": [], "SESSION_ENGINE": "django.contrib.sessions.backends." + engine})
                self.assertEqual(report["status"], "PASS")
        self.assertEqual(self.settings({"SESSION_ENGINE": "private.Backend"})["status"], "OPEN")
    def test_session_app_config_supported(self):
        self.assertEqual(self.settings({"INSTALLED_APPS": ["django.contrib.sessions.apps.SessionsConfig"]})["status"], "PASS")
    def test_custom_app_cannot_prove_db_session_app_absent(self):
        report = self.settings({"INSTALLED_APPS": ["private.AppConfig"]})
        self.assertEqual(self.rule(report, "session_backend_app")["status"], "OPEN")
        self.assertNotIn("private.AppConfig", serialize(report))
    def test_custom_middleware_and_unknown_shapes(self):
        report = self.settings({"MIDDLEWARE": [SESSION, "private.Session", CSRF, AUTH]})
        self.assertEqual(report["status"], "OPEN")
        self.assertNotIn("private.Session", serialize(report))
        self.assertEqual(self.settings({"MIDDLEWARE": "not_a_sequence"})["status"], "OPEN")
    def test_no_session_components_not_forced_secure(self):
        report = self.settings({"MIDDLEWARE": [CSRF], "INSTALLED_APPS": [], "SESSION_COOKIE_SECURE": False})
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(self.rule(report, "session_cookie_activity")["status"], "NA")
    def test_alias_list_mutation_updates_selected_location(self):
        source = "BASE=[" + repr(SESSION) + "]\nMIDDLEWARE=BASE\nBASE += [" + repr(CSRF) + "]\nINSTALLED_APPS=['django.contrib.sessions']\nSESSION_COOKIE_SECURE=True\nCSRF_COOKIE_SECURE=True"
        report = self.run_source(source)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(self.rule(report, "csrf_middleware")["location"]["line"], 3)
    def test_tuple_rebinding_does_not_mutate_old_alias(self):
        source = "BASE=(" + repr(SESSION) + ",)\nMIDDLEWARE=BASE\nBASE += (" + repr(CSRF) + ",)\nINSTALLED_APPS=['django.contrib.sessions']\nSESSION_COOKIE_SECURE=True\nCSRF_COOKIE_SECURE=True"
        self.assertEqual(self.run_source(source)["status"], "OPEN")
    def test_concat_stars_strings_and_constant_branch(self):
        source = "P='django.contrib.sessions.'\nBASE=[P+'middleware.SessionMiddleware']\nif not False:\n MIDDLEWARE=[*BASE]+[" + repr(CSRF) + "]\nelse:\n raise Exception('not executed')\nINSTALLED_APPS=['django.contrib.sessions']\nSESSION_COOKIE_SECURE=True\nCSRF_COOKIE_SECURE=True"
        self.assertEqual(self.run_source(source)["status"], "PASS")
    def test_duplicate_assignments_use_last_static_binding(self):
        report = self.settings()
        source = self.path.read_text() + "\nSESSION_COOKIE_SECURE=False\nSESSION_COOKIE_SECURE=True\n"
        self.assertEqual(self.run_source(source)["status"], "PASS")
    def test_signed_integer_constants_are_not_boolean_flags(self):
        for value in ("-1", "+1", "-True"):
            with self.subTest(value=value):
                prefix = "\n".join(k + "=" + repr(v) for k, v in SAFE.items())
                report = self.run_source(prefix + "\nSESSION_COOKIE_SECURE=" + value)
                self.assertEqual(self.rule(report, "session_secure")["status"], "OPEN")
    def test_cli_argument_privacy_and_deleted_capabilities(self):
        for arguments in (("--django-version", "private-value"), ("--update", "private-value"), ("--disarm", "private-value")):
            result = subprocess.run([sys.executable, "-m", "django_session_guard", *arguments], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "DjangoSessionGuard: invalid_cli_arguments\n")
    def test_unknown_branch_invalidates_defaults_and_bindings(self):
        source = "\n".join(k + "=" + repr(v) for k, v in SAFE.items()) + "\nif ENV:\n SESSION_COOKIE_SECURE=False"
        report = self.run_source(source)
        self.assertEqual(report["status"], "OPEN")
        self.assertIn("unknown_branch", serialize(report))
    def test_calls_imports_attributes_and_mutations_never_execute(self):
        marker = self.root / "SHOULD_NOT_EXIST"
        malicious = "open(" + repr(str(marker)) + ",'w').write('payload')"
        prefix = "\n".join(k + "=" + repr(v) for k, v in SAFE.items())
        for suffix in (malicious, "import private_package", "BASE.append('private')", "MIDDLEWARE[0]='private'", "X=object.attribute", "X=object[0]", "del MIDDLEWARE", "def callback():\n pass"):
            with self.subTest(suffix=suffix):
                self.assertEqual(self.run_source(prefix + "\n" + suffix)["status"], "OPEN")
                self.assertFalse(marker.exists())
    def test_method_mutation_cannot_keep_alias_pass(self):
        source = "BASE=[" + repr(SESSION) + "]\nMIDDLEWARE=BASE\nBASE.append(" + repr(CSRF) + ")\nSESSION_COOKIE_SECURE=True\nCSRF_COOKIE_SECURE=True"
        self.assertEqual(self.run_source(source)["status"], "OPEN")
    def test_unresolved_item_preserves_known_adverse_rule(self):
        report = self.run_source("MIDDLEWARE=[" + repr(SESSION) + ", UNKNOWN]\nSESSION_COOKIE_SECURE=False")
        self.assertEqual((report["status"], report["complete"]), ("FAIL", False))
    def test_unsupported_annotations_legacy_and_operators(self):
        for suffix in ("SESSION_COOKIE_SECURE: bool = True", "MIDDLEWARE_CLASSES=[]", "X=[x for x in []]", "X=True and False"):
            with self.subTest(suffix=suffix):
                prefix = "\n".join(k + "=" + repr(v) for k, v in SAFE.items())
                self.assertEqual(self.run_source(prefix + "\n" + suffix)["status"], "OPEN")
    def test_private_values_are_not_reported(self):
        token = "secret-account-exact-value"
        report = self.settings({"SESSION_ENGINE": token})
        source = self.path.read_text() + "\nSECRET_KEY=" + repr(token) + "\nSECRET_KEY_FALLBACKS=[" + repr(token) + "]\n"
        report = self.run_source(source)
        text = serialize(report)
        self.assertNotIn(token, text)
        self.assertNotIn(str(self.path), text)
        self.assertNotIn("SECRET_KEY", text)
    def test_non_ascii_byte_location(self):
        source = "LABEL='中文'\n" + "\n".join(k + "=" + repr(v) for k, v in SAFE.items())
        report = self.run_source(source)
        loc = self.rule(report, "csrf_middleware")["location"]
        self.assertEqual(loc, {"line": 2, "byte_column": 0, "byte_offset": len("LABEL='中文'\n".encode())})
    def test_unicode_string_separators_and_crlf_offsets(self):
        for prefix in ("LABEL='x\u2028y'\n", "LABEL='x\x85y'\n", "LABEL='中文'\r\n"):
            with self.subTest(prefix=prefix):
                source = prefix + "\n".join(k + "=" + repr(v) for k, v in SAFE.items())
                report = self.run_source(source)
                self.assertEqual(report["status"], "PASS")
                self.assertEqual(self.rule(report, "csrf_middleware")["location"]["byte_offset"], len(prefix.encode()))
    def test_declared_encoding_bom_and_bare_cr_are_open(self):
        for prefix in ("# coding: latin-1\n", "\ufeff", "# coding: unknown-codec\n", "# coding: base64_codec\n", "# coding: rot_13\n", "X=1\r"):
            source = prefix + "\n".join(k + "=" + repr(v) for k, v in SAFE.items())
            self.assertEqual(self.run_source(source)["status"], "OPEN")
        source = "# coding: UTF8\n" + "\n".join(k + "=" + repr(v) for k, v in SAFE.items())
        self.assertEqual(self.run_source(source)["status"], "PASS")
    def test_syntax_errors_keep_numeric_locations(self):
        report = self.run_source("X=1\nif (\n")
        self.assertEqual(report["error"]["location"]["line"], 2)
        report = self.run_source('{"x":"中文",}', input_format="json")
        self.assertEqual(report["error"]["location"]["line"], 1)
        # CPython versions point to the comma or the following closing brace.
        self.assertIn(report["error"]["location"]["byte_offset"], (13, 14))
    def test_json_projection_and_unknown_key(self):
        document = {"schema_version": 1, "django_version": "5.2", "settings": SAFE}
        self.assertEqual(self.run_source(json.dumps(document), input_format="json")["status"], "PASS")
        document["settings"] = SAFE | {"private-setting": "private-value"}
        report = self.run_source(json.dumps(document), input_format="json")
        self.assertEqual(report["status"], "OPEN")
        self.assertNotIn("private-value", serialize(report))
    def test_json_schema_duplicates_numbers_and_bad_unicode(self):
        for source in ('{"schema_version":1,"schema_version":1}', '{"schema_version":true,"django_version":"5.2","settings":{}}', '{"schema_version":1,"django_version":"6.0","settings":{}}', '{"x":NaN}', '{"x":1.2}', '{"x":"\\ud800"}', '[]'):
            with self.subTest(source=source):
                report = self.run_source(source, input_format="json")
                self.assertEqual((report["status"], report["complete"]), ("OPEN", False))
                self.assertIn("error", report)
    def test_syntax_encoding_and_archives_rejected(self):
        for source in ("if (", "X='\\ud800'", "SESSION_COOKIE_SECURE=True #\x00"):
            self.assertEqual(self.run_source(source)["status"], "OPEN")
        for raw in (b'\xff', b'PK\x03\x04', b'%PDF-1.7'):
            self.path.write_bytes(raw)
            self.assertEqual(review_settings(self.path, django_version="5.2")["status"], "OPEN")
    def test_profile_and_limits_api_are_explicit(self):
        for version in ("6.0", "5.2.17", False, None):
            self.assertEqual(review_settings(self.path, django_version=version)["status"], "OPEN")
        for limits in (False, 0, {}, "bad"):
            with self.subTest(limits=limits), self.assertRaises(TypeError):
                review_settings(self.path, django_version="5.2", limits=limits)
        for kwargs in ({"file_bytes": 0}, {"nodes": False}, {"depth": 33}, {"report_bytes": 1024}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                Limits(**kwargs)
    def test_local_paths_only_and_leaf_symlink(self):
        self.path.write_text("pass")
        link = self.root / "link"; link.symlink_to(self.path)
        for path in ("-", "https://invalid/settings.py", self.root, link, self.root / "missing"):
            with self.subTest(path=path):
                report = review_settings(path, django_version="5.2")
                self.assertEqual(report["status"], "OPEN")
                if len(str(path)) > 2:
                    self.assertNotIn(str(path), serialize(report))
        fifo = self.root / "pipe"; os.mkfifo(fifo)
        self.assertEqual(review_settings(fifo, django_version="5.2")["error"]["code"], "regular_file_required")
    def test_parent_symlink_is_explicitly_permitted(self):
        self.path.write_text("\n".join(k + "=" + repr(v) for k, v in SAFE.items()))
        parent = self.root / "parent"; parent.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(review_settings(parent / self.path.name, django_version="5.2")["status"], "PASS")
    def test_resource_budgets(self):
        cases = [("X='123456'", Limits(file_bytes=4)), ("X='123456'", Limits(token_bytes=4)),
            ("A=1\nB=2", Limits(tokens=2)), ("A=[[[1]]]", Limits(depth=2)),
            ("A=1", Limits(nodes=2)), ("A=[1,2]", Limits(items=1)),
            ("A=1\nB=2", Limits(bindings=1)), ("A=1", Limits(steps=1)),
            ("A='abc'+'def'", Limits(token_bytes=5)), ("A=[1]\nA+=[2]", Limits(items=1))]
        for source, limits in cases:
            with self.subTest(source=source, limits=limits):
                report = self.run_source(source, limits=limits)
                self.assertEqual((report["status"], report["complete"]), ("OPEN", False))
                self.assertIn("budget", report["error"]["code"])
    def test_json_depth_node_and_item_budgets(self):
        for source, limits in (("[[[1]]]", Limits(depth=2)), ('{"a":1,"b":2}', Limits(nodes=2)), ('{"a":[1,2]}', Limits(items=1))):
            report = self.run_source(source, input_format="json", limits=limits)
            self.assertEqual(report["status"], "OPEN")
            self.assertIn("budget", report["error"]["code"])
    def test_findings_and_report_budgets_preserve_known_fail(self):
        report = self.settings({"SESSION_COOKIE_HTTPONLY": False}, limits=Limits(findings=1))
        self.assertEqual((report["status"], report["complete"]), ("FAIL", False))
        self.assertEqual(report["findings"][0]["rule"], "session_httponly")
        report = self.settings({"SESSION_COOKIE_SECURE": False,
            "MIDDLEWARE": [SESSION, COMMON, CSRF, AUTH, LOGIN, REMOTE,
                "django.contrib.auth.middleware.PersistentRemoteUserMiddleware"],
            "CSRF_USE_SESSIONS": True}, limits=Limits(report_bytes=2048))
        self.assertEqual((report["status"], report["complete"]), ("FAIL", False))
        self.assertLessEqual(len(serialize(report).encode()), 2048)
    def test_unknown_assignment_diagnostic_bounded(self):
        report = self.run_source("A=MISSING\nB=OTHER", limits=Limits(findings=1))
        self.assertEqual(report["error"]["code"], "finding_budget")
    def test_no_import_eval_exec_or_network(self):
        # Runtime implementation imports only its own modules and the stdlib.
        with patch("builtins.eval", side_effect=AssertionError), patch("builtins.exec", side_effect=AssertionError):
            self.assertEqual(self.settings()["status"], "PASS")
    def test_whole_source_compile_semantics_even_in_dead_branches(self):
        prefix = "\n".join(k + "=" + repr(v) for k, v in SAFE.items())
        for statement in ("return", "continue", "break", "nonlocal PRIVATE_NAME",
                          "await PRIVATE_NAME", "yield PRIVATE_NAME"):
            with self.subTest(statement=statement):
                report = self.run_source(prefix + "\nif False:\n " + statement)
                self.assertEqual((report["status"], report["complete"]), ("OPEN", False))
                self.assertEqual(report["error"]["code"], "python_semantic_error")
                self.assertEqual(report["error"]["location"], {"line": 6})
                self.assertNotIn("PRIVATE_NAME", serialize(report))
    def test_compiler_gate_follows_ast_budget_and_discards_code(self):
        with patch("django_session_guard.input.compile", create=True,
                   side_effect=AssertionError("semantic compile must follow AST budget")):
            report = self.run_source("A=1", limits=Limits(nodes=2))
            self.assertEqual(report["error"]["code"], "ast_budget")
        marker = self.root / "SHOULD_NOT_EXECUTE"
        prefix = "\n".join(k + "=" + repr(v) for k, v in SAFE.items())
        with patch("django_session_guard.input.compile", create=True, wraps=builtins.compile) as gate:
            report = self.run_source(prefix + "\nif False:\n open(" + repr(str(marker)) + ", 'w')")
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(gate.call_count, 1)
            self.assertEqual(gate.call_args.kwargs, {"dont_inherit": True})
        self.assertFalse(marker.exists())
    def test_unknown_operators_invalidate_reassigned_trusted_settings(self):
        prefix = "from unknown import x\n" + "\n".join(
            k + "=" + repr(v) for k, v in (DEFAULTS | SAFE).items())
        cases = {"[]+x": "unknown_operator_effects", "x+[]": "unknown_operator_effects",
                 "[*x]": "unknown_iteration_effects", "(*x,)": "unknown_iteration_effects",
                 "not x": "unknown_truth_effects", "-x": "unknown_operator_effects",
                 "+x": "unknown_operator_effects", "not ([]+x)": "unknown_truth_effects"}
        for expression, code in cases.items():
            with self.subTest(expression=expression):
                report = self.run_source(prefix + "\nOTHER=" + expression)
                self.assertEqual(report["status"], "OPEN")
                self.assertIn(code, serialize(report))
                self.assertNotIn("PASS", [item["status"] for item in report["findings"]
                    if item["rule"] in ("session_secure", "csrf_secure")])
    def test_plain_unknown_name_items_preserve_known_negative_evidence(self):
        prefix = "from unknown import x\n" + "\n".join(
            k + "=" + repr(v) for k, v in (DEFAULTS | SAFE | {"SESSION_COOKIE_SECURE": False}).items())
        for expression in ("x", "[x]", "(x,)", "[*[x]]", "[x]+[]"):
            with self.subTest(expression=expression):
                report = self.run_source(prefix + "\nOTHER=" + expression)
                self.assertEqual((report["status"], report["complete"]), ("FAIL", False))
                self.assertEqual(self.rule(report, "session_secure")["status"], "FAIL")
                self.assertNotIn("unknown_operator_effects", serialize(report))
                self.assertNotIn("unknown_iteration_effects", serialize(report))
    def test_nested_effect_cannot_rebind_previously_captured_alias(self):
        prefix = "from unknown import x\n" + "\n".join(
            k + "=" + repr(v) for k, v in (DEFAULTS | SAFE).items())
        for suffix in ("A=MIDDLEWARE\nMIDDLEWARE=A+[not x]",
                       "MIDDLEWARE += [not x]", "MIDDLEWARE=[*MIDDLEWARE, not x]",
                       "MIDDLEWARE=([*MIDDLEWARE]+[not x])+[" + repr(AUTH) + "]"):
            with self.subTest(suffix=suffix):
                report = self.run_source(prefix + "\n" + suffix)
                self.assertEqual((report["status"], report["complete"]), ("OPEN", False))
                self.assertEqual(self.rule(report, "csrf_middleware")["status"], "OPEN")
                self.assertEqual(self.rule(report, "middleware_shape")["status"], "OPEN")
    def test_parser_and_compile_warnings_are_private_open(self):
        prefix = "\n".join(k + "=" + repr(v) for k, v in SAFE.items())
        for suffix in ('PRIVATE_LABEL="PRIVATE_SENTINEL\\z_ACCOUNT"',
                       'PRIVATE_LABEL = 1 is 1'):
            with self.subTest(suffix=suffix), redirect_stderr(StringIO()) as stderr:
                report = self.run_source(prefix + "\n" + suffix)
                self.assertEqual((report["status"], report["complete"]), ("OPEN", False))
                self.assertEqual(report["error"]["code"], "python_compile_warning")
                self.assertEqual(report["error"]["location"], {"line": 5})
                self.assertEqual(stderr.getvalue(), "")
                self.assertNotIn("PRIVATE_SENTINEL", serialize(report))
    def test_short_read_fault_is_open_and_input_unchanged(self):
        prefix = "\n".join(k + "=" + repr(v) for k, v in (DEFAULTS | SAFE).items()) + "\n"
        raw = (prefix + "SESSION_COOKIE_SECURE=False\n").encode()
        self.path.write_bytes(raw)
        self.assertEqual(review_settings(self.path, django_version="5.2")["status"], "FAIL")
        real_fdopen = os.fdopen
        class ShortStream:
            def __init__(self, fd, mode): self.stream = real_fdopen(fd, mode)
            def __enter__(self): return self
            def __exit__(self, *args): return self.stream.__exit__(*args)
            def fileno(self): return self.stream.fileno()
            def read(self, maximum): return self.stream.read(maximum)[:len(prefix.encode())]
        with patch("django_session_guard.input.os.fdopen", side_effect=ShortStream):
            report = review_settings(self.path, django_version="5.2")
        self.assertEqual(report["error"]["code"], "input_changed")
        self.assertEqual((report["status"], report["complete"]), ("OPEN", False))
        self.assertEqual(self.path.read_bytes(), raw)
    def test_after_read_identity_and_file_type_faults_are_open(self):
        raw = "\n".join(k + "=" + repr(v) for k, v in SAFE.items()).encode()
        self.path.write_bytes(raw)
        real_fstat = os.fstat
        for field, replacement in (("st_dev", -1), ("st_ino", -1), ("st_mode", stat.S_IFDIR)):
            calls = []
            def changed(fd):
                result = real_fstat(fd); calls.append(fd)
                if len(calls) == 2:
                    data = {name: getattr(result, name) for name in
                            ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")}
                    data[field] = replacement
                    return SimpleNamespace(**data)
                return result
            with self.subTest(field=field), patch("django_session_guard.input.os.fstat", side_effect=changed):
                report = review_settings(self.path, django_version="5.2")
            self.assertEqual(report["error"]["code"], "input_changed")
            self.assertEqual(self.path.read_bytes(), raw)
    def test_cli_exit_status_and_json_only_stdout(self):
        for overrides, code, status in (({}, 0, "PASS"), ({"SESSION_COOKIE_SECURE": False}, 1, "FAIL"), ({"SESSION_ENGINE": "private"}, 2, "OPEN")):
            self.settings(overrides)
            result = subprocess.run([sys.executable, "-m", "django_session_guard", str(self.path), "--django-version", "5.2"], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, code)
            self.assertEqual(json.loads(result.stdout)["status"], status)
            self.assertEqual(result.stderr, "")

if __name__ == "__main__":
    unittest.main()
