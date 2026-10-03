> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# DjangoSessionGuard

New implementation author and maintainer: dhtfish98.

A read-only, offline review of a **caller-asserted Django 5.2** settings snapshot.
It checks selected session/CSRF cookie policies and middleware dependencies
without importing, executing, or evaluating the settings file. Django is not
a dependency. `PASS` means this selected static policy projection passed;
framework execution, views, HTTPS deployment, browser behavior and CVP
admission always remain `OPEN` in separate report fields.

```sh
python -m pip install .
django-session-guard settings.py --django-version 5.2
django-session-guard settings.json --django-version 5.2 --format json
```

The CLI prints a bounded JSON report. Exit codes are 0 for selected-policy
PASS, 1 for a known selected-policy FAIL, 2 for OPEN or invalid arguments.
It never writes the input. Only explicit local regular UTF-8 files are read;
stdin, URLs, archives and directories are unsupported. The final path
component is opened with `O_NOFOLLOW`. Parent directory symlinks follow the
operating system's normal resolution; this is **not** an authorized-root or
every-component symlink boundary. Concurrent changes detectable through file
device/inode/size/mtime/ctime are OPEN. The reader also checks regular-file
type after reading and requires the byte count to equal the snapshot size.
Reports contain the snapshot SHA-256, fixed rule
labels and locations, never input paths, source fragments or setting values.
Hashes are fingerprints, not anonymization; supply a desensitized snapshot.

Python support is a deliberately small AST grammar: primitive string, bool,
int and None literals; name bindings; list/tuple literals and static `*`
expansion; string/list/tuple `+`; matching-type `+=`; `not` on bool; and `if`
with a known literal bool. Assignment order and multiple name targets are
modeled. List aliases share changes from `+=`, while tuple/string `+=`
rebinds only its target. Integer unary signs are supported (bool is excluded).
List/tuple concatenation creates a new container.
Locations include UTF-8 byte offsets; mutable selected aliases report the
supported mutation statement. Imports, annotations, functions, methods,
attributes, subscripts, comprehensions, deletion, other operators/statements
and unknown branches are unsupported. They invalidate trusted bindings and
defaults and keep coverage OPEN. No plugins or environment substitution run.
Unknown operands to `+`, unary signs, `not` or starred iteration also invalidate
trusted bindings because Python can invoke user-defined callbacks.
An effect anywhere in an assignment invalidates its entire expression result,
including cached mutable aliases and the left side of `+=`. A plain
unknown name or an unexpanded unknown list item does not invoke such callbacks;
finite known negative evidence is retained. Inactive branches of a known bool
`if` are not interpreted, though all syntax is counted. After token and AST
budgets pass, the whole AST is compiled only to check semantic validity and
the code object is discarded. It is never executed. Invalid control-flow
declarations, including in inactive branches, are OPEN. Parser/compiler
warnings are captured and reported as a fixed OPEN code and numeric location
without printing source snippets. This is not a general Python interpreter or
settings resolver.
Python source must declare UTF-8 (or omit its encoding declaration), with LF
or CRLF newlines. BOM, other declared encodings and bare CR are OPEN.

For JSON, use this complete static projection envelope. Omitted selected
settings use frozen Django 5.2 defaults. Unknown keys, duplicate keys, floats,
non-finite values and unsupported schema/profile are OPEN.

```json
{"schema_version":1,"django_version":"5.2","settings":{
  "MIDDLEWARE":["django.contrib.sessions.middleware.SessionMiddleware",
                "django.middleware.csrf.CsrfViewMiddleware",
                "django.contrib.auth.middleware.AuthenticationMiddleware"],
  "INSTALLED_APPS":["django.contrib.sessions"],
  "SESSION_COOKIE_SECURE":true,"CSRF_COOKIE_SECURE":true
}}
```

The ten selected settings are MIDDLEWARE, INSTALLED_APPS, SESSION_ENGINE,
SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SAMESITE,
CSRF_USE_SESSIONS, CSRF_COOKIE_SECURE, CSRF_COOKIE_HTTPONLY and
CSRF_COOKIE_SAMESITE. Unknown custom app/middleware identities cannot prove
absence of a component. Only explicitly listed standard component identities
are recognized; the tool does not load them. Legacy MIDDLEWARE_CLASSES is OPEN.

For selected session app/middleware activity, Secure and HttpOnly must be
literal True. Cookie SameSite Lax/Strict is accepted case-insensitively, matching
Django's cookie writer. Python False/None/empty string omits the attribute and
is OPEN. String "None" is OPEN because cross-site intent/browser deployment
cannot be established here. Invalid values and nonliteral flags are OPEN.
CSRF HttpOnly False is the supported default; True requires front-end DOM
token integration and remains OPEN. With CSRF_USE_SESSIONS=True, CSRF cookie
flags are NA because Django stores that secret in the session. Missing global
CSRF middleware is OPEN because views/decorators are outside this input.

Dependencies checked: Session before Authentication; Authentication before
LoginRequired and both RemoteUser variants; CSRF before both RemoteUser
variants; with CSRF_USE_SESSIONS, Session present and before CSRF and listed
CommonMiddleware (potential error-view dependency). Repeated selected core
middleware is a FAIL under this configuration policy, not an assertion that
Django forbids the syntax. The built-in db/cached_db backend requires the
session app, including its standard SessionsConfig name. Built-in cache/file/
signed_cookies have no selected database app requirement; their actual
storage, migrations, signing and runtime behavior remain unverified. Custom
engines are OPEN. Cache, message, localization and other middleware dependencies
are outside these selected ordering rules.

Hard ceilings: 256 KiB input, 20,000 tokens/nodes, 8,192 bytes per token/static
string, depth 32, 512 sequence/object items, 1,024 bindings, 50,000 model steps,
100 findings and 64 KiB report. The Python API `Limits` may tighten ceilings
(minimum report budget 2 KiB); False/0/other types are rejected. Budget errors
retain OPEN, location when known, and a known policy FAIL already discovered.
The snapshot may remain in memory during review; values are never sent out.

See [ORIGIN.md](<ORIGIN.md>), [DEFENSIVE_SCOPE.md](<DEFENSIVE_SCOPE.md>),
[VALIDATION.md](<VALIDATION.md>) and [evidence/profile-gate.json](<../evidence/profile-gate.json>)
for attribution, exact reference scope and actual validation boundaries.

File input requires positive `O_NOFOLLOW` and `O_NONBLOCK` OS flags. Missing
capabilities return controlled OPEN before opening any file. POSIX behavior is
verified on macOS; native Windows behavior is not verified.
