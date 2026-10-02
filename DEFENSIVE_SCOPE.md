# Defensive scope

Purpose: review a desensitized local static settings snapshot for selected
session/CSRF cookie misconfiguration and order/storage dependencies. Reports
are observations of a fixed policy projection, not proof of exploitability,
actual settings loaded, browser behavior, authentication or a secure site.

The tool reads exactly one local regular file. It does not start Django,
import a settings module, run eval/exec, inspect installed project modules,
load arbitrary AppConfig or middleware, resolve environment variables, access
network services, unpack archives, use stdin or write back configuration.
O_NOFOLLOW protects the leaf only; parent symlink resolution is documented.
Regular file snapshots and all processing/report budgets are bounded.
The reader requires matching device/inode/size/mtime/ctime, regular-file type
and exact read length. This detects snapshot inconsistencies; it does not
establish a transactional filesystem snapshot.

The modeled constants use execution order and supported mutable-list alias
semantics. Unsupported potentially executing syntax invalidates all trusted
bindings/defaults. Unresolved names/items are unknown; explicit negative
selected settings can still produce a known static FAIL while coverage is
incomplete. Later static assignments after a barrier are evaluated under the
small grammar but the report retains OPEN coverage. Unknown branches are not
guessed or executed. Dynamic subclass behavior, annotations and imports are
not silently interpreted as safe.
Even operators inside the supported grammar invalidate trusted values when
their operands may invoke unknown Python callbacks. Plain unknown references
and unexpanded list items retain finite evidence. Whole-source semantic
compilation follows token/AST budgets and discards the resulting code object
without execution. Compile-time errors and parser/compiler warnings are OPEN;
warnings cannot print source text to stderr.

Only selected standard identities and ten settings are considered. All view
decorators/exemptions, error view token usage, frontend DOM integration, real
request/session lifecycle, async behavior, cache/migrations/storage, HTTPS,
browser SameSite choices, all other security checks and general middleware
ordering remain outside this model. Global CSRF middleware listing does not
prove every view has CSRF protection. Session-backed CSRF requires token
integration just as cookie-backed CSRF does; that application integration is
included in the always-OPEN runtime deployment field.

Findings use fixed labels and setting names, numeric Python byte/line locations
or fixed JSON pointers. Unknown module names, settings values, source paths
and snippets are never echoed. Parse/read errors use fixed codes. JSON input
is a caller assertion of a complete static projection; it is not extracted
from a running app. An artifact hash does not anonymize content or establish
ownership. New MIT work and upstream BSD provenance are attributed separately;
CVP admission remains OPEN, without promises based solely on a repository.
