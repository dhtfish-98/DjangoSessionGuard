## Current version 0.1.1: attribution and bounded verification, 2026-10-03

New implementation author and maintainer: dhtfish98. Package version: `0.1.1`.

Required local file-open capabilities now fail closed to controlled OPEN before reading; missing, zero, None, boolean, string and floating-point flag values are covered by API/CLI regression contrasts. Normal regular files and symlink/FIFO rejection remain covered.

The current source suite passes 56 tests on Python 3.14/macOS arm64. Final wheel and sdist are built from the final files. A fresh consumer installation also passes 56 tests. Installed/source/wheel runtime bytes, licenses, retained upstream notices, RECORD and command contracts are verified separately before publication. Exact package hashes and execution receipts are recorded externally rather than embedded in this self-referential document.

These tests verify the documented finite profile. Historical native/reference measurements below are preserved; they are not new runs for this revision. Matching remote CI, actual deployments, applicant identity and CVP approval remain OPEN until separately evidenced.

## Prior verification evidence

# Validation boundaries

The selected modern Django 5.2 profile and official rule sources were fixed
before implementation; evidence/profile-gate.json records commit, source
hashes and full/partial read scope. New runtime, tests, packaging, workflow,
docs and all three complete licenses are reviewed in full. Whole upstream
projects and full Python/stdlib/dependency internals are not claimed audited.

Local source regression tests and a fresh installed-wheel consumer run cover
normal JSON/Python inputs, frozen defaults, true/false/type error cookie flags,
SameSite omission and cross-site uncertainty, CSRF cookie/session modes,
global protection gaps, session/backend/app conditions, middleware ordering,
custom component uncertainty, aliases, concatenation, tuple rebindings,
constant/unknown branches, unsupported syntax, nonexecution, byte locations,
private values, malformed inputs, path rejection and processing/output limits.
Each review fixture checks that its input bytes remain unchanged.
Regression cases also cover invalid control flow in inactive branches,
semantic compilation only after AST budgets, unknown operand callbacks after
explicit safe reassignment, finite adverse evidence from plain unknown names,
private parser/compiler warnings and controlled short-read/identity/type fault
injection. Fault injection establishes rejection of the modeled inconsistency;
it does not claim that a real operating-system short-read race was observed.

Local full result logs, source/installed identity, wheel/sdist SHA-256 and
consumer/CLI evidence are recorded in the external engineering delivery JSON.
The report distinguishes verified source/package behavior from runtime Django
or deployment behavior. No application was started and no actual settings
module, database, browser or views were loaded.

The CI workflow has been read and declares Python 3.11/3.14 checks against the
built wheel. A local passing run does not prove remote CI execution; remote
publication and exact-commit CI remain OPEN until independently confirmed.
CVP eligibility, ownership and applicant identity also remain OPEN.

Incomplete-bracket diagnostics preserve the native interpreter position: tested
CPython versions can point at the open bracket or at EOF. A separate stable
invalid-statement case checks exact source line 2. This version difference does
not change the static rule projection or normalize a parser position.
