# Origin and new contribution

Historical inspiration: [carljm/django-secure](https://github.com/carljm/django-secure)
at `55fb285945bbfb8af7ef4a847f4dac7d18ffe08f`. The archived README explicitly
states it was merged into Django 1.8. Selected check dispatch, session/CSRF,
old security middleware, command, settings proxy, packaging and licensing were
read completely (14 exact files listed in evidence/profile-gate.json).
Unselected decorators, docs, tests and whole upstream dependency behavior are
not claimed reviewed. The old MIDDLEWARE_CLASSES/runtime import checks and
response middleware have not been renamed into this implementation.

The supported modern profile was fixed **before runtime implementation** to
Django 5.2 LTS, source tag 5.2.17, commit
`e802ada38b3ecf345915163bb6d7f008be411664`. Modern session/CSRF deploy checks,
middleware, selected backends and SessionsConfig were read completely; only
the listed defaults and HttpResponse.set_cookie function were read from their
larger modules. Exact hashes, full/partial read scopes and official settings,
middleware, session, CSRF and deploy-check documentation are in the gate.
The official download page identifies this branch as supported through April
2028; that observation is contextual and not a promise of later availability.

New MIT implementation author and maintainer: dhtfish98. The new bounded
AST binder and mutable alias model, explicit version/static JSON contract,
dependency engine, privacy-conscious location report, error budgets, CLI and
regression tests are independent engineering contributions. The historical
checks run against imported Django settings; this tool never imports supplied
settings or Django. No full upstream feature or deployment equivalence is
claimed. No upstream implementation or test corpus is redistributed. The unused reference-only BSD license/copyright copies were removed; fixed source references remain without transferring upstream ownership.

Comparison to modern deployment checks: W010-W015 inspect session Secure/
HttpOnly with app/middleware conditions, W003 checks global CSRF middleware
and W016 checks CSRF Secure only outside CSRF_USE_SESSIONS. This tool compares
those rules and adds explicit static unknowns, SameSite behavior, frontend
token dependency and selected middleware/storage dependencies. Non-boolean
flags are OPEN instead of asserting runtime truthiness. Its selected-policy
PASS cannot replace Django's deploy checks or an application security review.

SECRET_KEY and SECRET_KEY_FALLBACKS have no secret-quality checks or retained
bindings in the Python model. The source snapshot/parser still necessarily
reads literal content; dynamic secret expressions can affect static coverage.
No X-XSS-Protection, redirects, HSTS, response headers, secret generation or
key inspection is implemented. Applicant eligibility and authorship evidence
must still be evaluated separately and remain OPEN.
