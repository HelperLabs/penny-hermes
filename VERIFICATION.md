# Release verification

Penny for Hermes **0.1.0** was checked on October 9, 2026.

| Check | Result |
| --- | --- |
| Unit tests and real-host integration on Hermes v0.21.6 | 74 passed |
| The same suite on current Hermes main | 74 passed |
| `hermes plugins validate /path/to/penny-hermes --install-deps` on both runtimes | Passed |
| Admission security scan | Safe |
| Core override check | Passed |
| Plugin host isolation compatibility | Supported |
| `git diff --check` | Passed |
| Public Penny resource and OAuth discovery | Verified without credentials |
| README support, terms, and privacy links | HTTP 200 |

The test command was `python -m unittest discover -s tests -q`, using each
Hermes checkout on Python's import path. Validators ran with isolated temporary
`HERMES_HOME` directories. The Hermes stable checkout was the v0.21.6 release.

Coverage includes real Hermes discovery and memory-manager routing; MCP
initialization, JSON and SSE responses, size limits, and redacted failures;
independent OAuth registration, PKCE, state and issuer checks, secure credential
storage, refresh/logout serialization, and identity-bound token use; private
recall, complete no-Space proof for older unlabeled responses, prior-query
annotations, strict save receipts, and stale-job cancellation.

Tests use synthetic data. **Live account authorization and an authenticated
Penny read/write round trip were not performed.** No personal memories or
credentials were used, and no product deployment was made.
