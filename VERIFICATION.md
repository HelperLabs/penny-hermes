# Release verification

Penny for Hermes **0.1.0** was checked on October 9, 2026.

| Check | Result |
| --- | --- |
| Unit tests and real-host integration on Hermes v0.21.6 | 77 passed |
| The same suite on current Hermes main | 77 passed |
| `hermes plugins validate /path/to/penny-hermes --install-deps` on both runtimes | Passed |
| Admission security scan | Safe |
| Core override check | Passed |
| Plugin host isolation compatibility | Supported |
| `git diff --check` | Passed |
| Public Penny resource and OAuth discovery | Verified without credentials |
| README support, terms, and privacy links | HTTP 200 |
| Live independent OAuth registration, consent, PKCE callback, and token exchange | Passed |
| Live credential refresh and authenticated read after refresh | Passed |
| Live profile read through the Hermes memory manager | Passed |
| Live private note save and exact ID/content read-back | Passed |
| Live background session initialization and note recall | Passed |
| Synthetic notes moved to Trash and absent from search | Passed |
| Test refresh-token revocation and rejection of further refresh | Passed |
| Local logout and rejection before network egress | Passed |

The test command was `python -m unittest discover -s tests -q`, using each
Hermes checkout on Python's import path. Validators ran with isolated temporary
`HERMES_HOME` directories. The Hermes stable checkout was the v0.21.6 release.

Coverage includes real Hermes discovery and memory-manager routing; MCP
initialization, JSON and SSE responses, size limits, and redacted failures;
independent OAuth registration, PKCE, state and issuer checks, secure credential
storage, refresh/logout serialization, and identity-bound token use; private
recall, complete no-Space proof for older unlabeled responses, prior-query
annotations, strict save receipts, and stale-job cancellation.

Automated tests use synthetic data. A separate manual live test installed the
public source in an isolated Hermes profile and used a dedicated OAuth client.
The test found and fixed two integration issues: OAuth requests needed the
plugin's User-Agent header, and current private saves return an explicit
`saved` receipt. Both fixes have regression tests.

The live test used Hermes's installed-provider loader and memory manager to
read the profile, save a synthetic note, and retrieve the same note by ID and
exact content. Background recall also found the note. An oversized memory
context correctly requested explicit reads instead of truncating core memory.

Both synthetic notes created during diagnosis and verification were moved to
Trash. The dedicated refresh token was revoked, a forced refresh was rejected,
and local credentials were removed. JWT access-token revocation was rejected by
the authorization server; no access token was retained after logout. Personal
memory contents and credentials were excluded from the verification report and
public artifacts. No Penny product deployment was made.
