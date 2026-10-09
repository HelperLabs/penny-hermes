# Penny for Hermes

Bring your Penny core memory and private notes into Hermes. The provider loads
your core memory, recalls relevant notes, and gives the agent three tools for
reading and saving selected memories.

Penny is made by [Helper Labs](https://mypenny.ai). This connector requires a
Penny account and Hermes **0.21.6 or later** on macOS or Linux. It has no third-party Python
dependencies.

## Install and connect

```sh
hermes plugins install HelperLabs/penny-hermes --enable
PENNY_PROFILE="${HERMES_HOME:-$HOME/.hermes}"
python "$PENNY_PROFILE/plugins/penny/penny_auth.py" login --home "$PENNY_PROFILE"
```

Open the link printed by the login command in your browser. Sign in to Penny
and authorize **Penny for Hermes**. The command waits for a local callback and
times out after three minutes. It never starts a login from an agent turn,
scheduled job, or messaging gateway.

Select Penny in your active profile's `config.yaml`:

```yaml
memory:
  provider: penny
```

Start a new Hermes conversation. Hermes selects one external memory provider at
a time; selecting Penny replaces your previous external provider for that
profile. Your built-in Hermes memory remains managed by Hermes.

For a named profile, use that profile's directory in `--home` and run Hermes in
the same profile. Each profile needs its own Penny authorization. This release
supports primary local conversations. Private memory requests from cron,
subagents, flush contexts, and messaging gateways are refused.

## Memory tools

| Tool | Purpose |
| --- | --- |
| `penny_profile` | Read your core memory and assistant persona. |
| `penny_search` | Search private notes for past work, decisions, and context. |
| `penny_remember` | Save a selected note with tags, confidence, and three questions it would answer. |

Try these prompts:

- “Read my Penny core memory before we start.”
- “Search Penny for the decisions we made about my project.”
- “Remember that I prefer meeting notes with decisions and next steps.”

Background recall keeps the agent's next turn from waiting on a network request.
It can include notes from the previous prompt, labeled with their original
query. Use `penny_search` when an answer needs a search for the current question.
If recall has not arrived, the agent can use the explicit memory tools. Long
memory responses are available through those tools; this connector keeps no
plaintext memory cache on disk.

## Data and permissions

The connector makes HTTPS requests to `app.mypenny.ai/mcp`. Login and credential
refresh use the authorization server advertised by Penny's resource discovery,
currently `clerk.mypenny.ai`. Discovery and OAuth endpoints are checked against
these fixed trusted origins; redirects do not forward credentials elsewhere.

Automatic recall sends up to the first 4,000 characters of each nontrivial local
user prompt to Penny as a search query. Explicit `penny_search` calls also send
their query. Penny receives the content of any note the agent saves through
`penny_remember`; authorize those saves under your usual Hermes approval
settings. The connector does not upload raw transcripts, assistant replies,
tool results, local files, or built-in Hermes memory. Search results from shared
Spaces are excluded. There are no Space writes, deletion tools, telemetry, or
self-updates.

Login registers a separate OAuth client for this connector. Access and refresh
tokens are stored in `<active Hermes profile>/penny/auth.json`, with a private
directory and owner-only file permissions. The connector reads and refreshes
only that file. It does not read another Penny client, vendor CLI, browser, or
system credential store. Do not copy another client's token into this file.

Retrieved notes are evidence. They do not authorize shell commands, change
approval settings, or override your current instructions. Errors omit memory
content, server response bodies, and credentials. Network requests have bounded
timeouts and response sizes; note writes are not automatically retried.

## Disconnect and update

Revoke **Penny for Hermes** in Penny's Connected apps settings to disconnect
server access. Remove the local credential with:

```sh
python "$PENNY_PROFILE/plugins/penny/penny_auth.py" logout --home "$PENNY_PROFILE"
```

Local logout removes this connector's credential file; server revocation is a
separate action. Updates use Hermes's plugin manager. Catalog releases are pinned
to an exact commit and require a reviewed catalog update.

## Development

Run the unit and real-host integration tests with Hermes on Python's import path:

```sh
PYTHONPATH=/path/to/hermes-agent python -m unittest discover -s tests -v
hermes plugins validate /path/to/penny-hermes --install-deps
```

Automated tests use synthetic responses and isolated temporary profiles. They never use
your account, saved memories, or live OAuth credentials. See
[VERIFICATION.md](VERIFICATION.md) for the checks performed for this release.

## Support

Report connector problems in this repository's Issues. Do not attach tokens,
private memories, or unredacted logs. For Penny account questions, use
[Penny support](https://mypenny.ai/contact).

The connector is MIT licensed. Penny's hosted service has its own
[terms](https://mypenny.ai/terms) and [privacy policy](https://mypenny.ai/privacy).
