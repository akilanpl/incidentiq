# IncidentIQ

**Operational intelligence that learns from every incident.**

Every incident leaves knowledge. IncidentIQ remembers.

IncidentIQ is an AI incident investigation workspace for SRE, DevOps and backend engineering teams.
It combines structured incident understanding, persistent operational memory, evidence-backed recommendations,
and engineer-reviewed feedback in a lightweight local application.

Built with Python, FastAPI, vanilla JavaScript, Groq, Hindsight Cloud and optional Prometheus telemetry.

## Run this checkout

```bash
./run.sh serve
```

Open **http://127.0.0.1:8000** and sign in with the locally configured operator. The helper selects `.venv/bin/python`
and binds the server to localhost. Stop an existing server before starting another on port 8000.

For a fresh installation only, use Python 3.11+:

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
# Only if .env does not exist: copy .env.example to .env, then enter API keys locally.
.venv/bin/python -m scripts.setup_operator
./run.sh serve
```

**Never overwrite an existing `.env`.** API settings remain there. The operator setup helper writes a separate,
Git-ignored `.env.auth` with mode `0600`, using `getpass`, a unique salt, `hashlib.scrypt`, and a random session secret.
It stores no plaintext password. Restart after configuration changes. No default username/password is supplied.

Authentication configuration: `INCIDENTIQ_AUTH_ENABLED`, `INCIDENTIQ_USERNAME`, `INCIDENTIQ_PASSWORD_SALT`,
`INCIDENTIQ_PASSWORD_HASH`, `INCIDENTIQ_SESSION_SECRET`. Live mode defaults to authentication enabled and fails
closed until setup is complete. Sessions use signed HttpOnly, SameSite=Strict cookies with 8-hour expiry and constant-time
signature checks. Logout revocations persist locally across restarts. Login attempts are limited to five per minute
per local client. Secure cookies are disabled because this MVP runs on localhost HTTP. This is not enterprise RBAC.

## Workspace

The dark, responsive three-panel interface includes dashboard metrics, recent investigations, searchable/filterable
history, memory search and reflection, analytics, local settings, an operator menu, collapsible sidebar and mobile
inspector. Metrics come from the real local history store. Provider indicators come from observed API operations;
bank/model-list connectivity is distinguished from successful inference. Unknown measurements remain unknown.

Every saved investigation includes its sanitised submission, structured understanding, source memories and IDs,
retrieval events, measured stage timings, public AI conclusions/recommendations, retention status and engineer-feedback
history. Clicking a saved investigation reopens that actual record. Refresh and server restarts preserve history.
Old pre-upgrade reports are not fabricated into transcripts; local history starts with requests recorded by this version.

## Investigation pipeline

1. Redact common text secrets; validate optional screenshot content/size and require operator review of its pixels.
2. Groq extracts structured facts, hypotheses, signatures and missing evidence before retrieval. Screenshots and text
   use one combined vision-understanding pass when an image is supplied.
3. Up to three distinct signature/symptom/dependency queries search genuine Hindsight Cloud memory. SDK operations
   remain on the dedicated execution thread; no unsafe parallel SDK/event-loop calls were introduced.
4. Merge duplicate source IDs/documents while preserving original fact IDs. Bound the evidence context to 11,000
   serialised characters. Service/environment compatibility, source verification and age are checked. Verified
   cross-service incidents can be used as explicitly labelled analogies, never proof of the current root cause.
5. Groq produces a schema-validated investigation with real source citations, ranked hypotheses, uncertainty,
   diagnostic checks, expected observations, remediation risks and resolution checks. Invalid reports receive one
   bounded repair attempt; unsupported citations or unavailable inference are not retained as learning.
6. **Only after recall and reasoning**, synchronously retain separate unverified `kind:incident_intake` and
   `kind:investigation_advice` records in Hindsight. Disabling historical recall does not disable classified learning.
7. Engineer-approved resolution is retained separately using the existing `kind:incident`, `status:verified`,
   `source:engineer-feedback` classification, with failed approaches separately recorded as `kind:dead-end`.

Intake and advice are excluded from confirmed diagnostic evidence. Verification is engineer attestation, not an
independent telemetry assertion. Current incidents stay open until the engineer explicitly verifies recovery.

All new investigations bypass evidence caching. Repeated workspace memory searches can use a bank/workspace-scoped
60-second cache; **Force fresh recall** bypasses it. Only source evidence is cached, never final diagnoses. Verified
resolution writes invalidate retrieval caches. Query events distinguish real API calls from cached evidence.

## Screenshots

Up to three PNG, JPEG and WebP images are supported: 5 MB each, 10 MB aggregate and 20 million pixels each. MIME/magic/content are checked with Pillow;
embedded metadata is removed before processing. Images are processed in memory and are not stored in local history
or Hindsight. Only extracted, redacted structured evidence and MIME/size metadata are retained.

`qwen/qwen3.8-27b` is documented for vision by [Groq](https://console.groq.com/docs/vision), was available in the
account, and passed a real synthetic screenshot request. The complete screenshot → Hindsight → Groq → learning
workflow also passed through the authenticated HTTP API and browser upload control.

Pixel secrets cannot be automatically redacted: the operator must review screenshots before uploading. Text secret
redaction is best-effort pattern matching, not comprehensive secret detection.

## Tests and live verification

```bash
./run.sh test
./run.sh smoke --learning-loop
.venv/bin/python -m compileall -q .
node --check app/static/workspace.js
node --check app/static/login.js
```

The smoke command makes real API calls and writes labelled synthetic Cloud memories. It verifies the preferred
model against the account model list and selects an available fallback ID. In this account, real JSON inference passed
with `openai/gpt-oss-120b` and fallback `openai/gpt-oss-20b`. `requirements.lock` records installed versions.

Evidence files under `docs/` include:

- `upgrade_gate.json`: real Incident A → confirmed resolution → differently worded, different-service Incident B with citations.
- `upgrade_image_e2e.json`: real combined screenshot/text investigation and verified outcome.
- `vision_verification.json`: real multimodal request and extracted error schema.
- `upgrade_classification.json`: actual Cloud recall confirming intake/advice/unverified versus resolution/verified metadata.
- `upgrade_restart.json`: actual server restart preserves history and confirmed Cloud memory; real cache/force-refresh results.
- `upgrade_final_live.json`: new cross-service investigation after restart, real citations, new classified retention.
- `live_verification.json`: official Cloud retain/semantic recall and fresh-client learning loop.

These tests use explicitly synthetic incidents. They are not real production outcomes or diagnostic-accuracy benchmarks.

## Storage and API

`data/investigations.json` is the small atomic JSON history store, protected by the local operator session. Runtime
history, revocations, auth configuration and API credentials are Git-ignored. Atomic writes use temporary files,
fsync and replace, with a process lock. Run one application process; multi-process shared-file history is unsupported.
The persistent operational memory remains in Hindsight Cloud bank `incidentiq-sre`, not in this JSON history file.

Auth: `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/session`.
Protected workspace: `/api/dashboard`, `/api/providers`, `/api/providers/check`, `/api/investigations`,
`/api/investigations/{id}`, `/api/memory/search`.
Existing `/api/ask`, `/api/resolve`, `/api/preference`, `/api/patterns` remain available and protected.
`/api/ask` accepts optional `image_data` (base64 data URL) and `image_reviewed:true`. `/api/resolve` accepts
`conversation_id`, confirmed cause/fix/outcome and `verified:true`; feedback scope must match its saved investigation.

Offline mode (`./run.sh offline`) is explicitly test-only, with FakeMemory and deterministic templates. It never
counts as Cloud/Groq verification. Live mode does not silently substitute offline providers.

No production commands, external identity service, multi-tenant RBAC or enterprise compliance claims are included.
The optional Prometheus adapter queries configured read-only metrics; without a real endpoint and queries, recovery
remains ENGINEER_ATTESTED and telemetry is TELEMETRY_NOT_CONFIGURED. Keep the app on localhost and review every remediation.

## Final remediation

The app now supports up to three images (5 MB each, 10 MB total), mandatory sanitised-evidence approval, local admin/responder/viewer roles and an optional read-only Prometheus verifier. Existing operator credentials are migrated; manage additional users in Settings. Independent recovery is not claimed without real configured metrics. See docs/RELEASE_TEST_REPORT.md for release acceptance evidence and limitations.


## Local access and evidence review

On an unconfigured installation, the first-run page creates an administrator without a default password.
Existing operator credentials migrate to ignored `data/users.json`; Settings lets admins create local accounts.
Admin manages users and all features; responder investigates and records feedback; viewer is read-only.
Backend authorization enforces these roles. The terminal setup helper resets its named account and rotates the
session secret while preserving other users. Do not run multiple application processes against these local files.

Before external processing, `/api/evidence/preview` produces sanitised evidence and a short-lived signed approval
bound to the user, operation, sanitised content and image hashes. The engineer must inspect and explicitly approve
that preview. Image pixels require separate human review; no automatic screenshot secret removal is claimed.
IncidentIQ uses automated sensitive-data detection and redaction, with mandatory human review before external
processing. Redaction is best-effort and cannot guarantee detection of every secret.

## Optional telemetry and provider status

Configure `PROMETHEUS_URL`, optional bearer token, and the query/threshold variables in `.env.example` locally.
Only these configured expressions reach GET `/api/v1/query`. All configured finite numeric checks must pass for
`VERIFIED_BY_TELEMETRY`; failed, absent or invalid results are `NOT_VERIFIED`. Without configuration, the adapter
reports `TELEMETRY_NOT_CONFIGURED`; engineer-confirmed resolution is `ENGINEER_ATTESTED`.
No production endpoint was supplied for this release, so independent recovery is not verified.

Header provider panels show app-observed states, timestamps and operation counts. Groq usage comes from actual
responses and rate-limit headers; it is not an individual key credit balance. Hindsight billing/usage links open
its Cloud dashboard. No undocumented billing API is queried and no remaining credits are invented.

## Release freeze

The local release is identified by tag `incidentiq-mvp-v1.0.0` only after the release gates pass. See
`docs/RELEASE_TEST_REPORT.md`. Feature development is closed; changes to the frozen release require an explicit
new development cycle. There is no public deployment. The architecture remains FastAPI + static HTML/CSS/JS,
local JSON history/auth, Groq inference and persistent Hindsight Cloud memory on a dedicated SDK thread.
For the tested dependency set install `requirements.lock` in a Python 3.12 virtual environment. Run one process.
Limitations: local prototype identity, no enterprise identity/RBAC or compliance guarantee, best-effort text
redaction, manual pixel privacy review, no real production telemetry verification, and synthetic incident tests
rather than a diagnostic-accuracy benchmark. Installed Codex visual inspection was blocked by Computer Use;
the IncidentIQ browser workspace itself was manually inspected on desktop and mobile.

## License and acknowledgements

MIT licensed. Includes work from [Recurrence](https://github.com/francisreubenr-rvu/recurrence) by Aryan Dubey, Francis Reuben R, Gopreeth Saharsh and Rohith AD. Copyright and permission notices are preserved in [LICENSE](LICENSE).

## Local Prometheus demo

See [demo/prometheus/README.md](demo/prometheus/README.md). The exporter exposes synthetic metrics only. With `PROMETHEUS_DEMO=1`, passing demo checks never establishes production recovery. Configuration is stored separately in ignored `.env.telemetry`.
