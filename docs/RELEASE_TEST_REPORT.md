# IncidentIQ MVP release validation — 2026-11-14

Release identifier: local annotated tag `incidentiq-mvp-v1.0.0`. No public deployment or upstream push.
Feature development is closed. A new development cycle must be explicitly authorized before changing the frozen release.

## Automated validation

- Complete relevant pytest suite: **106 passed**, including offline behavior, SDK mixed retain/recall concurrency and worker shutdown, sanitisation categories and nested secret fields, review-token payload/user binding, image content/size limits, authentication/session expiry/logout/origin checks, first-run setup, admin/responder/viewer backend enforcement, and mocked Prometheus healthy/failure/timeout/malformed scenarios.
- Python compile checks, three JavaScript syntax checks, shell syntax, dependency consistency and Git whitespace checks passed.
- Exact matching against locally configured API/session/password secrets found no matches in candidate tracked files. Runtime `.env`, `.env.auth`, local user hashes and history are Git-ignored. MIT LICENSE exactly matches upstream HEAD.
- Terminal operator reset regression confirms updated password reaches the active user store and preserves other accounts. Tested only against temporary files; the real operator credentials were not reset.

## Actual live checks (not mocks)

- `docs/live_verification.json`: Hindsight Cloud synchronous retain and differently worded recall recovered unique marker `INCIDENTIQ-LIVE-SMOKE-9e674f5fbbc6` from bank `incidentiq-sre` using official SDK. Groq model listing and structured understanding inference passed with `openai/gpt-oss-120b`.
- The same check retained a synthetic engineer-confirmed incident, created a fresh Hindsight client, recalled it for another incident, and generated a structured Groq recommendation citing real retrieved sources. Learning incident `INCIDENTIQ-LEARNING-2b984ddbc6`. Final reasoning used verified fallback `openai/gpt-oss-20b` after primary model HTTP 413. A preceding run failed final inference; its failure was not counted as success. The subsequent complete run passed without substituting fake providers.
- `docs/upgrade_gate.json`: earlier full Incident A investigation → confirmed feedback → differently worded/cross-service Incident B with actual citations. Earlier browser image/feedback evidence remains in `upgrade_image_e2e.json` and `remediation_e2e.json`.
- `docs/release_vision.json`: fresh actual PNG bytes reached `qwen/qwen3.8-27b`. Response recovered both `INCIDENTIQ-VISION-PROBE-20261114` and `DB_POOL_TIMEOUT`; actual request token usage is recorded. Three-image PNG/JPEG/WebP live test evidence remains in `remediation_live_probe.json`.
- `docs/release_runtime.json`: restarted final application in live mode at localhost:8000, unauthenticated access blocked, existing admin session accepted, Hindsight bank and Groq model-list connectivity passed. Model-list access is not presented as inference evidence; inference is separately recorded above.
- No Hindsight bank was cleared. No API keys or `.env` were replaced. Smoke verification no longer writes `.env`.

## Manual browser validation

Computer Use verified desktop sidebar, toolbar, main workspace, investigation composer/context panel, custom monochrome IncidentIQ mark and provider panels. Hindsight panel shows observed connection/bank/counts/timestamps and Cloud dashboard link; Groq panel scopes response usage/rate limits without invented credits. Login and logout succeeded using a temporary QA admin account that was subsequently removed. Existing operator was preserved.

At 390×844, document scroll width equalled viewport width (390px); sidebar collapsed and provider/context controls adapted. Desktop restored to 1440×900. Screenshots saved in user-facing outputs. Previous walkthrough also exercised actual text submission, sanitised review dialog, screenshot upload, engineer feedback and viewer restrictions. Installed Codex desktop app inspection was blocked by Computer Use access; no claim of that inspection is made.

## Acceptance matrix

| Gate | Result |
|---|---|
| Hindsight live retain/recall and persistence | PASS real Cloud |
| SDK dedicated-thread concurrency/cleanup | PASS regression |
| Groq understanding/reasoning | PASS real requests; fallback used on 413 |
| Screenshot validation/actual vision/marker | PASS tests + real PNG inference |
| Redaction/mandatory human review/retention sanitisation | PASS tests + reviewed HTTP/browser workflow |
| Auth/session/logout/role/origin enforcement | PASS tests + actual browser login/logout |
| Prometheus read-only adapter | PASS mocked adapter tests only |
| Independent production recovery | NOT VERIFIED: no endpoint or queries supplied |
| Live/offline distinction | PASS explicit tests; final server live |
| Responsive UI/provider panels | PASS desktop + mobile manual checks |
| Full learning demonstration | PASS actual retained resolution → subsequent cited recommendation |
| Credentials ignored/license attribution | PASS local scan + unchanged LICENSE |

## Known limitations and security posture

This is a local single-process MVP, not enterprise identity, multi-tenant security or compliance certification. Sessions are signed HttpOnly SameSite=Strict cookies with eight-hour expiry and persisted logout revocations; localhost HTTP does not use Secure cookies. Passwords use salted scrypt. Login rate limiting is local/process scoped. Admin manages local accounts; responder investigates and resolves; viewer is read-only, enforced by backend.

Text redaction covers common API keys, tokens, credential fields, private keys, connection credentials and personal data, but remains best-effort. Human approval is mandatory and bound to sanitised evidence. Screenshots require human pixel review; secrets in pixels are not automatically removed. Raw screenshots are not retained. Retained outcomes distinguish unverified advice from engineer-confirmed experience.

No real Prometheus endpoint/query policy was configured. UI reports `TELEMETRY_NOT_CONFIGURED`; engineer-confirmed outcomes are `ENGINEER_ATTESTED`, not independent telemetry verification. All release incidents are labelled synthetic; they do not measure real production diagnostic accuracy. Primary Groq request capacity can produce HTTP 413; the verified fallback can succeed, and unavailable/invalid reports remain explicit failures. Provider operation counts reset with the process and do not represent account billing. Local JSON stores support one application process. No production commands run, no public deployment exists, and the server binds only to 127.0.0.1.

## Reproduce and demonstrate

From this repository:

```bash
./run.sh test
./run.sh smoke --learning-loop
./run.sh serve
```

For fresh installation use Python 3.12, create `.venv`, install `requirements.lock`, copy `.env.example` only if `.env` does not exist, enter provider credentials locally, then create the first administrator in the local setup page. Never paste secrets into chat.

Demo: sign in → inspect provider panels → enter synthetic service/logs → inspect sanitised preview and approve → inspect understanding and actual recalled sources → record engineer-confirmed root cause/fix/failed approaches/outcome → approve sanitised feedback → submit a differently worded related incident → inspect citations of the stored resolution. Attach a reviewed synthetic PNG for the image path. Show unconfigured telemetry honestly; do not claim production recovery. Sign out when finished.

Git commit SHA is recorded in the external release manifest after the release commit; the annotated tag identifies this exact source snapshot.
