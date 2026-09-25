# AGENTS.md

This file is a quick orientation guide for coding agents working in this repository.

## Repository Purpose

This project is a Flask-based WebAuthn/FIDO2 demo and developer tool focused on:

- Simple registration and authentication flows
- Advanced WebAuthn request editing and debugging
- Post-quantum credential and algorithm experiments
- Credential inspection, attestation decoding, and metadata exploration
- A browser-based decoder for WebAuthn / CTAP structures

The repo includes both the application and a local `fido2/` library copy used by the server.

## High-Level Layout

- `server/app/`
  Flask app, route handlers, configuration, storage, attestation processing, metadata bootstrap, decoder logic.
- `frontend/templates/`
  Jinja/HTML templates for the main tabs and shared UI fragments.
- `frontend/static/scripts/`
  Frontend behavior, organized by feature area.
- `frontend/static/styles/`
  Shared and advanced-tab CSS.
- `web/`
  The new UI (Next.js 15 Pages Router, TypeScript, Tailwind CSS v4), exported as static
  files that Flask serves at `/beta` until the cutover. See "The new UI (`web/`)" below.
- `tests/`
  App, library, PQC, and optional device tests.
- `fido2/`
  Local Python FIDO2 implementation used by the app. Treat changes here as library-level changes, not normal UI work.

## Frontend Map

**The UI is moving to Next.js + Tailwind CSS in `web/` (Phases 25–30).** Read
`docs/UI_MIGRATION.md` before changing anything under `frontend/` or `web/`: it holds the owner's design
direction, the binding architecture (Pages Router static export served by Flask, the strict CSP kept) and
the content-parity rule.

### The new UI (`web/`)

Phase 25 laid the foundation; each later phase ports one surface (docs/UI_MIGRATION.md,
"Phases"). Until the cutover the legacy UI stays at `/` and the new one lives at `/beta`,
unlisted.

- `web/src/pages/`: `index.tsx` (the app shell), `design.tsx` (the unlisted
  `/beta/design` review page: every component in every state), `404.tsx`, `500.tsx`
  and `_error.tsx` (Next's own error pages use style attributes the CSP refuses),
  `_app.tsx` (Geist and Geist Mono from the `geist` package, self-hosted through
  `next/font/local`; the fonts' variables sit on a wrapper holding `#app-root` and
  `#overlay-root`, so portalled overlays inherit them) and `_document.tsx`.
- `web/src/styles/globals.css`: the design tokens (`@theme`). Tailwind's palette,
  type scale, radii and shadows are cleared first, so only named tokens exist: white
  surfaces, grey only as text and hairlines, one accent, semantic tints, shadows for
  floating layers (and the segmented highlight). Text fields carry `data-text-field`
  and show no focus effect; every other control keeps the `:focus-visible` ring. The
  `hover-or-demo` / `focus-or-demo` / `active-or-demo` variants let the design page
  show a state still through `data-demo`.
- `web/src/components/ui/`: the primitives (Button and IconButton, the text fields
  and Select, Switch, ToggleChip, SegmentedControl, Card, Badge and StatusChip,
  Overlay with Dialog / Drawer / Sheet, Toast, InfoPopover, the table primitives,
  MonoValue, KeyValueGrid). `SegmentedControl` moves its one highlight through the
  CSSOM (`element.style`) from a ref, never a `style` prop.
- `web/src/components/shell/`: the header (title, the four sections, Analyze Browser,
  GitHub; the phone menu sheet below 900 px), the footer, the sections' panels.
  `web/src/lib/useSection.ts` keeps the section in the URL hash (`#simple`,
  `#advanced`, `#codec`, `#mds`) with `replaceState`.
- `web/src/components/analyze-browser/`: the first ported surface, over the logic
  modules in `frontend/static/scripts/shared/browser/`, imported through the
  `@legacy/*` alias (`experimental.externalDir`), never copied. They move into
  `web/` at the cutover. `docs/ui-parity/analyze-browser.md` maps every item of the
  old panel to the new one.
- `web/scripts/check-export-csp.mjs`: parses every HTML file of the export and
  fails on an inline script that would run, a `<style>`, a style attribute, an `on*`
  attribute, a `javascript:` URL or a script or stylesheet from outside `/beta/`.
- `web/e2e/`: Playwright in Chromium. `serve-flask.mjs` starts Flask with every store
  in a temporary directory; `virtual-authenticator.ts` adds a CTAP2 authenticator
  through the DevTools WebAuthn domain; `fixtures.ts` fails a test on any console
  error, page error, CSP violation or report. `simple-ceremony.spec.ts` registers and
  authenticates on the current UI at `/`; `beta-smoke.spec.ts` covers `/beta`.

Rules for `web/src` (`tests/app/tooling/test_web_source_rules.py` holds them):
no `style` prop (the export would render a style attribute), no
`dangerouslySetInnerHTML` or other markup sink, no `<style>` / `<script>`, no
`next/script`, no `eval`, nothing written to `window`, no `atob`, and no copy of
the logic modules' exports or sentences. No `Suspense` on the server-rendered path:
React would put an inline script in the export. Links to the current UI are plain
`<a href="/">` (`next/link` adds `/beta`).

Running it locally (Node 22):

- `cd web && npm ci`
- `npm run dev`: the dev server at `http://localhost:3000/beta`, proxying `/api` to
  Flask at `FLASK_URL` (default `http://localhost:8000`, `python -m server.app.app`).
  WebAuthn ceremonies need the Flask origin; use the export for those.
- `npm run build`: the export in `web/out`, which Flask serves at `/beta`
  (`FIDO_SERVER_WEB_EXPORT_ROOT` points elsewhere). Without a build `/beta` is a 404.
- `npm run typecheck`, `npm test` (vitest, jsdom, Testing Library),
  `npm run test:coverage` (with the floors in `web/vitest.config.mts`),
  `npm run check:csp` (after a build), and `npm run e2e` (after a build; Chromium
  once with `npx playwright install chromium`; `E2E_PYTHON` names the Python with
  the app's dependencies, `.venv/bin/python` by default).

### The current UI (`frontend/`)

The app is a multi-tab UI wired together from `frontend/static/scripts/main.js`.

Important frontend entry points:

- `frontend/static/scripts/simple/auth-simple.js`
  Simple register/authenticate flows.
- `frontend/static/scripts/advanced/auth/advanced.js`
  Advanced register/authenticate flows.
- `frontend/static/scripts/advanced/credentials/index.js`
  Shared saved-credential list, card rendering, credential detail modal, list refresh behavior.
- `frontend/static/scripts/advanced/editor/index.js`
  Advanced JSON editor state and synchronization.
- `frontend/static/scripts/shared/ui/navigation.js`
  Top-level tab switching and advanced sub-tab switching.
- `frontend/static/scripts/shared/storage/local.js`
  Browser-side stored credential records and serialization sent back to the server.
- `frontend/static/styles/shared/layout.css`
  Shared layout and credential card animation styles.
- `frontend/static/scripts/shared/browser/`
  The Analyze Browser panel (header button). It reports what the browser says and
  says where each answer came from, or that it cannot know; it never guesses.
  `identity.js` copies what the browser exposes (`readIdentityInputs`) and names the
  browser, version, engine and system from that copy (`determineIdentity`, a pure
  function): a brand's version is never another brand's, "Google Chrome" only when
  the brand list says so, "Chromium-based browser" for a list of only Chromium.
  `webauthn-facts.js` asks the WebAuthn questions and keeps each answer in one of
  four states (`yes`, `no`, `unavailable` when the method is missing, `undetermined`
  when it threw, with why); it also reads `getClientCapabilities()`. `report.js`
  gathers both, groups the capabilities, builds the report and copies it, with no
  DOM: the new UI imports it too. `analyze.js` renders the legacy panel and handles
  its dialog (focus in, Tab kept inside, Escape, focus back to the button). `probe.js` reads an API that
  may be missing or throw. Web pages cannot ask which authenticator transports a
  browser supports: do not reintroduce WebUSB/WebHID/Web Bluetooth/Web Serial
  checks, which say nothing about WebAuthn. The identity cases are real
  user-agent strings with their Client Hints in
  `tests/frontend/shared/browser/identity-matrix.js`; add a browser there.
- `frontend/static/scripts/shared/ui/dom.js`
  How every view that shows data is built: `el(tag, {className, attrs, dataset,
  style, text}, ...children)` and `fragment()`. Strings become text nodes or
  attribute values, never markup, and an `on*`, `innerHTML`, `outerHTML` or `srcdoc`
  attribute throws; handlers are added with `addEventListener`. The `style` option
  is applied through CSSOM (`element.style`), which the CSP allows. No script hands
  the browser markup to parse -- no `innerHTML`/`outerHTML`, `insertAdjacentHTML`,
  `document.write`, `DOMParser`, even with a fixed string, since each is a Trusted
  Types sink; empty a container with `replaceChildren()` (see Testing Guidance). The
  credential cards, the credential detail modal (`credential-detail-runtime/`,
  `detail-nodes.js`), the registration result and its certificate / authenticator-data
  sub-modal (`registration-compose-runtime.js`) and the MDS raw-data popup
  (`advanced/mds/raw-window.js`, an `about:blank` window that shares the page's CSP,
  styled by `styles/advanced/mds-raw-window.css`) are built this way.
- `frontend/static/scripts/shared/ui/actions.js`
  How a template control does something. The markup names the action,
  `data-action="switch-tab"`, with any argument in another `data-*` attribute
  (`data-tab="codec"`), and never holds code: there is no inline `on*=` handler and
  nothing is put on `window`. The module that owns the behaviour exports a table
  (`navigationActions`, `formActions`, `codecActions`, ...) and a `bind...Actions()`
  that calls `bindActions(root, table)`: one delegated listener on the root of the
  area its controls sit in -- the tab, or `document` when they span areas (the
  sticky mini-header shows a clone of the top navigation) -- so a table entry never
  fires twice. `callWith(fn, 'tab')` makes the usual entry; an entry may also be
  `{ mouseenter, mouseleave }` (the info popups), dispatched only for the element
  that names the action. A disabled control is skipped. `main.js` calls the binders
  when it loads; a click before then does nothing. Names are local to their area, as
  the Analyze Browser panel's `close` / `copy-report` are.
  `tests/frontend/page-actions.test.js` renders the real templates
  (`tests/frontend/page-template.js`), loads `main.js` and checks that every
  `[data-action]` runs exactly its owner's entry; add a new owner's table there.
- `frontend/static/scripts/shared/utils/page-data.js`
  The page's data for its scripts: `index.html` renders
  `<script type="application/json" id="initial-mds-info">`, which the browser never
  runs, and `readPageData(id)` parses it. `initial-mds-snapshot` and
  `initial-credential-records` are read the same way; the server renders neither
  (the page reads the browser's storage), tests give theirs through
  `tests/frontend/page-data-helper.js` (`setup.js` writes the defaults).
- Registration detail snapshots (`registrationDetailSnapshot`, schemaVersion 2) hold
  the registration as data -- `state` (decoded attestation, certificates,
  authenticator data) and `response` (`credential`, `relyingParty`) -- never markup.
  `snapshot-sanitize.js` keeps each `response` part whole or drops it; the detail modal
  builds from a v2 snapshot without a request and otherwise hydrates the credential
  from its server artifact. Composed HTML from older versions, and the raw
  `registrationDetailHtml`-style keys, are never read.
- `frontend/static/scripts/shared/api/failed-response.js`
  The one reader of a failed response, for both tabs, the codec and the decode
  request: `readFailedResponse(response)` gives the server's `error` (or short plain
  text; never an HTML page), `failedCredentialId`, `signCountStatus`,
  `challengeSource`, `challengeStatus` and the body, and adds what to do for a 400
  about the ceremony state, 409, 413 and 503 unless the message already says;
  `FailedResponseError` carries it. Do not show a raw response body.
- `frontend/static/scripts/shared/ui/ceremony-result.js`
  The panel under each tab's buttons (`#simple-ceremony-result`,
  `#advanced-ceremony-result`) that says what the server made of the last ceremony:
  the signature counter with a sentence for `ok`, `not-supported` and `regressed`
  (a possible clone; a warning), and in the advanced tab where the challenge came
  from (`challengeSource`, `challengeStatus`). Not a `.status` toast: it stays until
  the next ceremony starts.
- `frontend/static/scripts/shared/utils/base64.js`
  Bytes on the wire are base64url, unpadded, in every field the server sends; a
  field named for base64 (`derBase64`, `publicKeyBase64`, `userHandleBase64`, the
  codec's `base64` views) is standard base64. Decode API data with the strict
  `base64UrlToBytes` (or `base64ToBytes` for such a field): one spelling per byte
  string, anything else throws `Base64Error`. `forgivingBase64ToBytes` does what
  `atob` did and is only for text a person typed (the editor's helpers in
  `binary.js` use it). No `atob` outside the vendored `shared/webauthn/json-ponyfill.js`.
- `frontend/static/scripts/shared/storage/local/record-migration.js`
  Brings records saved by earlier versions to today's format as they are read
  (`storage-core.js`, and artifacts in `hydrateCredentialFromServer`), persisting
  when anything changed: drops stored registration markup, and re-spells standard
  base64 as base64url in the known byte fields (`credentialId`, `publicKey`,
  `publicKeyBytes`, `userHandle`, `publicKeyCose` strings, `attestationStatement`
  byte strings). Fields named for base64, extension outputs and properties are left
  alone. Add a step here, with an old-format fixture in
  `tests/frontend/shared/storage/`, when a stored format changes.

Important templates:

- `frontend/templates/simple/tab.html`
- `frontend/templates/advanced/tab.html`
- `frontend/templates/decoder/tab.html`
- `frontend/templates/shared/navigation.html`
- `frontend/templates/shared/analyze-browser.html` (the panel's test renders this file)

## Backend Map

Flask app setup starts in:

- `server/app/app.py`
  The WSGI entry point, `server.app.app:app = create_app()`, in a checkout and in
  the image alike: the Dockerfile copies `server/app` to `/app/server/app`, so every
  module has one import path. Do not add `server.X` / `server.app.X` fallbacks.
- `server/app/factory.py`
  `create_app(config=None)` builds a fresh, fully configured app: settings from
  each config submodule's `config_from_env()`, then the `config` overrides, then
  `INIT_STEPS` in order (logging, secret, ProxyFix, gzip, security headers, static
  assets, blueprints, RP warning). `tests/app/core/test_app_factory.py` pins the
  order; changing it is a behaviour change.
- `server/app/config/`
  What `create_app()` is built from: `application.py` (`build_app()`),
  `logs.py`, `session_secret.py`, `compression.py`, `proxy.py`,
  `session_cookie.py`, `security_headers.py` (a strict CSP -- `script-src 'self'`,
  `style-src 'self' https://fonts.googleapis.com`, no `'unsafe-inline'` -- plus a
  `Content-Security-Policy-Report-Only` with `require-trusted-types-for 'script'`,
  both reporting to `/api/csp-report` by `report-uri` and, through
  `Reporting-Endpoints`, `report-to`; each settable in the environment, and
  `FIDO_SERVER_CONTENT_SECURITY_POLICY` replaces the whole enforced policy),
  `origins.py`, `attestation_trust.py`,
  `mds.py`, `relying_party.py` (RP ID, `create_fido_server`), `paths.py`,
  `request_limits.py` (`MAX_CONTENT_LENGTH`, 8 MiB, and the metadata upload's own
  16 MiB, chosen from the sizes measured in Phase 21 and settable in the
  environment; a larger body is answered 413 in JSON by `routes/errors.py`).
  Importing it configures nothing. The routes call `config.create_fido_server` /
  `config.determine_rp_id` through the package, so route tests patch those on the
  package; patch every other name in its submodule.
- `config.app` is a lazy alias for `server.app.app.app`, kept so the tests written
  against the old singleton still work. Nothing in `server/` may read it
  (a test enforces that): request code uses `flask.current_app`, and code outside
  a request takes the app as an argument.
- Importing any module under `server/app`, except the entry point, must not write
  to disk. `tests/app/core/test_import_side_effects.py` imports every module
  under an audit hook and fails on any write.
- Log with `logger = logging.getLogger(__name__)`, never `app.logger`. The app is
  named `server.app`, so module loggers are children of `app.logger` and reach
  the stderr handler `config/logs.py` makes sure exists;
  `tests/app/core/test_logging_reaches_stderr.py` checks that under gunicorn.
- On Cloud Run (`K_SERVICE` set) the app refuses to start without
  `FIDO_SERVER_SECRET_KEY` or a readable `FIDO_SERVER_SECRET_KEY_FILE`; only local
  development generates and persists `instance/session-secret.key`. A test run
  never does: `tests/conftest.py` sets a test `FIDO_SERVER_SECRET_KEY` when it is
  imported, before any test module imports the entry point, and a test of the
  secret's own handling removes it with `monkeypatch.delenv`.
- `server/app/mds_trust.py`
  The MDS trust anchor. A leaf on purpose: `tools/update_mds_snapshot.py` imports
  it without anything from Flask.

Main route modules:

- `server/app/routes/simple/`
  Simple WebAuthn begin/complete endpoints. `__init__.py` holds the Flask rules on
  the `simple` blueprint (`bp`); `registration.py`, `authentication.py` and
  `credential_list.py` hold the bodies. `registration.py` runs register-complete's
  stages: `registration_record.py` builds the record (attestation summary, credential
  info, authenticator data, relying-party and debug views, stored credential) and
  `registration_persistence.py` saves it -- appending to the user's credential list by
  compare-and-swap, retrying a lost race up to eight times, 409 after that, and 503
  when the stored list could not be read or did not decode -- then updates the
  session list and the device log. `authentication.py` checks the
  signature counter against the larger of the stored and the browser's copy. It
  fails closed: stored records that could not be read reject the assertion with 503
  (the browser's copy alone can be omitted or lowered); records that were read but
  hold nothing for the credential fall back to the browser's copy. The 200 and the
  regression rejection carry `signCountStatus` (`server/app/webauthn/sign_count.py`),
  which the tab's result panel shows. `credential_list.py`
  answers `GET /api/credentials` with `{"credentials": [...]}` plus `unreadableCount`
  (and the `X-Unreadable-Credentials` header) when a stored copy did not decode or a
  record could not be shown, and 503 when the store could not be read.
- `server/app/routes/advanced/`
  Advanced WebAuthn begin/complete endpoints, algorithm handling, request
  validation, metadata-heavy flows. Same shape: rules on the `advanced` blueprint
  in `__init__.py`, bodies in `registration.py`, `authentication.py`, `artifacts.py`.
  The bodies are short orchestrators over modules named for their stage:
  registration begin in `registration_options.py` (request checks, RP and server,
  authenticator selection, exclude list, extensions) with the algorithm offer in
  `algorithms.py`; registration complete in `registration_inputs.py` (request, state,
  fido2 verification), `registration_attestation.py` (origin allowlist, attestation
  checks and their summary), `registration_record.py` (credential info, debug view,
  relying-party view, stored credential) and `registration_persistence.py` (artifact,
  device log, answer); authentication in `assertion_credentials.py` (which stored
  credentials may answer), `assertion_options.py` (begin's server, UV, extensions) and
  `assertion_verification.py` (fido2's verdict and the answer). The challenge-source
  names live in `constants.py`, the binary request-field decode in `binary.py`, the
  attachment-hint check in `server/app/attachments.py`. The try blocks and the order
  of session reads in the bodies are behaviour; keep moved code inside them.
- `server/app/routes/general.py`
  Index page, metadata bootstrap helpers, decoder endpoints, misc app routes, on
  the `general` blueprint. `routes/web_export.py` (the `web_export` blueprint) serves
  the new UI's export at `/beta`: HTML `no-cache`, `/beta/_next/static/` immutable for
  a year with the build-time `.gz` copies (`static_assets.send_precompressed`), the
  export's `404.html` for an unknown path, a plain 404 with no export; the export
  root is `config/web_export.py` (`web/out`, or `FIDO_SERVER_WEB_EXPORT_ROOT`).
  `static_assets.py` has its own `static_assets`
  blueprint. Endpoint names are therefore `general.index`, `simple.register_begin`
  and so on; nothing refers to them today (no `url_for`).
- `server/app/routes/csp_report.py`
  `POST /api/csp-report`, on the `csp_report` blueprint: where browsers send CSP
  and Trusted Types violations. It bounds the body itself (512 KiB, answered 413
  without `errors.py`'s per-request log line), and `server/app/csp_reports.py` reads
  both wire formats and logs each violation as one WARNING line,
  `CSP violation: directive=... blocked=... path=...`, keeping nothing else (no
  query, user agent, address or sample). A token bucket per app (burst 30, 30 a
  minute) bounds a flood and says how many lines it dropped. A breakage the policy
  causes in production shows in the Cloud Run logs as these lines.

Related backend modules:

- `server/app/webauthn/attestation/`
  Attestation parsing and validation. `checks.py` (the checks), `trust.py`, `pqc.py`,
  `classical.py`. `certificates.py` serialises a certificate and extracts an
  attestation's details; it draws on `certificate_names.py` (a leaf: name
  spellings), `certificate_extensions.py` (one handler per extension; signed
  certificate timestamps are records, never `str()` of cryptography's objects),
  `certificate_public_keys.py` (loadable keys, and the best effort for one
  cryptography will not load) and `certificate_summary.py` (the text summary, a
  section at a time).
- `server/app/webauthn/signature_algorithms.py`
  The one spelling of a certificate's signature algorithm (`ECDSA_SHA256`,
  `ED25519_SHA512`, `RSASSA-PSS_SHA256` with the hash from the PSS parameters,
  `ECDSA_SHA3-256`, `ML-DSA-44` with no hash), for the certificate view and the MDS explorer
  (`mds_snapshot.py`) alike. A leaf outside the attestation package, whose
  `__init__` imports the whole stack: `tools/update_mds_snapshot.py` reaches it
  without Flask, which `tests/app/tooling/test_update_mds_snapshot.py` checks in a
  fresh interpreter.
- `server/app/webauthn/metadata/`
  FIDO MDS resolution: `blob.py`, `snapshots` via `effective.py`, `sessions.py`.
- `server/app/webauthn/pqc.py`
  The ML-DSA adapter.
- `server/app/storage/`
  Persistence: `credentials.py`, `record_format.py` (the JSON envelope and the
  restricted reader for legacy `.pkl` copies), `session_metadata.py`, `cloud.py`,
  `common.py`; credential artifacts are `server/app/credential_artifacts.py`. Every
  read-modify-write goes through compare-and-swap (`read_for_update` /
  `save_if_unchanged`). A read that fails raises `StorageReadError` (503), never a
  shorter list; content that does not decode is logged by name and counted, never
  overwritten unread.
  **Read `docs/STORAGE.md` before changing `server/app/storage` or `credential_artifacts.py`.**
- `server/app/decoder/`
  The codec behind the Decoder tab: `decode/` shows what input holds, `encode/`
  writes a value back. It shows what was sent -- it never repairs, synthesizes or
  drops a field -- and puts interpretation beside the decoded value, never in its
  place. Input is parsed only by `decode/cbor_parser.py`; encoder bytes come only
  from `decoder/cbor_canonical.py` and the EDN reader; `ctap_tables.py` and
  `cose_tables.py` are the only copies of their registries.
  **Read `docs/DECODER.md` before changing anything under `server/app/decoder`.**

Each of these packages keeps its public surface in `__init__.py` and its
implementation in submodules named for what they do. Import the submodule you
need; patch there rather than on the package's re-export, because the submodules
call each other through module objects.

## How Data Flows

For authentication work, the important path is usually:

1. Frontend collects stored credentials from browser-side storage.
2. Begin endpoint issues request options and stores server-side state in Flask session.
3. Browser performs `navigator.credentials.create/get`.
4. Complete endpoint verifies the response using `create_fido_server(...)`.
5. Frontend updates local saved credential state and refreshes the shared credential list.

The saved credential cards shown in simple and advanced tabs are rendered by the same shared display module, so UI changes there often affect both tabs.

## Common Places To Edit

- Credential card visuals or behavior:
  `frontend/static/scripts/advanced/credentials/index.js`
  `frontend/static/styles/shared/layout.css`
- Simple auth UX:
  `frontend/static/scripts/simple/auth-simple.js`
  `server/app/routes/simple/`
- Advanced auth UX:
  `frontend/static/scripts/advanced/auth/advanced.js`
  `server/app/routes/advanced/`
- JSON editor or advanced request shaping:
  `frontend/static/scripts/advanced/editor/index.js`
  `frontend/static/scripts/advanced/auth/forms.js`
  `frontend/static/scripts/advanced/auth/hints.js`

## Testing Guidance

Fast checks:

- Frontend syntax:
  `node --check <file>`
- Python syntax:
  `python -m compileall <file-or-dir>`
- Focused pytest:
  `pytest -q tests/app/<target_test>.py`

Repo test layout:

- `tests/app/`
  Flask/app behavior.
- `tests/fido2/`
  Library-level tests for the local `fido2/` copy.
- `tests/pqc/`
  PQC-related tests.
- `tests/device/`
  Hardware tests. These are skipped unless explicitly enabled.

If you are changing only UI logic plus lightweight server responses, prefer targeted tests over the full suite first.

Nine checks guard the code and the checkout rather than behaviour:

- `tests/app/tooling/test_html_sinks.py` fails on any `.innerHTML` / `.outerHTML`
  assignment, `insertAdjacentHTML`, `document.write`, `parseFromString`,
  `createContextualFragment` or `setHTMLUnsafe` in `frontend/static/scripts`, fixed
  string or not: each is a Trusted Types sink the report-only policy reports. Its
  `ALLOWED` list is empty; an entry needs its reason and may only be removed.
- `tests/app/tooling/test_inline_code.py` keeps out what the strict CSP refuses:
  an `on*=` attribute, a `style=` attribute or a `<script>` without `src` (other
  than `type="application/json"`) in a template; `setAttribute('style')` or markup
  written in a string with an `on...=` or `style=` in a script; and any write to
  `window` / `globalThis` / `self` (assignment, `delete`, `Object.assign`,
  `defineProperty`). Its `ALLOWED_*` dicts are empty and may only shrink.
- `tests/app/tooling/test_frontend_base64.py` fails on any `atob(` in
  `frontend/static/scripts` outside its `ALLOWED` list, which holds only the
  vendored `json-ponyfill.js`.

- `tests/app/tooling/test_web_source_rules.py` holds `web/src` to the same rules,
  with the readers of the two tests above, plus no `style` prop, no
  `dangerouslySetInnerHTML`, `<style>`/`<script>`, `next/script` or `eval`, and no
  copy of the Analyze Browser logic modules (their exports or their sentences).
  Its `ALLOWED` dict is empty and may only shrink.
- `tests/app/tooling/test_npm_lockfiles.py` fails when a lockfile (root or `web/`)
  lacks an optional dependency one of its packages declares: the per-platform
  native builds (`@next/swc-*`, `@tailwindcss/oxide-*`, `lightningcss-*`,
  `@rolldown/binding-*`) the Linux runner and the image need.

- `tests/app/tooling/test_no_silent_monkeypatch.py` fails on a
  `monkeypatch.setattr(..., raising=False)` (or `mock.patch(..., create=True)`):
  such a patch keeps passing after the name it patches moves, while patching
  nothing. Its `ALLOWED` list holds the few that must create an attribute, each
  with the reason it cannot exist (a builtin shadowed in one module, a
  Windows-only `ctypes` name).
- `tests/app/tooling/test_code_size_ratchet.py` fails on a function over 80 lines
  or a module over 700 in `server/app`, except those listed at their current
  length. Entries only go down: shrink one and lower its entry, get one under the
  limit and remove it; never raise one. Split along the stages of the work, not by
  line count.
- `tests/app/characterization/` records what the ceremony routes, the decoder and
  the attestation serialisers answer, byte for byte, in a pinned environment
  (fixed clock, seeded randomness, stores in a temporary directory, no MDS), and
  compares with `golden/`. An intended change of output, or a dependency bump that
  changes it (cryptography's extension text, say), is regenerated with
  `CHARACTERIZATION_WRITE=1 pytest tests/app/characterization` and the diff
  reviewed before committing; `python tests/app/characterization/encoding_diff.py
  [REVISION]` shows whether a golden diff is byte spellings only. `material.py`
  builds the keys and certificates
  deterministically; the only frozen input is ML-DSA signatures (`inputs/frozen.json`),
  since ML-DSA signing is randomised.
- `tests/checkout_guard.py`, a pytest plugin `tests/conftest.py` loads, fails the run
  when a test created, changed or removed anything under `server/runtime/`,
  `instance/`, the legacy credential stores (`server/app/session-credentials/`,
  `server/app/*_credential_data.pkl`), `.hypothesis/` or the MDS snapshot files in
  `frontend/static/`. What is there mixes the owner's local data with old test
  leftovers: the guard compares a listing taken in `pytest_configure`, before any
  test module is collected (so a write made while importing one is seen), with one
  taken when the session finishes, and never deletes.
  `tests/app/tooling/test_checkout_guard.py` runs it in a subprocess rooted at a
  directory of its own (`--checkout-root`). Give a test its own stores in
  `tmp_path`. `tests/app/conftest.py` also points the session-metadata store at a
  directory of the run's for the whole session: a session-cleanup thread can
  outlive the test that started it, and one that lists the checkout's directory
  removes the inactive sessions it finds there.

For a test that needs an app configured differently, use the `make_app` fixture in
`tests/app/conftest.py` (or `app` / `client`): it calls `create_app()` with a fixed
test secret, reading the environment at that moment, so `monkeypatch.setenv` before
it configures that app and no other. Do not `importlib.reload` config modules.

## Linting

- Ruff config lives in the root `ruff.toml`, not in `pyproject.toml` (that file is
  the vendored `fido2/` library's manifest).
- Run it with `uvx ruff@0.16.8 check .` Ruff is deliberately kept out of
  `uv.lock` and the venv, so do not `uv add` it.
- CI fails on any violation of the gated set (`E4`, `E7`, `E9`, `F`, `I`,
  `UP006/UP007/UP035/UP045`). It is at zero; keep it there.
- `F821` is gated at zero with nothing ignored, and `ruff.toml` has no
  `[lint.per-file-ignores]` section at all. Every module imports the names it
  uses; the old "carrier" modules that rebuilt their fragments' functions against
  their own globals are gone. Read `ruff.toml` before changing this, and do not
  reintroduce globals rebinding anywhere.
- The only `# noqa: F401` markers left are in
  `server/app/decoder/encode/__init__.py`, where the package deliberately
  re-exports encoder internals for callers and tests.
- Do not run `ruff format` -- the repo is not format-clean and it would rewrite
  about 69% of the files.

## Python Dependencies

- App dependencies are declared only in `server/pyproject.toml`; resolved versions are locked in `uv.lock`.
  The Docker image, CI and local venvs all install from that lock.
- Set up or refresh a local venv: `uv sync --locked`
- Add or change a dependency: edit `server/pyproject.toml`, run `uv lock`, commit both files.
  A stale lock fails the Docker build and CI.
- The root `pyproject.toml` is the vendored `fido2/` library's manifest, not the app's.
- Its build backend is pinned exactly (`poetry-core==X.Y.Z`): `uv.lock` does not lock
  build requirements, so a range lets a new release break an unchanged commit, as
  poetry-core 2.5.0 did on 2026-09-23. Keep it an exact pin;
  `tests/app/tooling/test_build_backend_pin.py` enforces that. Dependabot cannot bump
  it (it skips `[build-system]` in a Poetry project), so
  `.github/workflows/update-build-backend.yml` checks PyPI weekly, builds fido2 with
  the new release through uv and pip, runs pytest, and only then opens a bot PR.

## CI, Deploys And Bots

- Two independent pipelines run on a push to `main`: GitHub Actions
  (`.github/workflows/ci-*.yml`) and Cloud Build (`cloudbuild.yaml`). A red CI
  run does not stop Cloud Build, so `cloudbuild.yaml` runs pytest and vitest
  itself before it builds an image. Keep that gate: it is the only thing
  between a commit and production.
- `ci-*.yml` run on `pull_request` and on `push` to `main` only. Do not drop the
  branch filter; without it a same-repo PR runs everything twice.
- Every action is pinned to a commit SHA with the version in a trailing comment.
  Dependabot bumps both. Do not reintroduce a floating tag -- and note that
  `astral-sh/setup-uv` publishes no floating major tag at all.
- No workflow pushes to `main`. `update-footer-year.yml` and
  `update-build-backend.yml` commit to a bot branch through
  `.github/actions/open-bot-pr` and open a pull request, staging an explicit path
  list rather than `git add -A`. GitHub does not start workflow
  runs for events signed by `GITHUB_TOKEN`, so set a `BOT_PR_TOKEN` secret if
  those pull requests should get CI automatically. Enforcement still depends on
  branch protection on `main`, which lives in repository settings, not here.
- Scheduled workflows (`update-fido-mds.yml`, `update-footer-year.yml`,
  `update-build-backend.yml`, and `ci-security.yml`'s weekly run) fail where nobody
  looks. `ci-scheduled-runs.yml` reads their latest run on `main` on every push and
  pull request and emits a warning annotation while one has failed. It holds only
  `actions: read` and never fails the build. Issues are disabled on this
  repository, so it does not open one. Add any new scheduled workflow to its list.
- Coverage is a gate, not a published number: the floors in `.coveragerc` and
  `vitest.config.mjs` fail CI, and there is no coverage badge or badge workflow.
  Do not add one back.
- `fido2/hid/macos.py` is omitted from coverage on purpose: its only test module
  skips itself off Darwin, so measuring it made the total depend on the runner's
  OS and the floor could not hold on both.
- Frontend installs use `npm ci` everywhere, at the root and in `web/`. Each
  `package-lock.json` must list every platform's native build (fifteen
  `@rolldown/binding-*` at the root; in `web/` also `@next/swc-*`,
  `@tailwindcss/oxide-*` and `lightningcss-*`) -- the Linux runner and the image
  need their own; `test_npm_lockfiles.py` checks it. If a lock regeneration drops
  them, delete `node_modules` and `package-lock.json` and run `npm install` from
  clean; npm prunes foreign-platform optional dependencies when it reconciles
  against a partial tree (npm/cli#4828).
- `web/package.json` overrides the `postcss` Next 15 pins (8.4.31, with advisories)
  with a fixed release, so `npm audit` stays clean without leaving Next 15. Dependabot
  (`/web`) skips majors of `next`, `typescript` and `@types/node`: the charter names
  Next 15, whose build type-checks with TypeScript 5.
- `ci-web.yml` runs `web/`'s typecheck, unit tests with coverage floors, build and
  CSP scan, and the Playwright browser tests. `cloudbuild.yaml`'s `Web tests` step
  runs all but the browser tests before any image is built; the browser tests join
  the Cloud Build gate at the cutover (docs/UI_MIGRATION.md).
- The `Dockerfile`'s first stage (`node:22-slim`) builds `web/` and scans the export;
  only `web/out` reaches the runtime image, at `/app/web/out`, precompressed by
  `tools/build_static_assets.py --precompress-only`. No Node runs in production.
- `ci-security.yml` fails the build on a `pip-audit` finding against `uv.lock`,
  on `npm audit --audit-level=moderate` at the root and in `web/`, and on a fixable
  HIGH/CRITICAL Trivy finding in the image. Each threshold is justified in a comment next to it. If
  a scan starts failing, fix the dependency -- do not widen the threshold.
- The runtime stage of the `Dockerfile` runs `apt-get upgrade`. Removing it puts
  thirteen fixable HIGH/CRITICAL Debian CVEs back into the image.

## The FIDO MDS Snapshot

- The ~30MB generated snapshot under `frontend/static/` is **not tracked in git**
  and **not baked into the image**. `server/app/mds_provisioning.py` fetches it at
  runtime: local files, then Cloud Storage, then a verified upstream refresh.
- Working locally: run `python tools/update_mds_snapshot.py` once. Without it the
  metadata APIs return 404 and the explorer is empty; that is the documented
  fallback, not a bug.
- Never commit those files and never write a test that reads the real snapshot
  path. `docs/MDS_SNAPSHOT.md` has the full picture.

## Repo-Specific Gotchas

- The current UI (`frontend/`) is plain JS modules; the new UI (`web/`) is React through Next.js, exported as static files.
- Templates hold no code: a control names its action with `data-action`, and nothing is put on `window` (`shared/ui/actions.js`). The CSP has no `'unsafe-inline'`, so an inline handler, `<script>` or `style=` added back simply does not run.
- The simple and advanced tabs share the saved credential display, so re-render logic can have cross-tab side effects.
- Flask session state matters in begin/complete flows. Be careful not to break the fallback `__session_state` handling.
- The local `fido2/` directory is part of the repo. Do not assume behavior matches the latest upstream package.

## Good First Step For Most Tasks

Before changing code, identify:

1. Which tab or route owns the user-visible behavior.
2. Whether the change affects shared credential rendering.
3. Whether the server returns data that the frontend currently needs but does not receive.
4. The smallest focused test that proves the change.

## Recommended Working Style

- Read the specific route and its matching frontend module together.
- Prefer focused fixes over broad refactors unless the task explicitly asks for restructuring.
- Verify both simple and advanced flows whenever you touch shared credential UI or browser storage behavior.
- When adding server response fields, update both the frontend handling and at least one focused app test.
