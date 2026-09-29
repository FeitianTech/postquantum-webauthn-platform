# AGENTS.md

A quick orientation for coding agents working in this repository.

## Commits

Every commit, whoever makes it:

- Goes on `main` directly, no branch, and is small: one change you can describe in a sentence.
- Has a one-line message: one short sentence (at most 72 characters) saying what
  changed in the code, for example "Serve the web export at the site root" or
  "Read a 22-character AAGUID as base64url". No body, no trailers, no `Co-Authored-By`.
  CI checks the length and the single line (`tools/commit_messages.py`).
- Describes the code, never the work around it: no phase or step numbers, no plans,
  briefs, reviews or verifications, and nothing else that shows how the team
  organises its work.

## What this repository is

A FIDO2/WebAuthn test platform and developer tool: simple and advanced registration and
authentication, post-quantum (ML-DSA) credentials, credential inspection and attestation
decoding, a FIDO MDS explorer, and a CBOR/CTAP codec. Flask serves the API and the UI; the
UI is `web/`, a Next.js static export Flask serves at `/`. No Node runs in production.
The server uses python-fido2 from PyPI (`fido2`, pinned exactly); what it adds to fido2 lives
in `server/app` (see "Backend").

## Layout

- `server/app/`: the Flask app (factory, config, routes, WebAuthn, storage, decoder, MDS).
- `web/`: the UI (Next.js 15 Pages Router, TypeScript, Tailwind CSS v4). `web/src/logic` is
  its DOM-free logic in plain JavaScript; `web/e2e` its Playwright tests.
- `tests/`: `app/` (the Flask app, tooling guards, characterization; `python_fido2_vectors.py`
  holds the vectors taken from python-fido2's own tests), `pqc/`, `fixtures/` (the MDS fixture
  snapshot).
- `tools/`: `update_mds_snapshot.py`, `build_static_assets.py` (precompresses the export at
  image build), `commit_messages.py` (the commit message check), `update_footer_year.py`.
- `docs/`: `DESIGN.md` (the UI's design, security and serving rules), `DECODER.md`,
  `STORAGE.md`, `MDS_SNAPSHOT.md`.
- `Dockerfile`, `cloudbuild.yaml` (the deploy gate), `deploy/` (Cloud Run service config),
  `.github/` (workflows, Dependabot, the bot PR action).

## The UI (`web/`)

**Read `docs/DESIGN.md` before changing anything under `web/`**: light only, no grey
components, no focus effect on text fields, the section slide, the MDS page's structure,
the CSP and the source rules.

- `src/pages/`: `index.tsx` (the app shell), `design.tsx` (the unlisted `/design` page,
  `noindex`: every component in every state), `404.tsx`, `500.tsx`, `_error.tsx` (Next's own
  error pages use style attributes the CSP refuses), `_app.tsx` (Geist and Geist Mono from
  the `geist` package via `next/font/local`, on a wrapper holding `#app-root` and
  `#overlay-root`, so portalled overlays get them), `_document.tsx`.
- `src/styles/globals.css`: the design tokens (`@theme`, Tailwind's defaults cleared first);
  text fields carry `data-text-field`; `hover-or-demo` / `focus-or-demo` / `active-or-demo`
  let `/design` show a state still (`data-demo`). `@source not` keeps Tailwind out of
  `src/logic` and `src/test/logic`.
- `src/components/ui/`: the primitives (Button, IconButton, text fields, Select, Switch,
  ToggleChip, SegmentedControl, Card, Badge, StatusChip, Overlay with Dialog / Drawer / Sheet,
  Toast, InfoPopover, the table primitives, MonoValue, CodeBlock, KeyValueGrid,
  ConfirmDialog, FieldRow, OverlayHeader with `back`). Overlays stack: a module-level list of
  open layers, z-index by depth, only the top one handling Escape and Tab, focus returned
  layer by layer. `SegmentedControl` moves its highlight through the CSSOM from a ref;
  `MonoValue` measures overflow as if its "Show all" were not there, again when fonts load.
- `src/components/shell/`: the header (title, the four sections, Analyze Browser, GitHub;
  the phone menu sheet below 900 px; it measures itself into `--header-height`), the footer
  (its year kept by `tools/update_footer_year.py`), and `AppShell`, which mounts every
  section and gives the route only to the one shown (the others get `CLOSED_ROUTE`).
- `src/lib/`: `sections.ts` (`SECTIONS`, `NAV_ID`, `APP_TITLE`, which is also the relying
  party's name; `routeFromHash` / `hashPath`), `useSection.ts` (the section in the hash with
  `replaceState`; what is open inside one as segments after it, e.g.
  `#mds/<entryId>/certificate/<n>`; `open` pushes so Back closes one level, `close`, `replace`,
  `closeAll` go back as many levels as the page opened: the pushed state's `pqcOpened`; it
  tells Next's router, `beforePopState`, to leave Back to the page while the path stays),
  `entrance.ts` (entrances only for what the person brings up), `download.ts`,
  `useOverlayRoot.ts`.
- Sections:
  - `simple/` and `credentials/`: the Simple tab, and the saved credentials both tabs share
    (`SavedCredentialsProvider` at the shell's level; it follows another tab's change through
    the storage event). `CredentialDetailDialog` has four levels, each a pushed history entry:
    `#<section>/credential/<key>`, `…/registration`, `…/registration/certificate/<n>`,
    `…/registration/authenticator-data`; a level the credential lacks is corrected upward.
  - `advanced/`: the Advanced tab. Registration and Authentication segments, both mounted,
    each a form beside its JSON editor. `requestEditor.ts`: the editor's text is the request;
    a form change rewrites in the text only what it changed (`followForm`), an edit the form
    can follow updates the form at once. `useAdvancedRequest` / `useAuthenticationRequest`
    hold each request; `useRegistrationCeremony` / `useAuthenticationCeremony` run them;
    `fieldText.ts` is the only copy of the form's labels, options, errors and info popups
    (English and 中文).
  - `codec/`: Decode / Encode. Its tests render real answers from `src/test/codec-answers.json`,
    which `tests/app/tooling/test_web_codec_answers.py` keeps equal to what `/api/codec`
    answers (`CODEC_ANSWERS_WRITE=1` rewrites it).
  - `mds/`: the explorer (the table's rows are grids on one column template set through the
    CSSOM, `--mds-columns`, with `content-visibility: auto`), the filter bar, an entry and its
    certificates (`EntryRouter`; `CondensedBar` portalled into the overlay root, since an
    entering section is a transform), Manage Metadata, and `entryLink.ts`, how a saved
    credential opens `#mds/aaguid:<aaguid>`.
  - `analyze-browser/`: the Analyze Browser panel.
- Tests: vitest with two projects (`web/vitest.config.mts`): `components`
  (`src/**/*.test.{ts,tsx}`, Testing Library, `src/test/setup.ts`) and `logic`
  (`src/logic/**/*.test.js`, `src/test/logic/setup.js`: a fresh storage, `fetch` mock and
  document per test). Helpers are in `src/test/` (`credentials.ts` keeps records in the
  storage, `fetch.ts` answers `fetch` by path, `mds.ts` like Flask serving the fixture,
  `advanced.tsx`) and `src/test/logic/` (the real ceremonies from the characterization
  goldens, `repo-file.js` for files under the repository). The `@test-fixtures` alias is
  `tests/fixtures`.
- `e2e/` (Playwright, Chromium): `serve-flask.mjs` starts Flask with every store in a
  temporary directory and a copy of the MDS fixture as its snapshot;
  `virtual-authenticator.ts` adds a CTAP2 authenticator through the DevTools WebAuthn
  domain; `fixtures.ts` fails a test on any console error, page error or CSP report;
  `design-rules.ts` finds grey fills. The `*-recorded` specs compare a page's words with a
  recording in `e2e/recorded/` (`recorded-words.ts`, `recorded.ts`): a recording is never
  edited, and an intended change is an expected difference with its reason (the user name
  `paritycheck` is data inside a recording). `stored-records.spec.ts` loads what an earlier
  release stored in visitors' browsers. Every section and both Advanced segments are
  mounted: scope a query to its tabpanel (`#advanced-ceremony-panel-<segment>`).
- `scripts/check-export-csp.mjs` scans every exported HTML file; `scripts/dev-csp.mjs` is the
  CSP `npm run dev` sends (Flask's, plus the two allowances the dev server needs).

Running it (Node 22, in `web/`): `npm ci`; `npm run dev` (at `http://localhost:3000/`,
proxying `/api` to `FLASK_URL`, default `http://localhost:8000`; ceremonies need Flask's
origin, so use the export for those); `npm run build` (the export in `web/out`, which Flask
serves; `FIDO_SERVER_WEB_EXPORT_ROOT` points elsewhere); `npm run typecheck` (covers
`e2e/`); `npm test`; `npm run test:coverage`; `npm run check:csp` (after a build); `npm run
e2e` (after a build; `npx playwright install chromium` once; `E2E_PYTHON` names the Python
with the app's dependencies, `.venv/bin/python` by default; `E2E_PORT`, default 5151).

## The logic (`web/src/logic`)

DOM-free plain JavaScript modules, each module's tests beside it, imported by components as
`@/logic/…`. They import only each other (no npm package) and touch no DOM; every file is
held at 100 % coverage (the vendored ponyfill aside). Components import them and never copy
their exports or sentences. A new surface splits its logic out here first.

- `shared/storage/records.js`, `shared/storage/local/`: the saved credentials, one
  `localStorage` array visitors' browsers already hold. It reads no page; the first read is
  cached until another tab changes it (`followStoredCredentialChanges`); tests seed it with
  `seedUnifiedCredentialRecords`. `local/record-migration.js` brings records saved by earlier
  versions to today's format as they are read: when a stored format changes, add a step there
  with an old-format fixture in `src/test/logic/shared/storage/`.
- `simple/ceremony.js`: the Simple tab's two ceremonies (requests, every step's sentence).
- `advanced/json-editor/`, `advanced/editor/`, `advanced/auth/`: the Advanced tab's requests
  (`registration-request.js`, `authentication-request.js`: defaults, build, read back, the
  form's rules), the editor's model and keys, `request-patch.js` (`followForm`), hints, fake
  credential IDs, byte fields, Allow Credentials' choices, extension availability, and both
  ceremonies (`ceremony.js`, `assertion.js`).
- `advanced/credentials/`, `advanced/credential-display/`: a saved credential's row, deletion,
  algorithm tag, hydration from its server artifact, and its details and registration view as
  data. Registration snapshots (`schemaVersion` 2) hold the registration as data, never markup;
  older composed HTML is never read.
- `decoder/codec/`: the Codec's requests, results and values. `advanced/mds/`: the MDS
  explorer's loading, filters, sort, columns, rows, entry, certificate, raw view and Manage
  Metadata (the server builds each row: `mds_snapshot.build_explorer_entry`).
- `shared/browser/`: the Analyze Browser's facts. It reports what the browser says and where
  each answer came from, or that it cannot know; it never guesses. Web pages cannot ask
  which transports a browser supports: do not add WebUSB/WebHID/Bluetooth/Serial checks. The
  identity cases are real user-agent strings with Client Hints in
  `src/test/logic/shared/browser/identity-matrix.js`; add a browser there.
- `shared/api/failed-response.js`: the one reader of a failed response (`readFailedResponse`,
  `FailedResponseError`): the server's `error`, the codec's `offset` and `path`, what to do for
  a 400, 409, 413 or 503. Never show a raw response body.
- `shared/ceremony/result.js`: the result panel's signature counter and challenge sentences.
- `shared/utils/base64.js`: bytes on the wire are unpadded base64url; a field named for base64
  (`derBase64`, …) is standard base64. Decode with the strict `base64UrlToBytes` /
  `base64ToBytes`; `forgivingBase64ToBytes` only for typed text. No `atob` outside the vendored
  `shared/webauthn/json-ponyfill.js` (@github/webauthn-json, kept with its source map).

## Backend (`server/app`)

- `app.py`: the WSGI entry point, `server.app.app:app = create_app()`, in a checkout and in the
  image alike (the Dockerfile copies `server/app` to `/app/server/app`). No `server.X` import
  fallbacks.
- `factory.py`: `create_app(config=None)`: each config submodule's `config_from_env()`, then the
  overrides, then `INIT_STEPS` in order (`test_app_factory.py` pins it).
- `config/`: `application.py`, `logs.py`, `session_secret.py`, `compression.py`, `proxy.py`,
  `session_cookie.py`, `security_headers.py` (the strict CSP and the Trusted Types report-only
  policy, both reporting to `/api/csp-report`; `FIDO_SERVER_CONTENT_SECURITY_POLICY` replaces
  the enforced policy), `origins.py`, `attestation_trust.py`, `mds.py`, `relying_party.py`,
  `paths.py` (project, runtime and instance roots), `request_limits.py` (8 MiB, the metadata
  upload 16 MiB; 413 in JSON), `web_export.py`. Importing it configures nothing. Routes call
  `config.create_fido_server` / `config.determine_rp_id` through the package, so patch those
  there and every other name in its submodule. Tests reach the entry point's app through
  `tests/app/entry_app.py`.
- Importing any module but the entry point writes nothing (`test_import_side_effects.py`). Log
  with `logging.getLogger(__name__)`. On Cloud Run (`K_SERVICE`) the app refuses to start
  without `FIDO_SERVER_SECRET_KEY` or `FIDO_SERVER_SECRET_KEY_FILE`; only local development
  generates `instance/session-secret.key`, and tests never do.
- `mds_trust.py` (the MDS trust anchor), `mds_blob.py` (the BLOB's chain to that root, which
  may end in a cross-certificate fido2's `parse_blob` refuses, its signature and payload),
  `mds_snapshot_dir.py` (the snapshot's file names, its directory, the whole-file and `.gz`
  sibling writers) and `mds_snapshot_sets.py` (the snapshot in Cloud Storage) are Flask-free
  leaves the updater imports.
- Routes: `routes/simple/` and `routes/advanced/` (begin/complete; the bodies are short
  orchestrators over modules named for their stage; the try blocks and the order of session
  reads are behaviour); `routes/general.py` (MDS info, decoder endpoints, misc);
  `routes/web_export.py` (the export at `/`: the site's catch-all, since Flask has no static
  rule; HTML `no-cache`, `/_next/static/` immutable with the build's `.gz`, the export's 404
  page, a plain 404 under `/api/`; `/beta…` 308 to `/…`, built with `url_for`);
  `static_assets.py` (the snapshot browsers load, `/assets/<segment>/<file>?v=<version>`,
  immutable when the version is current, and no other snapshot file at any path;
  `send_precompressed`); `routes/csp_report.py` (one WARNING line per violation, bounded);
  `routes/errors.py`.
- `webauthn/attestation/` (checks, trust, PQC and classical, certificate serialisation;
  `chain.py` verifies certificate chains, ML-DSA included, which fido2's `verify_x509_chain`
  does not; `evaluation.py` checks an attestation against the MDS metadata step by step),
  `webauthn/signature_algorithms.py` (the one spelling of a signature algorithm),
  `webauthn/metadata/` (MDS resolution), `webauthn/pqc.py` (the ML-DSA adapter),
  `webauthn/mldsa.py` (ML-DSA parameter sets, sizes and certificate keys),
  `webauthn/cose_keys.py` (RS384, RS512, PS384, PS512: the package imports it so fido2's
  `CoseKey` lookups find them), `webauthn/assertion_hash.py` (the Advanced tab's hash choice
  for an assertion), `webauthn/sign_count.py`. `config/logs.py` holds `fido2.server`'s
  logger at WARNING: fido2 logs credential IDs at INFO.
- `storage/` and `credential_artifacts.py`: every read-modify-write is compare-and-swap; a
  failed read raises `StorageReadError` (503), never a shorter list. **Read `docs/STORAGE.md`
  first.** `decoder/`: the Codec's server side; it shows what was sent and never repairs it.
  **Read `docs/DECODER.md` first.**
- Each package keeps its public surface in `__init__.py` and its implementation in submodules
  named for what they do; import the submodule you need and patch there.

Data flow of a ceremony: the page collects the stored credentials; begin issues options and
keeps state in the Flask session, and only there; the browser
runs `navigator.credentials.create/get`; complete verifies with `create_fido_server(...)`; the
page updates the saved credentials, which both tabs show.

## Testing

- `pytest -q` (`tests/`); `cd web && npm test` (both vitest projects); `npm run e2e`.
  Targeted: `pytest -q tests/app/<file>.py`, `npx vitest run --project logic <path>`.
- `make_app` (`tests/app/conftest.py`) builds an app from the environment at that moment:
  `monkeypatch.setenv` before it. Do not `importlib.reload` config modules. pytest never reads
  `web/out` (the `export_root` fixture builds a small export).
- `tests/conftest.py` points `FIDO_SERVER_MDS_SNAPSHOT_DIR` at an empty directory of the run's
  and turns the upstream refresh off; a test that needs a snapshot uses
  `mds_fixture_snapshot`, a copy of `tests/fixtures/mds`, which `mds_fixture.py` builds with the
  updater's own code (`MDS_FIXTURE_WRITE=1` rewrites it).
- `tests/app/characterization/` records what the ceremony routes, the decoder and the
  attestation serialisers answer, byte for byte, in a pinned environment, against `golden/`.
  `CHARACTERIZATION_WRITE=1 pytest tests/app/characterization` rewrites them after an intended
  change; review the diff (`encoding_diff.py` tells byte-spelling-only diffs).
- `tests/checkout_guard.py` fails the run when a test changed anything under `server/runtime/`,
  `instance/` (which holds the MDS snapshot too) or `.hypothesis/`. Give a test its own stores in `tmp_path`.

Guards on the code and the checkout (`tests/app/tooling/`; each `ALLOWED` list may only shrink):

- `test_html_sinks.py`, `test_inline_code.py`, `test_frontend_base64.py`,
  `test_decoder_dom_rules.py`: no markup sink, style attribute, inline handler, write to
  `window` or `atob` in the logic modules.
- `test_web_source_rules.py`: `web/src`'s rules (docs/DESIGN.md) and the logic's (DOM-free,
  imported not copied), read with comments and strings set aside.
- `test_web_dev_csp.py`: the dev server's CSP is Flask's default.
- `test_npm_lockfiles.py`: `web/package-lock.json` lists every platform's native build.
- `test_no_silent_monkeypatch.py`: no `raising=False` / `create=True` patch.
- `test_code_size_ratchet.py`: no function over 80 lines or module over 700 in `server/app`
  beyond the listed ones, whose entries only go down.
- `test_commit_messages.py`: the commit message check.

## Linting

`uvx ruff@0.16.8 check .` (config in `ruff.toml`; ruff is kept out of `uv.lock`). CI fails on
any violation of the gated set (`E4`, `E7`, `E9`, `F`, `I`, `UP006/UP007/UP035/UP045`), which is
at zero; `F821` has nothing ignored and there is no per-file ignore. Do not run `ruff format`
(the repo is not format-clean). The only `# noqa: F401` markers are in
`server/app/decoder/encode/__init__.py`.

## Python dependencies

Declared in the root `pyproject.toml` (the app's manifest; the app is not a package), locked in
`uv.lock`; the image, CI and local venvs install from the lock (`uv sync --locked`). To change
one: edit `pyproject.toml`, `uv lock`, commit both. `fido2` is pinned exactly; Dependabot
proposes its minor releases, and a major one is a deliberate move (the characterization
goldens show what it changes).

## CI, deploys and bots

- Two independent pipelines run on a push to `main`: GitHub Actions and Cloud Build. A red CI
  run does not stop Cloud Build, so `cloudbuild.yaml` runs its own gate first: `Python tests`
  (pytest) and `Web tests` (typecheck, both vitest projects with coverage, build, CSP scan) in
  parallel, then Build, Push and Deploy (Cloud Run `pqcwebauthn`). Playwright runs in GitHub CI
  only. Keep that gate: it is all that stands between a commit and production.
- Workflows (`ci-*.yml` run on `pull_request` and on `push` to `main` only): `ci-python.yml`,
  `ci-web.yml` (web and the Playwright tests), `ci-docker.yml` (builds the image and checks it
  answers), `ci-security.yml` (`pip-audit`, `npm audit --audit-level=moderate` in `web/`, Trivy
  on the image; fix the dependency, never widen a threshold), `ci-repository.yml` (actionlint
  with shellcheck from its author's image pinned by digest, which Dependabot does not bump;
  and on a push, `tools/commit_messages.py` over the pushed commits), `ci-scheduled-runs.yml`
  (warns while a scheduled workflow's latest run on `main` has failed: add any new scheduled
  workflow to its list).
- Every action is pinned to a commit SHA (or an image digest) with its version in a trailing
  comment. No workflow pushes to `main`: `update-footer-year.yml` opens pull requests through
  `.github/actions/open-bot-pr` (merge them by rebase or cherry-pick, so each commit keeps a
  one-line message);
  `update-fido-mds.yml` only verifies the upstream BLOB.
- Coverage is a gate: `.coveragerc`'s floor and `web/vitest.config.mts`'s (every logic file at
  100 %).
- `npm ci` everywhere. If a lock regeneration drops foreign-platform native builds, delete
  `node_modules` and the lock and `npm install` from clean (npm/cli#4828). `web/package.json`
  overrides Next 15's pinned `postcss`; Dependabot skips majors of `next`, `typescript` and
  `@types/node`.
- The Dockerfile's first stage builds `web/` and scans the export; only `web/out` reaches the
  runtime image, at `/app/web/out`, precompressed by `tools/build_static_assets.py`. The runtime
  stage's `apt-get upgrade` keeps fixable Debian CVEs out of the image.

## The FIDO MDS snapshot

- About 30 MB of generated files in `instance/mds-snapshot/` (in the image,
  `/app/instance/mds-snapshot`); `FIDO_SERVER_MDS_SNAPSHOT_DIR` puts it elsewhere. Not tracked in
  git and not baked into the image: `server/app/mds_provisioning.py` provides it at runtime
  (local files, then Cloud Storage, then a verified upstream refresh). Whatever writes the
  snapshot writes each file whole, metas last, and the explorer file's `.gz` sibling too.
- Cloud Storage holds immutable sets and `mds/current.json`, the pointer to one
  (`server/app/mds_snapshot_sets.py`: create-only sets, a generation-checked pointer that only
  moves forward); `tools/update_mds_snapshot.py --publish` publishes a verified snapshot, and a
  running instance takes a newer set from `/api/mds/metadata/info` (`follow_newer_snapshot`).
- Locally, run `python tools/update_mds_snapshot.py` once. Without a snapshot the explorer APIs
  answer 200 with no entry and the explorer is empty: the documented fallback, not a bug.
- Never commit those files, and never write a test that reads the real snapshot directory.
  `docs/MDS_SNAPSHOT.md` has the whole picture.

## Gotchas

- The CSP has no `'unsafe-inline'`: an inline handler, `<script>` or `style` attribute simply
  does not run. Style at run time through the CSSOM from a ref.
- The Simple and Advanced tabs share the saved credential list and its storage: verify both
  flows when you touch either.
- Begin/complete flows depend on Flask session state.
- fido2 finds a COSE key class by walking `CoseKey`'s subclasses, and the first class with an
  algorithm ID wins: an app subclass can add an algorithm, never replace fido2's.
- Exported HTML carries attributes: state that feeds an attribute starts at its build-time
  value and changes after hydration, or hydration differs.
- A hash navigation does not reload the page: in a Playwright test, reload after writing to
  `localStorage` before going to a deep URL.

Before changing code: find which section or route owns the behaviour, whether the saved
credentials are involved, whether the server already returns what the page needs, and the
smallest test that proves the change. Prefer focused fixes; when you add a response field,
change the page's handling and at least one app test with it.
