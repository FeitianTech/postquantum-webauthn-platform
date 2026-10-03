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

- `server/app/`: the Flask app (factory, config, routes, WebAuthn, storage, the visitor session,
  decoder, MDS).
- `web/`: the UI (Next.js 15 Pages Router, TypeScript, Tailwind CSS v4). `web/src/logic` is
  its DOM-free logic in plain JavaScript; `web/e2e` its Playwright tests.
- `tests/`: `app/` (the Flask app, tooling guards, characterization; `python_fido2_vectors.py`
  holds the vectors taken from python-fido2's own tests), `pqc/`, `fixtures/` (the MDS fixture
  snapshot).
- `tools/`: `update_mds_snapshot.py`, `build_static_assets.py` (precompresses the export at
  image build), `commit_messages.py` (the commit message check), `update_footer_year.py`,
  `subset_geist.sh` (Geist's two faces in `web/src/fonts`, with fonttools through `uvx`).
- `docs/`: `DESIGN.md` (the UI's design, security and serving rules), `DECODER.md`,
  `STORAGE.md`, `MDS_SNAPSHOT.md`.
- `Dockerfile`, `cloudbuild.yaml` (the deploy gate), `deploy/` (Cloud Run service config),
  `.github/` (workflows, Dependabot, the bot PR action).

## The UI (`web/`)

**Read `docs/DESIGN.md` before changing anything under `web/`**: light only, no grey
components, no focus effect on text fields, the section slide, the MDS page's structure,
the CSP and the source rules.

- `src/pages/`: `index.tsx` (the app shell), `404.tsx`, `500.tsx`, `_error.tsx` (Next's own
  error pages use style attributes the CSP refuses), `_app.tsx` (Geist and Geist Mono via
  `next/font/local`: Geist as two faces of one family, the Latin one preloaded and the rest by
  `unicode-range`, cut from the `geist` package's file into `src/fonts` by
  `tools/subset_geist.sh`; Geist Mono the package's own file, not preloaded; on a wrapper
  holding `#app-root` and `#overlay-root`, so portalled overlays get them), `_document.tsx`.
- `src/styles/globals.css`: the design tokens (`@theme`, Tailwind's defaults cleared first);
  text fields carry `data-text-field`. `@source not` keeps Tailwind out of `src/logic` and
  `src/test/logic`.
- `src/components/ui/`: the primitives (Button, IconButton, text fields, Select, Switch,
  ToggleChip, SegmentedControl, Badge, StatusChip, Overlay with Dialog / Drawer / Sheet,
  Toast, InfoPopover, the table primitives, MonoValue, CodeBlock, KeyValueGrid,
  ConfirmDialog, FieldRow, OverlayHeader with `back`). Overlays stack: a module-level list of
  open layers, z-index by depth, only the top one handling Escape and Tab, focus returned
  layer by layer. `SegmentedControl` moves its highlight through the CSSOM from a ref;
  `MonoValue` measures overflow as if its "Show all" were not there, again when fonts load.
- `src/components/shell/`: the header (title, the four sections, Analyze Browser, GitHub;
  the phone menu sheet below 900 px; it measures itself into `--header-height`), the footer
  (its year kept by `tools/update_footer_year.py`), and `AppShell`, which gives the route only
  to the section shown (the others get `CLOSED_ROUTE`). Simple is in the page's chunk; Advanced,
  Codec, MDS and the Analyze Browser panel are chunks of their own (`import()` through
  `lib/lazyModule.ts`): the section the URL names loads at once, behind a `SectionPlaceholder`
  panel, and the rest once the first view is interactive, each then mounted, hidden.
- `src/lib/`: `sections.ts` (`SECTIONS`, `NAV_ID`, `APP_TITLE`, which is also the relying
  party's name; `routeFromHash` / `hashPath`), `useSection.ts` (the section in the hash with
  `replaceState`; what is open inside one as segments after it, e.g.
  `#mds/<entryId>/certificate/<n>`; `open` pushes so Back closes one level, `close`, `replace`,
  `closeAll` go back as many levels as the page opened: the pushed state's `pqcOpened`; it
  tells Next's router, `beforePopState`, to leave Back to the page while the path stays),
  `entrance.ts` (entrances only for what the person brings up: what mounts already shown
  enters only once the page has left its first URL), `lazyModule.ts` (a chunk loaded once,
  `useLazyModule`: ahead, or at once when needed, a failed load tried again when next
  needed; `whenInteractive`), `download.ts`, `useOverlayRoot.ts`.
- Sections:
  - `simple/` and `credentials/`: the Simple tab, and the saved credentials both tabs share
    (`SavedCredentialsProvider` at the shell's level; it follows another tab's change through
    the storage event). `CredentialDetailDialog` (a chunk of its own, loaded by
    `CredentialDetails` when it is asked for or once the page is interactive) has four levels,
    each a pushed history entry:
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
  storage, `fetch.ts` answers `fetch` by path, `mds.ts` like Flask serving the fixture: its
  list and details from `src/test/mds-files.json`, which `tests/app/tooling/test_web_mds_files.py`
  keeps equal to what the server serves (`MDS_FILES_WRITE=1` rewrites it),
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
  release stored in visitors' browsers. Every section is mounted once its chunk has arrived,
  and both Advanced segments with it: scope a query to its tabpanel
  (`#advanced-ceremony-panel-<segment>`), and wait for a section's content, not its panel
  (the placeholder answers to the same name).
- `scripts/check-export-csp.mjs` scans every exported HTML file; `scripts/check-size-budget.mjs`
  holds each page's first-load JS, each named chunk and the chunks no page names, raw and
  gzipped, to its budget (`npm run check:size`, after the build, in CI and Cloud Build's gate);
  `scripts/dev-csp.mjs` is the
  CSP `npm run dev` sends (Flask's, plus the two allowances the dev server needs);
  `scripts/code-size.mjs` holds `src` (tests and `src/test` aside) to no function over 120
  lines and no module over 400, with no exceptions (`code-size.test.ts` runs it in `npm test`).

Running it (Node 22, in `web/`): `npm ci`; `npm run dev` (at `http://localhost:3000/`,
proxying `/api` and `/assets/mds` to `FLASK_URL`, default `http://localhost:8000`; ceremonies need Flask's
origin, so use the export for those); `npm run build` (the export in `web/out`, which Flask
serves; `FIDO_SERVER_WEB_EXPORT_ROOT` points elsewhere); `npm run typecheck` (covers
`e2e/`, and through `tsconfig.logic.json` checks the logic's JSDoc types with `checkJs`);
`npm test`; `npm run test:coverage`; `npm run check:csp` and `npm run check:size` (after a
build); `npm run e2e`
(after a build; `npx playwright install chromium` once; `E2E_PYTHON` names the Python with
the app's dependencies, `.venv/bin/python` by default; `E2E_PORT`, default 5151).

## The logic (`web/src/logic`)

DOM-free plain JavaScript modules, each module's tests beside it, imported by components as
`@/logic/…`. They import only each other (no npm package) and touch no DOM; every file is held
at 100 % coverage. The areas mirror the components' (`simple`, `advanced`, `credentials`,
`mds`, `codec`, `browser`), with `shared` for what more than one uses: an area imports `shared`
and itself, and another area only where its components do (`simple` and `advanced` read
`credentials`). A module imports what it needs, the storage and the server's decoder too; its
tests stub such a module with `vi.mock`, or seed the storage. Types are JSDoc, checked by `tsc`
(`tsconfig.logic.json`, `checkJs`): a shape's `@typedef` lives in the module that builds it,
and components `import type` it from there. Components call the logic by its own names, with
nothing between (no `model.ts`), and never copy its exports or sentences. A new surface splits
its logic out here first.

- `credentials/storage/local/`, `credentials/storage/records.js` (all of them in order): the
  saved credentials, one `localStorage` array visitors' browsers already hold, each kind's
  reads and writes in its own module. It reads no page; the first read is
  cached until another tab changes it (`followStoredCredentialChanges`); tests seed it with
  `seedUnifiedCredentialRecords`. `local/record-migration.js` brings records saved by earlier
  versions to today's format as they are read: when a stored format changes, add a step there
  with an old-format fixture in `src/test/logic/credentials/storage/`.
- `simple/ceremony.js`: the Simple tab's two ceremonies (requests, every step's sentence).
- `advanced/`: the Advanced tab. `registration/` and `authentication/` each hold their
  request (`request.js`: defaults, build, read back, the form's rules), its validation and
  its ceremony (`ceremony.js`), with Allow Credentials' choices and extension availability
  under `authentication/`; `editor/` the editor's model and keys, `request-patch.js`
  (`followForm`) and what both requests' validation shares; `hints.js`,
  `fake-credentials.js` and `hex-input.js` serve both forms.
- `credentials/`: the saved list (`saved-list.js`: the records, each row, the warm-up),
  deletion (`delete-flow.js`, through the list's report), the algorithm tag, hydration from
  a server artifact (`hydrate.js`), and (`registration/`, `certificates/`, `detail/`) a
  credential's details and registration view as data, which `detail/compose.js` composes into
  a registration state of its own. Registration snapshots (`schemaVersion` 2) hold the
  registration as data, never markup; older composed HTML is never read.
- `codec/`: the Codec's requests, results and values. `mds/`: the MDS
  explorer's loading (the list fetched ahead, without the cookie: `prefetchExplorerList`), filters,
  sort, columns, rows, entry (its detail from the file its row names, else resolve:
  `requestEntryDetail`), certificate, raw view and Manage Metadata (the server builds each row:
  `mds/build.py`'s `build_explorer_entry`, and the list's: `mds/explorer_files.py`).
- `browser/`: the Analyze Browser's facts. It reports what the browser says and where
  each answer came from, or that it cannot know; it never guesses. Web pages cannot ask
  which transports a browser supports: do not add WebUSB/WebHID/Bluetooth/Serial checks. The
  identity cases are real user-agent strings with Client Hints in
  `src/test/logic/browser/identity-matrix.js`; add a browser there.
- `shared/failed-response.js`: the one reader of a failed response (`readFailedResponse`,
  `FailedResponseError`): the server's `error`, the codec's `offset` and `path`, what to do for
  a 400, 409, 413 or 503. Never show a raw response body.
- `shared/ceremony-result.js`: the result panel's signature counter and challenge sentences.
- `shared/aaguid.js`: an AAGUID's two readings: `aaguidHex` (any spelling a record or the
  server holds, as hex) and `aaguidGuid` (the dashed GUID, as the server's
  `format_guid_candidate` builds an MDS entry's id).
- `shared/base64.js`: bytes on the wire are unpadded base64url; a field named for base64
  (`derBase64`, …) is standard base64. Decode with the strict `base64UrlToBytes` /
  `base64ToBytes`; `forgivingBase64ToBytes` only for typed text. No `atob`.
- `shared/native-json.js`: the browser's own WebAuthn JSON
  (`PublicKeyCredential.parseCreationOptionsFromJSON` / `parseRequestOptionsFromJSON`,
  `credential.toJSON()`; Chrome and Edge 129, Firefox 119, Safari 18.4). A begin answer's
  `publicKey` goes to the browser's parser as the server wrote it, and the credential's own JSON
  to the server; nothing is converted or merged on the way. A browser without the methods runs
  no ceremony: `UPDATE_BROWSER_TEXT` (`components/ceremony/UpdateBrowserNotice.tsx`).

## Backend (`server/app`)

- `app.py`: the WSGI entry point, `server.app.app:app = create_app()`, in a checkout and in the
  image alike (the Dockerfile copies `server/app` to `/app/server/app`). No `server.X` import
  fallbacks.
- `factory.py`: `create_app(config=None)`: the `config_from_env()` of each module in
  `CONFIG_SOURCES` (the seven config submodules that read the environment), then the
  overrides, then `INIT_STEPS` in order (`test_app_factory.py` pins it).
- `config/`: `application.py` (the bare app, and `add_after_request_once`), `logs.py`,
  `session_secret.py`, `compression.py`, `proxy.py`, `fetch_metadata.py` (a write under `/api/`
  whose `Sec-Fetch-Site` names another site is refused, 403), `session_cookie.py` (the cookie's flags
  and lifetime; only an answer that changed the session sets the cookie
  (`SESSION_REFRESH_EACH_REQUEST` off), so nothing landing after a ceremony's begin can undo
  it; and `cookie_size`), `security_headers.py` (the strict CSP, Trusted Types enforced for
  Next's two policies, reporting to `/api/csp-report`; `FIDO_SERVER_CONTENT_SECURITY_POLICY`
  replaces it),
  `origins.py`, `attestation_trust.py`, `relying_party.py` (the default RP name is the site's,
  `APP_TITLE`), `paths.py` (the project and instance roots; `store_dir`: every local store under
  `instance/`, its setting read when used), `request_limits.py` (8 MiB, the metadata
  upload 16 MiB; 413 in JSON), `web_export.py`. Importing it configures nothing, and the
  package re-exports nothing: routes call `relying_party.create_fido_server` and
  `origins.determine_expected_origin` through their modules, where tests patch them. Tests
  reach the entry point's app through `tests/app/entry_app.py`.
- Importing any module but the entry point writes nothing (`test_import_side_effects.py`). Log
  with `logging.getLogger(__name__)`. On Cloud Run (`K_SERVICE`) the app refuses to start
  without `FIDO_SERVER_SECRET_KEY` or `FIDO_SERVER_SECRET_KEY_FILE`; only local development
  generates `instance/session-secret.key`, and tests never do.
- `mds/`: the FIDO MDS snapshot. Its `__init__` imports nothing, so the updater takes
  `trust.py` (the MDS trust anchor), `blob.py` (the BLOB's chain to that root, which may end in
  a cross-certificate fido2's `parse_blob` refuses, its signature and payload), `files.py` (the
  snapshot's file names, its directory, the whole-file and `.gz` sibling writers, Last-Modified),
  `build.py` (the explorer rows; `certificates.py`, what their roots say), `snapshot.py` (a snapshot's seven files, from its BLOB, payload
  and cache state) and `sets.py` (the snapshot in Cloud Storage) without Flask.
  The runtime: `provisioning.py` (local files, Cloud Storage, upstream), `cache.py` (the
  loaders and their one `SnapshotCache`), `explorer_files.py` (what browsers load, derived from
  the full explorer snapshot: the list, the icons, each entry's detail; kept per snapshot by
  `cache.load_explorer_files`), `uploads.py` (a visitor's uploaded metadata),
  `entries.py`, `effective.py` (the snapshot merged with a visitor's uploads), `verifier.py` (the
  verified entries indexed from their JSON by fido2's keys, each parsed when found, a visitor's
  uploads in front).
- Leaves the rest import: `encoding.py` (base64, base64url and hex, written and read strictly),
  `json_values.py` (`make_json_safe`, and `as_bytes`, the one reading of a value as bytes),
  `aaguid.py` (an AAGUID's GUID spelling), `env_flags.py`.
- `visitor_session.py`: the namespace a visitor's uploads and credentials are stored under (its id
  in a signed cookie of its own, never the Flask session; the last-access touch, throttled in
  memory; and the one sweep of idle namespaces, on both backends).
- Routes: `routes/simple/` and `routes/advanced/` (begin/complete; the bodies are short
  orchestrators over modules named for their stage; the try blocks and the order of session
  reads are behaviour); `routes/ceremony_session.py` (every begin: refused, the session kept as
  it was, when its cookie would pass `MAX_COOKIE_SIZE`); `routes/json_body.py` (every route's
  JSON body: an object, or read as an empty one); `routes/mds.py` (the MDS routes and
  certificate decoding);
  `routes/codec.py` (`/api/codec`); `routes/web_export.py` (`/health`, and the export at `/`:
  the site's catch-all, since Flask has no static rule; HTML `no-cache`, `/_next/static/`
  immutable with the build's `.gz`, the export's 404 page, a plain 404 under `/api/`;
  `send_precompressed`); `routes/assets.py` (the explorer's
  files under `/assets/mds/`: the list at one URL revalidated by its ETag, the icons by digest,
  each entry's detail at `?v=<version>`; no snapshot file at any path); `routes/csp_report.py`
  (one WARNING line per violation, bounded);
  `routes/errors.py`.
- `webauthn/attestation/` (checks, trust, the root evaluation for every algorithm, ML-DSA
  included, certificate serialisation; `chain.py` verifies certificate chains with
  `verify_directly_issued_by` (RSA-PSS, EdDSA and ML-DSA too, which fido2's `verify_x509_chain`
  does not); `evaluation.py` checks an attestation against the MDS metadata step by step),
  `webauthn/signature_algorithms.py` (the one spelling of a signature algorithm),
  `webauthn/cose_algorithms.py` (a named COSE algorithm read, for both tabs),
  `webauthn/attachments.py` (the authenticator attachment hints),
  `webauthn/pqc.py` (the ML-DSA adapter),
  `webauthn/mldsa.py` (ML-DSA parameter sets, sizes and certificate keys),
  `webauthn/cose_keys.py` (RS384, RS512, PS384, PS512: the package imports it so fido2's
  `CoseKey` lookups find them), `webauthn/assertion_hash.py` (the Advanced tab's hash choice
  for an assertion), `webauthn/sign_count.py`, `webauthn/client_binary.py` (bytes a client
  sends, read one way for both tabs), `webauthn/client_credentials.py` (a saved credential the
  page sends back, read into its key material for both tabs), `webauthn/registration_facts.py`
  (what a verified registration's authData and extension outputs say, the relying party's view
  of it and the saved credential record, each in one key order for both tabs). `config/logs.py`
  holds `fido2.server`'s logger at WARNING: fido2 logs credential IDs at INFO.
- `storage/` (`credentials.py`, `credential_artifacts.py`, `session_metadata.py`,
  `github_mirror.py`, over `cloud.py` and `common.py`): every read-modify-write is
  compare-and-swap; a failed read raises `StorageReadError` (503), never a shorter list. **Read
  `docs/STORAGE.md` first.** `decoder/`: the Codec's server side (`decode/text.py` the entry,
  `encode/text.py` the encoder's, `values.py` the leaf both share); it shows what was sent and
  never repairs it. **Read `docs/DECODER.md` first.**
- A package's `__init__.py` is a docstring (`webauthn`'s imports `cose_keys`, and `decoder/edn`
  exports its two functions); the code lives in submodules named for what they do. Import the
  module that defines a name, call it through that module, and patch it there. Nothing in
  `server/app` imports in a cycle.

Data flow of a ceremony: the page collects the stored credentials; begin issues options and
keeps state in the Flask session, and only there; the browser
runs `navigator.credentials.create/get`; complete verifies with `create_fido_server(...)`; the
page updates the saved credentials, which both tabs show.

## Testing

- `pytest -q` (`tests/`); `cd web && npm test` (both vitest projects); `npm run e2e`.
  Targeted: `pytest -q tests/app/<file>.py`, `npx vitest run --project logic <path>`.
- A test of one module goes in that module's file (`test_<module>.py`, in its area's folder
  under `tests/app/`); a test of one behaviour across modules goes in a file named for that
  behaviour (`security/test_registration_race.py`, `storage/test_storage_read_errors.py`).
  Each test is named for the behaviour it checks. Older files named for neither (the
  `*_contracts`, `*_edges` files) take no new tests. Tests import the app's modules at the
  top; a shared helper lives once (`tests/app/fido2_stand_ins.py`,
  `tests/app/security/ceremony_helpers.py`, `tests/app/storage/credential_seed.py`, …).
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
- `test_plain_imports.py`: no `pytest.importorskip` of the app's own modules, `tools` or `tests`.
- `test_import_cycles.py`: no import cycle in `server/app`, and no import inside a function but
  the listed ones.
- `test_code_size_ratchet.py`: no function over 80 lines or module over 700 in `server/app`,
  with no exceptions.
- `test_test_names.py`: no test file or test named for how it was written (an uplift, a batch, a
  residual, a branch focus, coverage) rather than what it tests; in `web/`, every test file is
  named for a module beside it, and no file name or test title says such a word or "edge cases".
- `test_test_layout.py`: tests import first-party modules at the top, nothing writes
  `sys.modules`, no helper is defined twice, and (with the `tests/fixture_values.py` plugin) no
  fixture's value is or holds a module.
- `test_commit_messages.py`: the commit message check.

## Linting

`uvx ruff@0.16.8 check .` (config in `ruff.toml`; ruff is kept out of `uv.lock`). CI fails on
any violation of the gated set (`E4`, `E7`, `E9`, `F`, `I`, `UP006/UP007/UP035/UP045`), which is
at zero; `F821` has nothing ignored and there is no per-file ignore. Do not run `ruff format`
(the repo is not format-clean). No package re-exports names, so there is no `# noqa: F401`.

## Python dependencies

Declared in the root `pyproject.toml` (the app's manifest; the app is not a package), locked in
`uv.lock`; the image, CI and local venvs install from the lock (`uv sync --locked`). To change
one: edit `pyproject.toml`, `uv lock`, commit both. `fido2` is pinned exactly; Dependabot
proposes its minor releases, and a major one is a deliberate move (the characterization
goldens show what it changes).

## CI, deploys and bots

- Two independent pipelines run on a push to `main`: GitHub Actions and Cloud Build. A red CI
  run does not stop Cloud Build, so `cloudbuild.yaml` runs its own gate first: `Python tests`
  (ruff, pytest with `.coveragerc`'s floor) and `Web tests` (typecheck, both vitest projects
  with coverage, build, CSP scan, size budget) in parallel, then Build, Push and Deploy (Cloud Run `pqcwebauthn`). Playwright
  runs in GitHub CI only. Keep that gate: it is all that stands between a commit and production.
- Workflows (`ci-*.yml` run on `pull_request` and on `push` to `main`; `ci-security.yml` also
  weekly, since advisories land without a commit): `ci-python.yml`,
  `ci-web.yml` (web and the Playwright tests), `ci-docker.yml` (builds the image and checks it
  answers), `ci-security.yml` (`pip-audit`, `npm audit --audit-level=moderate` in `web/`, Trivy
  (its image pinned by digest) on the image; fix the dependency, never widen a threshold), `ci-repository.yml` (actionlint
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
  git and not baked into the image: `server/app/mds/provisioning.py` provides it at runtime
  (local files, then Cloud Storage, then a verified upstream refresh). Whatever writes the
  snapshot writes each file whole, metas last. Browsers load none of them: the server derives
  the explorer's list, icons and entry details from the snapshot it holds (`mds/explorer_files.py`).
- Cloud Storage holds immutable sets and `mds/current.json`, the pointer to one
  (`server/app/mds/sets.py`: create-only sets, a generation-checked pointer that only
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
