# AGENTS.md

A FIDO2/WebAuthn test platform (what the site does: `README.md`, `docs/FEATURES.md`). Flask serves
the API and the UI, `web/`, a Next.js static export served at `/`; no Node runs in production. The
server uses python-fido2 from PyPI (`fido2`, pinned exactly); what it adds lives in `server/app`.

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

## Before you change anything

Find which section or route owns the behaviour, whether the saved credentials are involved,
whether the server already returns what the page needs, and the smallest test that proves the
change. Prefer focused fixes; when you add a response field, change the page's handling and at
least one app test with it.

Read first:

- `docs/DESIGN.md` before changing anything under `web/`.
- `docs/STORAGE.md` before `server/app/storage`, the visitor's namespace or the credential log.
- `docs/DECODER.md` before `server/app/decoder`.
- `docs/MDS_SNAPSHOT.md` before `server/app/mds` or anything that provisions or publishes the
  snapshot.
- `deploy/README.md` before changing the deploy (`cloudbuild.yaml`, `deploy/`) or a setting the
  server reads: its "Environment variables" table lists every one, size limits included.

## Layout

- `server/app/`: the Flask app (factory, config, routes, WebAuthn, storage, the visitor session,
  decoder, MDS).
- `web/`: the UI (Next.js 15 Pages Router, TypeScript, Tailwind CSS v4). `web/src/logic` is
  its DOM-free logic in plain JavaScript; `web/e2e` its Playwright tests.
- `tests/`: `app/` (the Flask app, tooling guards, characterization; `python_fido2_vectors.py`
  holds the vectors taken from python-fido2's own tests), `pqc/`, `fixtures/` (the MDS fixture
  snapshot, `mds/snapshot`, with a statement to upload beside it, and the JSON lists the tests
  read: finding codes, registration algorithms, Simple usernames, MDS spellings, MDS roots with
  a negative serial).
- `tools/`: `update_mds_snapshot.py`, `build_static_assets.py` (precompresses the export at
  image build), `commit_messages.py` (the commit message check), `required_checks.py` (Cloud
  Build's wait for GitHub's browser tests and image check), `update_footer_year.py`,
  `subset_geist.sh` (Geist's two faces in `web/src/fonts`, with fonttools through `uvx`).
- `docs/`: `FEATURES.md`, `DESIGN.md`, `DECODER.md`, `STORAGE.md`, `MDS_SNAPSHOT.md`.
- `Dockerfile`, `cloudbuild.yaml` (the deploy gate), `deploy/` (Cloud Run service config,
  the checked deploy), `.github/` (workflows, the bot PR action).
- `LICENSE` (Apache 2.0). Third-party material keeps its own licence beside it: the Geist font
  (`web/src/fonts/OFL.txt`), python-fido2's test vectors (in `tests/app/python_fido2_vectors.py`).

## The UI (`web/`)

- `src/pages/`: `index.tsx` (the app shell), `404.tsx`, `500.tsx`, `_error.tsx` (Next's own
  error pages use style attributes the CSP refuses), `_app.tsx` (the fonts, on a wrapper holding
  `#app-root` and `#overlay-root`, so portalled overlays get them), `_document.tsx`.
- `src/styles/globals.css`: the design tokens. `@source not` keeps Tailwind out of `src/logic`
  and `src/test/logic`.
- `src/components/ui/`: the primitives (controls, text fields, `Overlay` with Dialog / Drawer /
  Sheet, `Toast`, `ConfirmDialog`, `MonoValue`, the table primitives, `ErrorBoundary`, …): use
  them rather than a new control.
- `src/components/shell/`: the header (it measures itself into `--header-height`), the footer
  (its year kept by `tools/update_footer_year.py`), and `AppShell`: it gives the route only to
  the section shown (the others get `CLOSED_ROUTE`), keeps each section, the credential details
  and the Analyze Browser panel in an error boundary, and loads the lazy chunks through
  `lib/lazyModule.ts` (which chunk loads when: docs/DESIGN.md, "What serves what").
- `src/lib/`: `sections.ts` (`SECTIONS`, `NAV_ID`, `APP_TITLE`, which is also the relying
  party's name; `routeFromHash` / `hashPath`), `useSection.ts` (the section and what is open
  inside it, in the hash: `open` pushes, `close`, `replace`, `closeAll`;
  `useSectionNavigation()`'s `GoToSection(section, path, handoff)` hands another section
  `route.handoff`, what the URL must not carry), `entrance.ts`, `lazyModule.ts`, `download.ts`,
  `useOverlayRoot.ts`.
- Sections (`src/components/`):
  - `simple/` and `credentials/`: the Simple tab, and the saved credentials both tabs share
    (`SavedCredentialsProvider`, at the shell's level). `CredentialDetailDialog` has four
    levels, each a pushed history entry: `#<section>/credential/<key>`, `…/registration`,
    `…/registration/certificate/<n>`, `…/registration/authenticator-data` (over an MDS entry,
    `#mds/<entryId>/credential/<key>…`); a level the credential lacks is corrected upward. Each
    part a level shows has "Decode in Codec" (`components/codec/DecodeInCodec.tsx`), and Back
    from the Codec finds the level as it was left (`detail/useReturnFromCodec.ts`).
  - `advanced/`: Registration and Authentication segments, both mounted, each a form beside its
    JSON editor. `requestEditor.ts`: the editor's text is the request, and a form change
    rewrites in it only what it changed (`followForm`). `useRegistrationHandoff` sets an MDS
    statement's settings with the form's own setters. `fieldText.ts` is the only copy of the
    form's labels, options, errors and info popups (English and 中文).
  - `codec/`: Decode / Encode; a payload handed to it is decoded in Decode. Its tests render real
    answers from `src/test/codec-answers.json`, which `tests/app/tooling/test_web_codec_answers.py`
    keeps equal to what `/api/codec` answers (`CODEC_ANSWERS_WRITE=1` rewrites it).
  - `mds/`: the explorer, an entry and its certificates (`EntryRouter`; `CondensedBar` is
    portalled into the overlay root, since an entering section is a transform), the details
    dialog over an entry (`routeUnderEntry.ts`), Try in Advanced, Manage Metadata, and
    `entryLink.ts` (`#mds/aaguid:<aaguid>`).
  - `analyze-browser/`: the Analyze Browser panel.
- Tests: vitest with two projects (`web/vitest.config.mts`): `components` (Testing Library;
  `src/test/setup.ts` makes queries wait up to 30 s, for the deploy gate's load) and `logic`
  (`src/test/logic/setup.js`: a fresh storage, `fetch` mock and document per test). Helpers are in
  `src/test/`: `app.tsx`'s `renderApp` is the one way a test renders the whole app (it imports
  every lazy chunk first; `test_web_source_rules.py` holds every `AppShell` test to it);
  `credentials.ts` keeps records in the storage, `fetch.ts` answers `fetch` by path, `mds.ts`
  serves the fixture as Flask does, from `src/test/mds-files.json`, which
  `tests/app/tooling/test_web_mds_files.py` keeps equal to what the server serves
  (`MDS_FILES_WRITE=1` rewrites it), `advanced.tsx`. `src/test/logic/` holds the real ceremonies
  from the characterization goldens and `repo-file.js` for files under the repository. The
  `@test-fixtures` alias is `tests/fixtures`.
- `e2e/` (Playwright, Chromium): `serve-flask.mjs` starts Flask with every store in a
  temporary directory and a copy of the MDS fixture as its snapshot; `virtual-authenticator.ts`
  adds a CTAP2 authenticator through the DevTools WebAuthn domain; `fixtures.ts` fails a test on
  any console error, page error or CSP report; `design-rules.ts` finds grey fills. The
  `*-recorded` specs compare a page's words with a recording in `e2e/recorded/`: a recording is
  never edited, and an intended change is an expected difference with its reason (the user name
  `paritycheck` is data inside a recording). `stored-records.spec.ts` loads what an earlier
  release stored in visitors' browsers. Every section is mounted once its chunk has arrived,
  and both Advanced segments with it: scope a query to its tabpanel
  (`#advanced-ceremony-panel-<segment>`), and wait for a section's content, not its panel
  (the placeholder answers to the same name).
- `scripts/`: `check-export-csp.mjs` scans every exported HTML file; `check-size-budget.mjs`
  holds the build's chunks, raw and gzipped, to their budgets; `dev-csp.mjs` is the CSP
  `npm run dev` sends (Flask's, plus the two allowances the dev server needs); `code-size.mjs`
  holds `src` (tests and `src/test` aside) to no function over 120 lines and no module over 400,
  with no exceptions (`code-size.test.ts` runs it in `npm test`).

Running it (Node 22, in `web/`): `npm ci`; `npm run dev` (at `http://localhost:3000/`, proxying
`/api` and `/assets/mds` to `FLASK_URL`, default `http://localhost:8000`; ceremonies need
Flask's origin, so use the export for those); `npm run build` (the export in `web/out`, which
Flask serves; `FIDO_SERVER_WEB_EXPORT_ROOT` points elsewhere); `npm run typecheck` (covers
`e2e/`, and through `tsconfig.logic.json` checks the logic's JSDoc types with `checkJs`);
`npm test`; `npm run test:coverage`; `npm run check:csp` and `npm run check:size` (after a
build); `npm run e2e` (after a build; `npx playwright install chromium` once; `E2E_PYTHON` names
the Python with the app's dependencies, `.venv/bin/python` by default; `E2E_PORT`, default
5151).

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

- `credentials/storage/` (`records.js`, `local/`): the saved credentials, one `localStorage`
  array visitors' browsers already hold. Its first read is cached until another tab changes it;
  tests seed it with `seedUnifiedCredentialRecords`. `local/record-migration.js` brings records
  saved by earlier versions to today's format as they are read: when a stored format changes,
  add a step there with an old-format fixture in `src/test/logic/credentials/storage/`. A Simple
  username is `local/simple-credentials.js`'s `simpleUsername`: trimmed as the server trims it,
  then compared exactly, so "Alice" and "alice" are two accounts, on both sides
  (`tests/fixtures/simple-usernames.json`).
- `simple/ceremony.js`: the Simple tab's two ceremonies, their requests and every step's sentence.
- `advanced/`: `registration/` and `authentication/` (each its `request.js`, validation and
  `ceremony.js`; `registration/` also `statement-settings.js` and `statement-changes.js`, what
  an MDS statement says a registration can take), `editor/` (the editor's model and keys;
  `request-patch.js`, `followForm`), and `response-parts.js` (what of a response the Codec
  reads). An authentication offers and sends every saved credential, the Simple tab's too
  (`prepareAdvancedCredentialsForServer`).
- `credentials/`: the saved list, deletion (`delete-flow.js`: from the server's storage first,
  then from this browser), `deletion-signal.js`, `resident-key.js`, and a credential's details
  and registration view as data (`registration/`, `certificates/`, `detail/`). Signal a
  credential as unknown only after its deletion here, never on a server's answer that it is
  unknown (one this browser lacks may be another browser's). A stored `residentKey` is never
  read (earlier versions derived it from BE or the request). Registration snapshots
  (`schemaVersion` 2) hold the registration as data, never markup, and its certificates without
  their DER; older composed HTML is never read.
- `codec/`: the Codec's requests, results and values. `mds/`: the explorer's loading, filters,
  sort, columns, rows, entry, certificate and Manage Metadata (the server builds each row:
  `mds/build.py`, and the list: `mds/explorer_files.py`).
- `browser/`: the Analyze Browser's facts. It reports what the browser says and where each answer
  came from, or that it cannot know; it never guesses. Web pages cannot ask which transports a
  browser supports: do not add WebUSB/WebHID/Bluetooth/Serial checks. The identity cases are real
  user-agent strings with Client Hints in `src/test/logic/browser/identity-matrix.js`; add a
  browser there.
- `shared/failed-response.js`: the one reader of a failed response (`readFailedResponse`,
  `FailedResponseError`). Never show a raw response body.
- `shared/ceremony-result.js` (the result panel's sentences) and `shared/registration-findings.js`
  (`answerFindings`: where an answer holds a ceremony's findings).
- `shared/attestation-findings.js`: the one table of the findings' sentences, English and 中文
  (`FINDING_SENTENCES`, its codes held to `tests/fixtures/attestation-finding-codes.json`). Only
  the findings list's chunk imports it.
- `shared/aaguid.js`: `aaguidHex` (any spelling as hex) and `aaguidGuid` (the dashed GUID).
- `shared/base64.js`: bytes on the wire are unpadded base64url; a field named for base64
  (`derBase64`, …) is standard base64. Decode with the strict `base64UrlToBytes` /
  `base64ToBytes`; `forgivingBase64ToBytes` only for typed text. No `atob`.
- `shared/native-json.js`: the browser's own WebAuthn JSON (`parseCreationOptionsFromJSON` /
  `parseRequestOptionsFromJSON`, `credential.toJSON()`). A begin answer's `publicKey` goes to the
  browser's parser as the server wrote it, and the credential's own JSON to the server; nothing
  is converted or merged on the way. A browser without the methods runs no ceremony:
  `UPDATE_BROWSER_TEXT` (`components/ceremony/UpdateBrowserNotice.tsx`).

## Backend (`server/app`)

Running it (Python 3.12+, at the root): `uv sync --locked`, then
`ENABLE_GITHUB_LOGGING=0 uv run flask --app server.app.app run --port 8000` serves the API and
the export in `web/out` (after `npm run build`) at `http://localhost:8000/`, where `npm run dev`'s
`FLASK_URL` finds it; open `localhost`, not `127.0.0.1`, which is no RP ID. A first run writes
`instance/session-secret.key`, and the stores fill `instance/` as you use them; the explorer's
entries need a snapshot ("The FIDO MDS snapshot", below). `ENABLE_GITHUB_LOGGING=0` keeps a
`GITHUB_TOKEN` in your shell from copying your registrations and uploads to the credential log.

- `app.py`: the WSGI entry point, `server.app.app:app = create_app()`, in a checkout and in the
  image alike. No `server.X` import fallbacks.
- `factory.py`: `create_app(config=None)`: the `config_from_env()` of each module in
  `CONFIG_SOURCES`, then the overrides, then `INIT_STEPS` in order (`test_app_factory.py` pins it).
- `config/`: one module per concern. Importing it configures nothing, and the package
  re-exports nothing: routes call `relying_party.create_fido_server` and
  `origins.determine_expected_origin` through their modules, where tests patch them. Every
  limit and quota the environment can set is read in `request_limits.py`; the figures are in
  deploy/README.md ("Environment variables"), docs/STORAGE.md ("Quotas") and docs/DECODER.md
  ("Limits"). A fixed bound is a constant of the module that applies it. Tests reach the entry
  point's app through `tests/app/entry_app.py`.
- Importing any module but the entry point writes nothing (`test_import_side_effects.py`). Log
  with `logging.getLogger(__name__)`, and text a client chose (a file name, a path, the Advanced
  tab's free-text username) through `log_text.client_text`. `config/logs.py` holds
  `fido2.server`'s logger at WARNING: fido2 logs credential IDs at INFO. Tests never generate
  the session secret.
- `mds/`: the FIDO MDS snapshot. Its `__init__` imports nothing, so the updater takes the leaves
  (`trust`, `blob`, `revocation`, `files`, `build`, `statement_fields`, `certificates`,
  `entries`, `snapshot`, `explorer_files`, `sets`) without Flask. `statement_fields.py`'s
  spellings, and the page's static filter options, are held to
  `tests/fixtures/mds-enum-spellings.json`. `listed_uploads.ROW_FORMAT` and
  `explorer_files.DERIVED_FORMAT` move with what they keep or derive.
- Leaves the rest import: `encoding.py` (base64, base64url and hex, written and read strictly),
  `json_values.py` (`make_json_safe`, and `as_bytes`, the one reading of a value as bytes),
  `aaguid.py`, `env_flags.py`, `log_text.py`, `accept_encoding.py`.
- `visitor_session.py`: the visitor's namespace (docs/STORAGE.md). `challenge_registry.py`: each
  ceremony's challenge used once (the session is a client-side cookie, so popping it does not
  stop a replay). `csp_reports.py`, `startup.py` (the Cloud Run warm-up).
- `routes/simple/` and `routes/advanced/`: begin and complete, short orchestrators over modules
  named for their stage. Each Simple ceremony keeps its state under its own session key; the try
  blocks and the order of session reads are behaviour. A registration complete reads the
  attestation (`extract_attestation_details`) only once the state is consumed and fido2
  accepted the response. The Simple tab refuses a registration or a sign-in only on an integrity
  error (`INTEGRITY_ERRORS`), every other finding its warning; the Advanced tab completes and
  reports them all (`attestationErrors`, `assertionErrors`); a warning is the answer's `warnings`
  in both. An Advanced complete is for the RP ID its begin kept beside its state.
- `routes/json_body.py`: every route's JSON body, an object or read as an empty one (malformed
  JSON too). Only RFC 8259's JSON: `NaN`, `Infinity`, `-Infinity` and a number no double holds
  are refused, and so is a body nested more than 64 deep or holding more than 100,000 values
  (`MAX_VALUES`), each a 400 in JSON, the CSP report's too. Never read a body through
  `request.get_json`, whose reader takes them.
- `routes/ceremony_errors.py`: a refused response's answer, fido2's findings as fido2 wrote
  them, else a sentence of the app's own, and one WARNING line, never the exception's text; what
  fails after fido2 accepted is a 500. No answer carries an exception's text but the codec's,
  written to be shown. Both tabs' completes refuse, before fido2 reads it, CBOR past its bounds
  (`webauthn/cbor_bounds.py`) and a number where fido2 reads bytes (`webauthn/byte_members.py`).
- `routes/errors.py`: every HTTP error under `/api/` is answered in JSON, `{"error": sentence}`
  (a path no API route holds 404 whatever the method, a method a route does not take 405 with
  `Allow`, an unhandled exception 500); pages keep their HTML.
- `routes/web_export.py` (`/health` and the export at `/`: docs/DESIGN.md), `routes/assets.py`
  (the explorer's files, never a snapshot file: docs/MDS_SNAPSHOT.md), `routes/mds.py`,
  `routes/codec.py`, `routes/csp_report.py`, `routes/ceremony_session.py` (a begin's cookie size).
- `webauthn/attestation/`: a registration's checks, which `checks.py` runs in order. A format
  fido2 cannot verify, a compound attestation included, is `unsupported_attestation` naming it:
  not checked, its signature and root `null`, never `attestation_signature_invalid`. A root is
  valid only once the chain verified to it; one from the visitor's own uploads is valid with
  `metadata_not_fido_trusted`.
  Every finding is a code from `error_codes.py` (`tests/fixtures/attestation-finding-codes.json`
  lists them), with a reason after `: ` only when the exception has one; `INTEGRITY_ERRORS` are
  the ones the Simple tab refuses on. `constants.UNREADABLE_EXTENSIONS` is caught wherever a
  certificate's extensions are read. Both x5c readers (`certificates.py`, `trust.py`) take a
  certificate of at most 64 KiB and a chain's first 10 entries, and read an entry only from
  bytes, text or a certificate view, never with `bytes(value)`. What a registration keeps, once
  each: docs/STORAGE.md.
- `webauthn/`: `signature_algorithms.py` (the one spelling of a signature algorithm),
  `cose_algorithms.py` (a named COSE algorithm read; `PREFERRED_REGISTRATION_ALGORITHMS`, the one
  order a registration offers, most preferred first: docs/FEATURES.md, "Algorithms";
  `tests/fixtures/registration-algorithms.json` holds the Advanced form to it), `cose_keys.py`
  (RS384, RS512, PS384, PS512: the package's `__init__` imports it so fido2's `CoseKey` lookups
  find them), `pqc.py` and `mldsa.py` (ML-DSA); `assertion_checks.py`, `client_credentials.py`,
  `client_binary.py` and `registration_facts.py` read or build each thing one way, in one key
  order, for both tabs.
- `storage/` (`credentials.py`, `credential_artifacts.py`, `session_metadata.py`,
  `github_mirror.py`, `github_outbox.py`, over `cloud.py`, `common.py` and `record_format.py`):
  the stores (docs/STORAGE.md: compare-and-swap, what a failed read raises, the quotas, and the
  credential log on GitHub, on only with `GITHUB_TOKEN`; no request waits for it).
- `decoder/`: the Codec's server side (docs/DECODER.md); it shows what was sent and never
  repairs it.
- A package's `__init__.py` is a docstring (`webauthn`'s imports `cose_keys`, and `decoder/edn`
  exports its two functions); the code lives in submodules named for what they do. Import the
  module that defines a name, call it through that module, and patch it there.

Data flow of a ceremony: the page collects the stored credentials; begin issues options and
keeps state in the Flask session, and only there; the browser runs
`navigator.credentials.create/get`; complete verifies with `create_fido_server(...)`; the page
updates the saved credentials, which both tabs show.

## Testing

- `pytest -q` (`tests/`); `cd web && npm test` (both vitest projects); `npm run e2e`.
  Targeted: `pytest -q tests/app/<file>.py`, `npx vitest run --project logic <path>`.
- A test of one module goes in that module's file (`test_<module>.py`, in its area's folder
  under `tests/app/`); a test of one behaviour across modules goes in a file named for that
  behaviour (`security/test_registration_race.py`, `storage/test_storage_read_errors.py`).
  Each test is named for the behaviour it checks. Filenames ending in `_contracts.py`
  or `_edges.py` are refused by `test_test_names.py`. Tests import the app's modules at
  the top; a shared helper lives once (`tests/app/fido2_stand_ins.py`,
  `tests/app/security/ceremony_helpers.py`, `tests/app/storage/credential_seed.py`, …).
- `make_app` (`tests/app/conftest.py`) builds an app from the environment at that moment:
  `monkeypatch.setenv` before it. Do not `importlib.reload` config modules. pytest never reads
  `web/out` (the `export_root` fixture builds a small export).
- `tests/conftest.py` points `FIDO_SERVER_MDS_SNAPSHOT_DIR` at an empty directory of the run's
  and turns the upstream refresh off; a test that needs a snapshot uses
  `mds_fixture_snapshot`, a copy of `tests/fixtures/mds/snapshot`, which `mds_fixture.py` builds
  with the updater's own code (`MDS_FIXTURE_WRITE=1` rewrites it).
- `tests/app/characterization/` records what the ceremony routes, the decoder and the
  attestation serialisers answer, byte for byte, in a pinned environment, against `golden/`.
  `CHARACTERIZATION_WRITE=1 pytest tests/app/characterization` rewrites them after an intended
  change; review the diff (`encoding_diff.py` tells byte-spelling-only diffs).
- `tests/checkout_guard.py` fails the run when a test changed anything under `server/runtime/`,
  `instance/` (which holds the MDS snapshot too) or `.hypothesis/`. Give a test its own stores
  in `tmp_path`.

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
  residual, a branch focus, coverage) rather than what it tests; no `_contracts.py` or
  `_edges.py` filename; in `web/`, every test file is
  named for a module beside it, and no file name or test title says such a word or "edge cases".
- `test_test_layout.py`: tests import first-party modules at the top, nothing writes
  `sys.modules`, no helper is defined twice, and (with the `tests/fixture_values.py` plugin) no
  fixture's value is or holds a module.
- `test_attestation_finding_codes.py`: every finding the attestation checks write is a code, and
  they are the codes `tests/fixtures/attestation-finding-codes.json` lists.
- `test_commit_messages.py`: the commit message check.

## Linting

`uvx ruff@0.16.8 check .` (config in `ruff.toml`; ruff is kept out of `uv.lock`). CI fails on
any violation of the gated set (`E4`, `E7`, `E9`, `F`, `I`, `UP006/UP007/UP035/UP045`), which is
at zero; `F821` has nothing ignored and there is no per-file ignore. Do not run `ruff format`
(the repo is not format-clean). Only `decoder/edn` re-exports names (its two functions, in
`__all__`), so there is no `# noqa: F401`.

## Python dependencies

Declared in the root `pyproject.toml` (the app's manifest; the app is not a package), locked in
`uv.lock`; the image, CI and local venvs install from the lock (`uv sync --locked`). To change
one: edit `pyproject.toml`, `uv lock`, commit both. `fido2` is pinned exactly; moving it is a
deliberate change (the characterization goldens show what it changes).

## CI, deploys and bots

- Two independent pipelines run on a push to `main`: GitHub Actions and Cloud Build, whose
  `cloudbuild.yaml` runs its own test gate, then builds, waits for GitHub's checks and deploys
  (deploy/README.md says how). Keep that gate: it is all that stands between a commit and
  production. Playwright runs in GitHub CI only; the GitHub checks step's job names are held to
  the workflows' (`test_required_checks.py`), and `deploy/deploy-revision.sh` to its checks
  (`test_deploy_revision.py`).
- Workflows (`ci-*.yml` run on `pull_request` and on `push` to `main`; `ci-security.yml` also
  weekly, since advisories land without a commit): `ci-python.yml`, `ci-web.yml` (web and the
  Playwright tests), `ci-docker.yml` (builds the image and checks what it answers),
  `ci-security.yml` (`pip-audit`, `npm audit --audit-level=moderate` in `web/`, Trivy on the
  image; fix the dependency, never widen a threshold), `ci-repository.yml` (actionlint, and on a
  push `tools/commit_messages.py` over the pushed commits), `ci-scheduled-runs.yml` (warns while a
  scheduled workflow's latest run on `main` has failed: add any new scheduled workflow to its
  list).
- Every action is pinned to a commit SHA (or an image digest) with its version in a trailing
  comment. No workflow pushes to `main`: `update-footer-year.yml` opens pull requests through
  `.github/actions/open-bot-pr` (merge them by rebase or cherry-pick, so each commit keeps a
  one-line message); `update-fido-mds.yml` publishes a newer verified MDS snapshot to the
  bucket twice a day, signed in through Workload Identity Federation (no key in GitHub).
- Coverage is a gate: `.coveragerc`'s floor and `web/vitest.config.mts`'s (every logic file at
  100 %).
- `npm ci` everywhere. If a lock regeneration drops foreign-platform native builds, delete
  `node_modules` and the lock and `npm install` from clean (npm/cli#4828). `web/package.json`
  overrides Next 15's pinned `postcss`. The site stays on Next 15, TypeScript 5 (which Next 15's
  build checks with) and Node 22.
- No bot opens dependency pull requests (there is no `.github/dependabot.yml`):
  `ci-security.yml`'s audits, on every push and weekly, are the alert, and a dependency moves by
  hand when one fails or a change needs it.
- The Dockerfile's first stage builds `web/` and scans the export; only `web/out` reaches the
  runtime image, precompressed by `tools/build_static_assets.py`. The runtime stage's
  `apt-get upgrade` keeps fixable Debian CVEs out of the image. The server runs as uid and gid
  10001, which owns only `/app/instance`: whatever it writes at run time goes there (the MDS
  snapshot a cold start provisions; locally the session secret and the stores). gunicorn's
  control socket is off.

## The FIDO MDS snapshot

Generated files in `instance/mds-snapshot/` (`FIDO_SERVER_MDS_SNAPSHOT_DIR` puts them
elsewhere), provided at run time; docs/MDS_SNAPSHOT.md has the whole picture.

- Locally, run `python tools/update_mds_snapshot.py` once. Without a snapshot the list answers
  404 and the explorer shows only the session's uploads, if any: the documented fallback, not a
  bug.
- Never commit those files, and never write a test that reads the real snapshot directory.

## Gotchas

- The CSP has no `'unsafe-inline'`: an inline handler, `<script>` or `style` attribute simply
  does not run. Style at run time through the CSSOM from a ref.
- The Simple and Advanced tabs share the saved credential list and its storage: verify both
  flows when you touch either. Advanced authentication uses Simple credentials too, for the
  `rpId` its request names (the page's host by default), while a Simple credential is for
  `FIDO_SERVER_RP_ID`: the two agree in production and in the e2e tests (`localhost`). It
  writes nothing on the server, so the server's record of a Simple credential's counter lags
  until the next Simple sign-in, which compares with the page's copy too.
- fido2 finds a COSE key class by walking `CoseKey`'s subclasses, and the first class with an
  algorithm ID wins: an app subclass can add an algorithm, never replace fido2's.
- Exported HTML carries attributes: state that feeds an attribute starts at its build-time
  value and changes after hydration, or hydration differs.
- A hash navigation does not reload the page: in a Playwright test, reload after writing to
  `localStorage` before going to a deep URL.
