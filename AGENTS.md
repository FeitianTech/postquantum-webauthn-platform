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
- `tests/`
  App, library, PQC, and optional device tests.
- `fido2/`
  Local Python FIDO2 implementation used by the app. Treat changes here as library-level changes, not normal UI work.

## Frontend Map

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

Important templates:

- `frontend/templates/simple/tab.html`
- `frontend/templates/advanced/tab.html`
- `frontend/templates/decoder/tab.html`
- `frontend/templates/shared/navigation.html`

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
  `session_cookie.py`, `security_headers.py`, `origins.py`, `attestation_trust.py`,
  `mds.py`, `relying_party.py` (RP ID, `create_fido_server`), `paths.py`. Importing
  it configures nothing. The routes call `config.create_fido_server` /
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
  development generates and persists `instance/session-secret.key`.
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
  hold nothing for the credential fall back to the browser's copy. `credential_list.py`
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
  the `general` blueprint. `static_assets.py` has its own `static_assets`
  blueprint. Endpoint names are therefore `general.index`, `simple.register_begin`
  and so on; nothing refers to them today (no `url_for`).

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
  `common.py`.
  Every read-modify-write of credential records (the signature counter, appending a
  registration) goes through `read_for_update` / `save_if_unchanged`,
  compare-and-swap: a GCS generation precondition, or locally an `flock` on the
  file's `.lock` beside it (`common.file_lock`, with `common.replace_file` and
  `common.file_digest`). `delkey` empties the current copy -- it leaves it in place,
  holding no records, whenever any copy existed -- and removes every legacy copy,
  locally under that lock. A save whose records came from a legacy copy holds "there
  is no current copy" as its version; a removed current copy would make that true
  again and let the save write deleted records back.
  A store read tells three cases apart. Nothing stored is fine. A copy or a listing
  that cannot be read (an I/O or Cloud Storage error) raises `common.StorageReadError`,
  never a shorter list; `routes/errors.py` answers 503. Content that does not decode
  is logged by file or object name (never its content) and skipped, and
  `iter_credentials` / `list_credentials` count it in their `undecodable` list. The
  first copy that exists is the user's: an older one never stands in for it.
  `read_for_update` refuses a current copy it cannot decode
  (`credentials.CredentialsUndecodable`) rather than let the save replace it unread,
  and with no current copy it refuses a first legacy copy that does not decode: the
  save would shadow it, and delete a session `.pkl`, unread.
  Credential artifacts (`server/app/credential_artifacts.py`) are kept per session
  on both backends (locally `<artifact dir>/<session>/`) and merge the same way:
  conditional on the generation on GCS, under the record's `flock` locally. Their
  reads keep the same three cases: an artifact that cannot be read raises
  `StorageReadError` (503), one that does not decode is logged by name and treated
  as absent. A merge that cannot read the record, or whose record does not decode,
  refuses rather than overwrite it, and one whose write raised is re-read: it counts
  as stored if the record holds every merged value.
  Listings stay inside what they need: the legacy pass lists `user-data/` with the
  `/` delimiter, so it never walks every session's objects, and
  `session_metadata.list_sessions` reads session names as prefixes
  (`cloud.list_prefixes`), so a flat legacy object is not a session.
  `tests/app/storage/fake_gcs.py` records each listing's prefix and delimiter.
  A name the store refuses raises `common.InvalidStorageIdentifier`, a `ValueError`
  that `routes/errors.py` answers with 400 and no traceback.
- `server/app/decoder/`
  Decoder/encoder logic used by the developer tooling UI: `decode/` and `encode/`.
  `ctap_tables.py` is the one CTAP table both read (command and status bytes,
  request parameters, response members), derived from the vendored `fido2`; COSE
  algorithm names come from `webauthn/pqc.py`'s `describe_algorithm`. Do not add
  another copy of either. Encoder bytes come only from `decoder/cbor_canonical.py`,
  which writes CTAP2-canonical CBOR; do not serialise encoder output with cbor2.
  Decoder input is parsed only by `decode/cbor_parser.py`: strict, failing with
  the offset and path where input stops being well-formed; lenient only when a
  request sends `"lenient": true`, and the response then lists what it skipped.
  Never decode input with `fido2.cbor`, cbor2 or fido2's `AttestationObject` /
  `AuthenticatorData` (`test_decoder_parses_cbor_only_itself.py` checks).
  `decode/canonical.py` reports CTAP2 canonical-form violations as `findings` on
  every decode; the CTAP2 key order is `decoder/ctap2_order.py`, shared with the
  encoder. The decoder shows what was sent: it never synthesizes or drops a field
  (the old "repair" code did, for a set of corrupt captures), and bytes after the
  top-level item are reported, never decoded or dropped. Map keys become JSON keys
  only through `keys.json_keys`: keys that would share a spelling (1 and "1",
  h'01' and "01") are each spelled with their type, and `decode/key_collisions.py`
  reports the map as `json-key-collision`. A CTAP member label applies only to an
  integer key in a CTAP message; user entities, credential descriptors and
  attestation objects are read by their text keys. Text that is both hex and a JSON
  number is read by the precedence in `decode/ambiguous_input.py` (hex only when it
  is one well-formed CBOR item), and the response names the reading not taken.
  Interpretation sits beside the decoded value, never in place of it:
  `decode/interpretations.py` adds `data.extensionsDecoded` (`decode/extensions.py`,
  CTAP 2.2 section 12 and WebAuthn L3 section 10) and `data.attestationStatementDecoded`
  (`decode/attestation_statement.py`, WebAuthn L3 section 8, which calls
  `tpm_structures.py`, `android_key.py`, `safetynet.py`, `apple_anonymous.py`), and
  `decode/get_info.py` reads authenticatorGetInfo. It shows, it does not verify:
  every attestation view says so and lists what it did not check. CTAP numbers and
  names (getInfo members and options, extension identifiers) go in `ctap_tables.py`,
  COSE registries in `decoder/cose_tables.py` (shared with `encode/cose_key.py`).
  DER is read only through `cryptography` (`x509` and `hazmat.asn1`), never by hand.
  Findings inside authData, a nested PublicKeyCredential field or a TPM structure
  carry the input offset and path (`${2}<credentialPublicKey>{1}`; a nested field's
  findings add `source`). `decode/ctap.py` and `decode/pipeline.py` are under the
  module size limit now; keep them there by putting new code in a module named for
  what it does, as `ctap_prefix.py` (the command or status byte), `findings.py`
  (collecting and ordering findings), `ctap_responses.py` (makeCredential and
  getAssertion response views), `authenticator_data.py`, `json_input.py`,
  `edn_view.py`, `key_equivalence.py` and `ctap_conformance.py` are. The encoder
  refuses a decoded-JSON member it cannot rebuild rather than dropping it; that
  includes a CTAP member whose value is null.

  `decodedValue` is JSON, so it is lossy by nature: it cannot show a key's CBOR
  type, a head's width, a chunked string, a float's width, a NaN's payload or a
  duplicated key. `data.edn` is the lossless view beside it, the item in extended
  diagnostic notation (RFC 8949 section 8, draft-ietf-cbor-edn-literals), written by
  `decoder/edn/spell.py` with an encoding indicator only where the bytes differ from
  preferred serialisation. It is given for CBOR readings (a plain item, a CTAP
  message's item past its command or status byte, which stays in `data.ctap`, and
  an attestation object), and only when it is exact: `decode/edn_view.py` reads the
  text back and compares it with the item's bytes, so a tree the lenient parser
  could not read whole gets no EDN rather than a wrong one (`spell` itself refuses a
  node whose text would not span its bytes, which catches damage the lenient parser
  leaves unmarked). The encoder's EDN input
  (format `EDN`, also `edn (exact bytes)` and `cbor (edn)`) is `decoder/edn/reader.py`:
  it writes exactly the bytes the text notates -- map order, duplicate keys, head
  and float widths as written, never canonicalised -- and refuses, with the offset in
  the text as sent, reserved indicators, an indicator too narrow for its value, a
  float not exact at its width or beyond a double's range, `simple(24..31)`, a signed
  tag number, a `(_ ...)` chunk that is not a byte or text string, a lone surrogate,
  items nested more than 64 deep (the decoder's limit), a CBOR sequence and an
  integer beyond 64 bits.
  That last is a deliberate departure from the EDN draft, which reads such an
  integer as a bignum: write the tag, `2(h'...')`. So encoder bytes come from
  `decoder/cbor_canonical.py` for JSON input and from `edn` for EDN input, and every
  CBOR head either writes goes through `decoder/cbor_head.py`. Decode then encode of
  `data.edn` gives back the input's bytes: `tests/app/decoder/test_edn_round_trip.py`
  proves it with Hypothesis over generated items (`tests/app/cbor_items.py`: every
  head width, chunked and zero-chunk strings, duplicate keys, nested tags, raw-bit
  floats) and over every CBOR input in the goldens and fixtures
  (`tests/app/codec_corpus.py`), at the module and at the API. Hypothesis writes
  `.hypothesis/` in the working directory whatever its `database` setting, so
  `tests/conftest.py` points `HYPOTHESIS_STORAGE_DIRECTORY` at a temporary directory
  and loads a derandomized profile with no example database.

  Map keys are equal by RFC 8949 section 5.6.1 (`decode/key_equivalence.py`): 1.0 at
  any width is one key, -0.0 and 0.0 are one key, a chunked string equals the same
  text unchunked, NaNs differ by payload, 1 and 1.0 differ. Equal keys are one entry
  of `decodedValue` (the later value) and one `duplicate-map-key` finding at the entry
  kept, whose `earlier` lists every earlier entry's offsets and key and value in EDN;
  inside a value the decoded value drops, `kept` is null and the message says none is
  kept (`duplicate-json-key` does the same).
  A key `json_keys` spells with its type is written by `keys.qualified_key_text` and
  read back only by `keys.read_json_key`, which the encoder uses for every object key
  it writes: `"1" (text)`, `h'01' (bytes)`, `1.5 (float)`, `[1, 2] (array)`. A key
  that looks typed (an EDN literal, then ` (<kind>)`) but whose kind is unknown, or
  one a lenient decode could not read, is an error naming the key; anything else is
  a text key, so `Temperature (C)` stays text. Two JSON keys that make equal CBOR
  keys are refused, naming both. JSON input is read by `decode/json_input.py`, which
  reports a key given twice in one object as `duplicate-json-key` (the path, the
  value kept and the values dropped; no offset, which the JSON reader cannot give);
  the encoder refuses such input and points at EDN, which can express it. The
  encoder shows the JSON it was given back with its keys as written (`keys.as_written`
  marks them `JsonLabel`), so its own output can be pasted back in.

  The encoder never reads a plain map as a CTAP message. It encodes CTAP from
  `ctapDecoded`, from `expandedJson` beside a `ctap` object, or from the
  `ctap-webauthn` format; anything else in format `CBOR` is generic CBOR, so
  `{"1": "a"}` is `a161316161`. A makeCredential or getAssertion view shows every
  key of the map, spelling a non-integer key with its type, and
  `decode/ctap_conformance.py` reports each as `ctap-non-integer-key`.

  `malformed` lists the messages of the findings that the input is not well-formed
  (RFC 8949 appendix F, trailing bytes included) or not in CTAP2 canonical form: the
  categories `skipped`, `malformed`, `trailing` and `canonical` in
  `decode/findings.py`. Notes about how the input was read or shown
  (`ambiguous-input`, `json-key-collision`, `duplicate-json-key`, `ctap-prefix-not-read`,
  `ctap-non-integer-key`, a CTAP limit) are in `findings` only.

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

Four checks guard the code and the checkout rather than behaviour:

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
  reviewed before committing. `material.py` builds the keys and certificates
  deterministically; the only frozen input is ML-DSA signatures (`inputs/frozen.json`),
  since ML-DSA signing is randomised.
- `tests/conftest.py` fails the run when a test created, changed or removed anything
  under `server/runtime/`, `instance/`, the legacy credential stores
  (`server/app/session-credentials/`, `server/app/*_credential_data.pkl`),
  `.hypothesis/` or the MDS snapshot files in `frontend/static/`.
  What is there mixes the owner's local data with old test leftovers: the guard
  compares listings from before and after the run, and never deletes. Give a test its
  own stores in `tmp_path`. `tests/app/conftest.py` also points the session-metadata
  store at a directory of the run's for the whole session: a session-cleanup thread
  can outlive the test that started it, and one that lists the checkout's directory
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
- Frontend installs use `npm ci` everywhere. `package-lock.json` must list all
  fifteen `@rolldown/binding-*` platform packages -- vitest pulls rolldown and
  the Linux runner needs its own. If a lock regeneration drops them, delete
  `node_modules` and `package-lock.json` and run `npm install` from clean; npm
  prunes foreign-platform optional dependencies when it reconciles against a
  partial tree (npm/cli#4828).
- `ci-security.yml` fails the build on a `pip-audit` finding against `uv.lock`,
  on `npm audit --audit-level=high`, and on a fixable HIGH/CRITICAL Trivy
  finding in the image. Each threshold is justified in a comment next to it. If
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

- The frontend is plain JS modules, not React/Vue.
- Global functions are intentionally exposed from `frontend/static/scripts/main.js` for template event handlers.
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
