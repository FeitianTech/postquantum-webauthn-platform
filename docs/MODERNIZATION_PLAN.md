# Modernization Program

Living plan. Status: **in progress**. Owner: tech lead (Claude). Started 2026-09-15.

Every finding below was verified by reading source or by execution. Claims that
turned out to be wrong are recorded in "Rejected findings" so nobody re-raises them.

## Progress

### Batch 1 — P0 security — DONE, pushed 2026-09-16
Closed: S1 challenge bypass, S2 signature bypass, S3 RP-ID/origin allowlist, S4 stored XSS,
S5 advisory checks now gate, S6 PQC error laundering, S7 headers/cookies/ProxyFix,
S8 ML-DSA secret logging, S9 metadata IDOR, S10 path traversal + pickle.

Verified by the tech lead, not by agent report: the original S1 PoC now returns HTTP 400;
the new security tests fail 36/42 against the unfixed code in a clean worktree; an `os.system`
pickle gadget executes under stock `pickle` and is refused by the restricted unpickler;
`X-Forwarded-Host: attacker.example` does not move `request.host` or the RP ID.

Tests: Python 1412 → **1623**, frontend 244 → **278**. Coverage badges after push:
Python 95.02% → 94.61%, frontend 82.45% → 82.71%.

### Batch 2 — C1 ML-DSA migration to `cryptography` — CODE DONE, infra pending (2026-09-16)
Verification, certificate parsing, detection and metadata all run on `cryptography`.
**Zero `oqs` references remain in `fido2/` or `server/` (only prose).**

- ML-DSA-44/65/87 verify via `cryptography`; a tampered signature raises
  `InvalidSignature` (**C3 fixed**), a truncated key raises `ValueError`.
- ~670-line hand-rolled DER/ASN.1 block deleted. What survives (~60 lines,
  `_parse_der_length`/`_parse_der_integer`) backs `_require_canonical_ecdsa_signature`,
  which is **ECDSA** canonical-signature enforcement — correctly retained.
  `fido2/cose.py` 1322 → ~990 lines; 544 deletions vs 202 insertions across cose.py + base.py.
- **C4 fixed**: the certificate panel now reports `claimedNistLevel` and
  `signatureLengthBytes`, sourced from the parsed certificate. It had *never* worked —
  the old code read hyphenated liboqs keys that never existed.
- **C5 fixed** (both parts): FIPS 204 sizes 2420/3309/4627, and the `setdefault` "enrichment"
  that could never overwrite is gone.
- **T1 fixed**: `tests/pqc/` no longer monkeypatches `verify` or injects a fake `oqs` module.
  Real keypairs, real signatures, bit-flip rejection, and real ML-DSA self-signed
  certificates through the packed-attestation policy checks.
- `cryptography>=49` in both `requirements.txt` and `pyproject.toml`; the `<45` cap is gone.
- Tests 1623 → **1653** passing. PQC now works on macOS/arm64 and in CI without liboqs.

**Process note:** the first migration agent committed a broken tree (a deleted DER helper
still had a live caller, 54 failures) because it never ran the full suite, then misread its
own commits as a rival agent and stopped. A second agent died on a rate limit. The tech lead
finished the work. Lesson recorded: **agents must run the full suite before committing**, and
a shared `main` makes "is someone else editing?" genuinely ambiguous to a subagent.

**Still pending (infra only, no code depends on it):**
- `prebuilt_liboqs/` — 13MB committed binary blob + wheel, deletable
- `Dockerfile` — 14 lines of liboqs wiring: `LD_PRELOAD`, `ldconfig`, symlink,
  `LD_LIBRARY_PATH`, the wheel install, `pqcrypto`, and the `sh -c` wrapper that exists
  only to set `LD_PRELOAD`
- `pyproject.toml:43` `pqc = ["oqs", "pqcrypto"]` extra
- `docker-compose.yml` pins `linux/amd64`; with liboqs gone, arm64 becomes buildable
- Stale comment `tests/app/security/test_pqc_attestation_reporting.py:140` claims liboqs is
  unavailable so real ML-DSA signatures cannot be produced — no longer true; that test can
  now be upgraded to real crypto

### Phase 1 — S11 signCount + replay — DONE (2026-09-17), verified
Challenge single-use via `server/app/challenge_registry.py` (in-process, TTL 10 min,
`FIDO_SERVER_CHALLENGE_TTL_SECONDS`); `/begin` stamps `issued_at` inside the signed state and
`/complete` consumes the challenge BEFORE verifying, so a failed attempt burns it too. A state
older than the TTL or missing `issued_at` is refused — without that, an old cookie could be
replayed once the registry forgot the entry. simple flow rejects; advanced reports
`challengeStatus` (fresh/replayed/expired/not-tracked) and `signCountStatus`
(ok/regressed/not-supported).

Tech-lead verification (not taken on report): new tests run against unmodified `origin/main`
in a clean worktree give **22 failed / 1 passed** on the end-to-end tests — the one pass is the
plain happy path — plus 12 registry tests that cannot import. 34/35 fail on revert, as claimed.
Suite 1653 → **1688**.

Bonus fix found by the agent: the counter was decoded with standard base64 while
authenticatorData is base64url, so the counter was misread or dropped whenever the encoding
contained `-` or `_`.

**KNOWN LIMITATION — the simple-flow clone check is weak by design.** The authoritative server
record is keyed by the browser's own namespace cookie, and the stored counter is
`max(server record, counter the browser sent)`. An attacker with a cloned key using a fresh
browser has no server record, so the only "stored" value is the one they supply — they simply
send a high counter and never trip the check. It reliably catches regressions **within the same
browser**, not a clone used elsewhere. Closing this needs a credential store keyed by user
identity rather than browser namespace — an architectural change (see M3/M4), not a patch.

**Follow-ups queued:**
- Counter save is read-modify-write with no locking; two concurrent authentications can both
  succeed with the same counter.
- Advanced register/complete has no replay reporting; advanced authenticate errors raised
  before the state loads leave the state unconsumed.
- The simple credential list API still shows the registration-time counter — the builders read
  `auth_data.counter` instead of the new `sign_count` field.
- Multi-instance replay: registry is per-instance, `maxScale: 10`. Agent recommends a GCS
  store using `ifGenerationMatch=0` (create-if-absent) so the first write wins across
  instances, with a lifecycle rule for cleanup. **Decision pending.**

### Phase 2 — liboqs infrastructure removal — DONE (2026-09-17), verified
`prebuilt_liboqs/` deleted (13MB binary + wheel). Dockerfile lost all four overlapping
library-load mechanisms (`LD_LIBRARY_PATH`, the `COPY`, the `ldconfig`/symlink dance,
`LD_PRELOAD`), plus `cmake`/`ninja-build`/`CMAKE_BUILD_PARALLEL_LEVEL` and the `pqcrypto`
install. CMD is now exec form, so gunicorn is PID 1 and receives SIGTERM directly.
`pqc` extra dropped; `platform: linux/amd64` pin removed from docker-compose.

Tech-lead verification inside the built image (not taken on report): `/health` → 200 `ok`;
`detect_available_pqc_algorithms()` → `{-48,-49,-50}` with no error; ML-DSA sign/verify works;
`oqs` absent; `cryptography` 50.0.1. Image 350MB → 327MB (89.3 → 83.3MB compressed);
**arm64 now builds natively for the first time**. Suite 1688 → **1689**.

The extra test is a genuine negative: the same attestation signed by a DIFFERENT ML-DSA key
asserts `pqc_signature_valid is False`, proving the positive case depends on the signature
rather than the payload shape.

### CRITICAL — production ships Flask 2.3.3 while CI tests Flask 3.1.3 (CONFIRMED)
No longer an inference from manifests. Verified by running the built image:
`Flask 2.3.3`, Python 3.12.14, cryptography 50.0.1.
Cause: the Docker build never reads `requirements.txt` (which says `Flask>=3.1.3,<4.0`).
Deps reach the image via `pip install .` + `./server`, and `server/pyproject.toml:13` pins
`Flask = "^2.0"`. So the gunicorn and `google-*` pins in `requirements.txt` do not apply to the
image either. **Production runs a Flask major version behind what CI tests.** This raises the
priority of the dependency single-source-of-truth work — see A1.

Also noted: the builder stage still installs `build-essential`, `git`, `libssl-dev`,
`pkg-config`; `cryptography` wheels bundle OpenSSL so these may be removable. The
`apt-get purge` in the builder stage is a no-op because that stage is discarded.

### Phase 3 — A1 dependency single source of truth — DONE (2026-09-17), verified
`server/pyproject.toml` is now the app's only dependency manifest; `uv.lock` (39 packages,
hashed) is committed at the root; `requirements.txt` is **deleted**. The Docker image exports
the lock and installs with `pip --require-hashes`; CI runs `uv sync --locked --python 3.12`;
Dependabot targets `uv.lock`. Python floor raised to 3.12 in both manifests. The root
pyproject stays the vendored library's manifest (fido2 is NOT un-vendored).

Tech-lead verification — built a fresh image and read its metadata:

| Package | Before | After |
|---|---|---|
| Flask | **2.3.3** | **3.1.3** |
| cbor2 | **5.9.0** | **6.1.4** |
| cryptography | 50.0.1 | 50.0.1 |
| gunicorn / google-* | unchanged | unchanged |

**Production and CI now run the same versions.** Container re-verified: `/health` 200,
`/` 200 with CSP header, PQC `{-48,-49,-50}`. Stale-lock detection confirmed — editing
`server/pyproject.toml` without re-locking makes `uv lock --check` fail. All six workflow
YAMLs parse. Suite **1689**.

Agent found a SECOND split I had not listed: cbor2 was capped at `^5.6.4` in the vendored
library's manifest, so the image ran 5.9.0 while CI tested 6.1.4. The vendored fido2 never
imports cbor2 (only `server/app` does), so it was removed from the library manifest.
The old image also paired Flask 2.3.3 with Werkzeug 3.1.8 — a combination nothing tested.
Removing the three unimported deps also dropped asn1crypto, attrs, certvalidator, ecdsa,
oscrypto and six from the image.

**Local development (UPDATED):** `.venv` is now synced from `uv.lock`, not `requirements.txt`.
Use `uv sync --locked`. Run tests with `.venv/bin/python -m pytest -q`. ruff is NOT in the
lock by design — run it via `uvx ruff@0.16.8 ...` so it cannot drift into the app's deps.

**Residual risk:** the GitHub Actions and Dependabot changes are untested until pushed —
they cannot run locally. Watch the first CI run after this lands.

### Phase 4 — A2 lint baseline and gate — DONE (2026-09-17), verified
Standalone `ruff.toml` (kept out of the vendored library's manifest so it stays diffable
against upstream). **3705 findings to 1655**, of which 1008 is the deliberately-ungated F821.
Gated set `["E4","E7","E9","F","I","UP006","UP007","UP035","UP045"]` passes at **zero** and is
wired into CI. UP006 723 to 0, UP035 298 to 0, UP045 523 to 0, F401 625 to 0, I001 111 to 0.
Suite held at 1689 / 278 at every commit; the agent reverted three times rather than force a fix.

Coverage floors added and verified to bite: Python `fail_under = 95` (measured 95.42; exits 2
at 97, 0 at 95), vitest thresholds 82/66/91/82. **Critically, the agent noticed neither floor
ran on PRs** — `ci-python.yml` ran bare pytest and `ci-frontend.yml` ran vitest without
`--coverage`, so the floors would only have fired in the badge workflow after merge. Coverage
is now wired into both jobs; without that, "coverage cannot silently collapse" was false.

`ruff format` deliberately NOT gated: it would rewrite 268 of 387 files (~14k lines).
RUF100 deliberately ungated — under this narrow a gate it calls 79 live markers dead,
including the `# noqa: F401` re-exports in vendored `fido2/**/__init__.py`. 7 genuinely stale
markers removed by hand.

**F822: 26 findings, 0 real bugs.** Tech-lead re-verified at runtime: all 13 `__all__` entries
in `attestation.py` and all 19 in `metadata.py` resolve via `hasattr` — they are installed by
`_install_runtime_bindings(...)` at import. Ignored in those two files only.

### CORRECTION TO THE STRUCTURAL PLAN — there are FIVE namespace carriers, not three
My earlier analysis named three modules that rebind fragments with
`types.FunctionType(func.__code__, globals(), ...)`: `attestation.py`, `metadata.py`,
`decoder/decode.py`. Phase 4 found two more with the **same coupling by a different
mechanism**: `routes/advanced.py` and `routes/simple.py` pass themselves into their fragments
via `_self_module()`, which then read names straight off the module
(`advanced_module.request.get_json(...)`).

**Verified by the tech lead:** deleting `import math` from `routes/advanced.py` — which ruff
calls unused — breaks 2 tests, because fragments reach it as `advanced_module.math`.
Confirmed live fragment uses: `advanced_module.jsonify` 52, `advanced_module.session` 25,
`advanced_module.uuid` 3, `advanced_module.hashlib`/`json`/`time` 2 each.

These two produce **no F821**, so **the F821 meter understates the debt by two modules**.
M3 must cover five carriers. Track `_self_module`/`advanced_module`/`simple_module`
reference count (539 at last audit) as the second meter.

### Real bugs found in Phase 4, queued not fixed
`simple_parts/credentials_route_impl.py` — four blanket handlers:
- DELETE returns `{"status":"OK","removed":N}` after swallowing deletion failures, so a
  partial or total failure reports success. Note `delkey` now raises on a rejected name.
- The listing path nests THREE blanket handlers (drop-a-credential, drop-a-user,
  return-empty), so a listing failure returns **HTTP 200 with `[]`** — indistinguishable
  from "you have no credentials".

Also: `checks_metadata_runtime.py:78` computes `metadata_aaguid_bytes` and never compares it,
unlike the credential/certificate aaguids — incomplete work, marked FIXME.
`tests/app/core/test_config.py:190` builds `expected_path` and never asserts on it.
S110/S112 triage (all 32 read): 14 load-bearing, 13 masking real errors, 4 genuine bugs,
1 needs review. BLE001 sample of 20: 16 load-bearing, 4 silently swallow — extrapolates to
~35 of 175 worth review.

### Phase 5 — A3/A4/A5/A6 guardrails — DONE (2026-09-17), verified. **M2 COMPLETE.**
Bots no longer push to `main`: a local composite action `.github/actions/open-bot-pr` commits an
explicit pathspec onto a fixed bot branch and opens a PR. `update-fido-mds.yml` dropped to
**`contents: read`** entirely — with the snapshot untracked it has nothing to commit, so it is now
a daily canary that downloads the BLOB and verifies it against the pinned trust root.
`cloudbuild.yaml` gained parallel Python and frontend test steps that `Build` waits on, so a
deploy cannot happen without tests. All 15 `uses:` pinned to full SHAs. Double-run fixed.
New `ci-security.yml`: pip-audit (clean), `npm audit --audit-level=high` (4 highs fixed via
overrides), Trivy HIGH/CRITICAL on the image (13 fixable fixed via `apt-get upgrade`).

**MDS snapshots out of git.** All SEVEN artifacts untracked (the three `.meta.json` companions
too — `_load_packaged_explorer_meta` compares them, so splitting generations would let them
disagree). New `server/app/mds_provisioning.py` resolves in three tiers: local files → GCS
(`gs://$FIDO_SERVER_GCS_BUCKET/mds/`, existing bucket and service account) → upstream fetch with
trust-root verification, then uploads to GCS so the next cold start stops at tier 2.

Tech-lead verification: built the image and ran it with **no snapshot, no GCS, no upstream** —
`/health` 200, `/` 200, PQC `{-48,-49,-50}`, and `/api/mds/metadata/base` returns 404, which is
the documented clean fallback (pre-existing missing-snapshot behaviour, not a new failure mode).
Image contains zero snapshot files. Tracked working tree **34.9MB → ~6.4MB**.
Suite 1689 → **1714**, vitest 278, ruff clean.

### CRITICAL CATCH — `astral-sh/setup-uv@v10` never resolved
The agent found that `astral-sh/setup-uv` publishes **no floating major tag**. Tech-lead
confirmed with `git ls-remote`: only `v10.0.0`, `v10.0.1`, `v10.1.0` exist; a bare `v10` ref
does not. **The CI introduced in Phase 3 and pushed to `main` would have failed at the
"Set up uv" step** — it was broken for two pushes and nobody could see it locally. Now pinned
to v10.1.0's SHA (`bec219d...`, verified against ls-remote). This is exactly the residual risk
flagged in Phase 3: workflow changes cannot be validated locally. **Watch the next Actions run.**

### Operator actions REQUIRED — not doable from the repo
1. **Configure branch protection on `main`.** The bots still need `contents: write` to push a
   *branch*; there is no finer permission. Only branch protection actually enforces the PR flow.
2. **Set a `BOT_PR_TOKEN` secret** (PAT or App token). GitHub does not start workflow runs for
   events signed by `GITHUB_TOKEN`, so bot PRs will sit with **no checks** until someone pushes
   to them. The action falls back to `GITHUB_TOKEN` — it works, it just will not auto-trigger CI.
3. **No GCP credentials exist in Actions**, so no workflow can seed the MDS bucket. Production
   self-heals via tier 3. An operator can seed it with
   `FIDO_SERVER_GCS_ENABLED=1 FIDO_SERVER_GCS_BUCKET=pqcwebauthn python tools/update_mds_snapshot.py --gcs-upload`.

**History rewrite (tech lead's call, NOT attempted):** `.git` is 155MB (pack 146MiB); the 216 MDS
blobs are 911.6MB raw / **79.1MB packed**, so a rewrite would reclaim ~79MB (~54% of the pack),
taking `.git` to ~70MB. Growth has stopped regardless.

Noted: reported image growth of +55MB from `apt-get upgrade` did not reproduce for the tech lead
(342MB → 344MB, +2MB) — likely base-image digest drift. `ci-frontend.yml` still uses
`npm install` rather than `npm ci`. Trust root duplicated in `config.py` and
`tools/update_mds_snapshot.py`. 3 moderate dev-only npm advisories remain visible but ungated
(`@vitest/mocker`; the fix needs vitest 4.1.11, which npm 10.9.8 cannot install).

### Owner decisions (2026-09-24) — settled, do not re-raise
- **Deploy gate: DONE (2026-09-24).** The Cloud Build trigger builds from `cloudbuild.yaml`, so its test
  steps gate every deploy. `gcloud builds triggers update github ... --build-config=cloudbuild.yaml`
  fails with `INVALID_ARGUMENT`: the trigger carries an inline `build`, and a trigger may not have
  both. The switch is a re-import of the same trigger with `filename: cloudbuild.yaml` and no `build`.
  Both test steps were run beforehand in their exact images (`python:3.12-slim`: 2466 passed /
  5 skipped; `node:22-slim`: 293 passed).
  Proven on a manual run of `main` (build `0ff71eaa`, commit `ed279cdc`): Python tests and Frontend
  tests ran in parallel first, Build waited for both, and revision `pqcwebauthn-00436` carries the
  commit, build and trigger labels. Two imports of the backup file reverted the switch by mistake; the
  backup of the inline trigger is kept out of the repo and offered only when a rollback is needed.
- **Branch protection on `main`: off.** The bot PR flow is a convention, not enforced.
- **`BOT_PR_TOKEN`: not set.** Bot pull requests get no CI run until someone pushes to them.
- **Git history rewrite: deferred, the tech lead's call on timing.** Planned for the final-audit
  phase, once the tree has stopped churning, so it happens once.
- **Multi-instance replay protection: not now.** The challenge registry stays per-instance.
- **Registration logging to `rainzhang05/CredentialLogs`: keep as it works today.**

### Phase 6 — M3 pilot: unwind the globals carrier in `metadata` — DONE (2026-09-17), verified
Four staged passes over 24 commits: give fragments real imports (inert while the carrier lives,
so safe first) -> move 15 caches, 5 locks and 14 constants into a new leaf
`metadata_parts/runtime_state.py` (all 8 `global` statements gone) -> route cross-fragment calls
through `other_runtime.foo()` so patching the defining module still intercepts -> delete the
carrier. `metadata.py` 258 -> **127 lines**, now a re-export shim.

| Metric | Before | After |
|---|---|---|
| F821 repo-wide | 1008 | **557** |
| F821 in `metadata_parts` | 450 | **0** |
| `metadata.py` carrier refs | present | **0** |
| ruff per-file-ignores | 5 modules | **4** |

Remaining F821: `decode_parts` 366, `attestation_parts` 175, `decoder/decode.py` 16.
Public API intact — all 19 `__all__` entries resolve; 7 modules still import from
`server.app.metadata`. Suite unchanged at 1708/278, ruff green.

**Tech-lead verification — collected test IDs diffed across the phase: zero added, zero
removed.** A pure refactor at the test level, which is exactly right.

**Fault injection reproduced independently.** Renaming `_base_metadata_trust_verified` at its
definition now produces **43 loud errors** (86 `AttributeError` mentions) — matching the agent's
number exactly. On the old code the same rename left **112 tests passing while patching
nothing**. This is the real win: the tests were silently vacuous and are now honest.

Technique worth reusing for the remaining carriers: re-exports written as **assignments**
(`_load_base_metadata = base_snapshot_runtime._load_base_metadata`) rather than imports, since
an assignment counts as a use and pyflakes then sees no unused import — that is what let
`metadata.py` come off the F401/UP035 ignore list.

**Corrections to my own briefing (my errors, not the agent's):**
- The 7 `# pyright: reportUndefinedVariable=false` markers are in `decoder/decode_parts/`,
  NOT `metadata_parts/`. None were droppable in this phase.
- I quoted a 1714 pytest baseline; the real baseline at `origin/main` was **1708**. Verified in
  a clean worktree. No tests were lost — my earlier figure was stale.

**Import cycle unchanged and not breakable here:** `ensure_metadata_session_id` lives in
`session_identity_runtime`, which needs `..session_metadata_store` -> `storage_common`. Pointing
`storage_common` at the fragment just re-forms the cycle one hop over. The function-level import
at `storage_common.py:98` stays; edge count identical.

**Found but not fixed:** three dead `monkeypatch.setattr(metadata, "SESSION_METADATA_DIR", ...)`
patches deleted — that name never existed on `metadata.py`, and `raising=False` hid the no-op for
its entire life. `MetadataDownloadError` is in `__all__` but never raised or caught
(`download_metadata_blob` raises `RuntimeError`) — dead public API. Two pre-existing
builtin-shadow patches (`config.open`, `github_client.range`) left alone.

### Phase 7 — M3: unwind the globals carrier in `attestation` — DONE (2026-09-17), verified
Same staged approach as the metadata pilot, over 25 commits: bare-name fragment imports in the
carrier -> give each fragment real imports (inert while the carrier lives) -> a leaf
`attestation_parts/runtime_state.py` for the shared constants -> route cross-fragment calls
through `other_runtime.foo()` -> delete the carrier. `attestation.py` 263 -> **154 lines**, now a
re-export shim.

| Metric | Before | After |
|---|---|---|
| F821 repo-wide | 557 | **382** |
| F821 in `attestation_parts` | 175 | **0** |
| `attestation.py` carrier refs | present | **0** |
| ruff per-file-ignores | 4 modules | **3** |
| `raising=False` in `tests/app/attestation/` | 131 | **0** |

Remaining F821: `decode_parts` 366, `decoder/decode.py` 16. `attestation.py` came **off** the
`["F401", "UP035", "F822"]` ignore list — it passes the full gated rule set unsuppressed. The
assignment trick from the metadata phase carried over unchanged. Suite unchanged at 1708/278.

**Collected test IDs diffed across the phase: zero added, zero removed**, despite ~160 patch
lines being rewritten.

**Prerequisite the metadata phase did not need.** `attestation.py` imported its fragments as
`_trust_runtime` etc., where `metadata.py` used bare names. Since a rebound fragment resolves
`trust_runtime.foo()` in the *carrier's* globals, stage C would have raised `NameError` on every
converted call. Renaming those 17 imports had to come first. Worth checking before starting on
`decoder/decode.py` and the two route carriers.

**Fault injection — and a correction to the expected shape of the result.** Method: rename a
symbol at its definition *and* every production call site (a faithful "the symbol moved"
simulation), leaving the test patches pointed at the old name. Across the 14 private helpers the
tests patch, covering 41 patch sites:

| | Before | After |
|---|---|---|
| Patchers that passed silently | **3** | **0** |
| Patchers that failed | 38 | **41** |
| Failures raised *at the patch line* | **0** | **41** (82 `AttributeError` mentions) |

This is a much smaller silent-pass count than metadata's 112, and the reason is instructive:
metadata's injected symbol was mutable *state* that tests reset to a value it already held, so
the patch was a no-op even when it worked. Attestation's symbols are *functions* replaced with
behaviour-changing stubs, so losing the stub usually changes an assertion somewhere downstream.
The real improvement here is therefore diagnostic quality rather than raw count: before, a moved
symbol could never fail at the patch itself, because `raising=False` guaranteed the patch could
not complain — the suite reported an assertion mismatch several frames away, or nothing at all.
Now all 41 fail with an `AttributeError` naming the missing symbol at the line that patches it.

**`raising=False` audit: 131 -> 0.** Every site was re-pointed at the module that actually owns
the attribute, and the attribute was confirmed to exist at each one. The 11 remaining facade
patches are all `monkeypatch.setitem` on shared dicts (`EXTENSION_DISPLAY_METADATA`,
`app.config`), which mutate the same object the fragments read and are correct as they stand.

**Fragments are now independently usable.** Before, `import
server.app.attestation_parts.trust_ca_runtime` succeeded but every call raised `NameError`;
`trust_ca_runtime._certificate_fingerprint(b"x")` now works from a bare import. That is why no
test had ever imported a fragment directly.

**Import cycle unchanged.** `config`, `metadata` and `pqc` have no back-edge to `attestation`
(verified by import), so giving the fragments real `..config` / `..metadata` / `..pqc` edges
added no cycle — it only made an edge that already existed at the carrier level explicit. The
latent risk is now retired rather than hidden behind globals injection.

**Found but not fixed:**
- `_check_pqc_certificate_constraints` is called from a sibling in its own module. Its 5 patches
  could not move during stage C — an intra-file call still resolves through the carrier — so they
  moved with the carrier deletion. Any remaining carrier will have the same ordering constraint.
- `attestation.py` no longer re-exports `_HASH_NORMALISE_PATTERN`; it was an alias of
  `certificate_signature_leaf._HASH_NORMALISE_PATTERN` that nothing in the repo ever read.
- `is_pqc_algorithm` is still imported by name rather than through `..pqc`. No test patches it,
  so there is nothing to intercept; revisit if that changes.
- `server/app/decoder/decode.py` still imports 7 names from `attestation.py` and snapshots them
  into its own carrier globals. That coupling is unchanged and belongs to the decoder milestone.

### Phase 7 — M3: unwind the `attestation` carrier — DONE (2026-09-17), verified

| Metric | Before | After |
|---|---|---|
| F821 repo-wide | 557 | **382** |
| F821 in `attestation_parts` | 175 | **0** |
| `raising=False` in attestation tests | 131 | **0** |
| `attestation.py` | 263 lines, carrier | **154**, re-export shim |
| ruff carrier ignores | 4 modules | **3** |

`attestation.py` came off the F401/UP035/F822 ignore list unsuppressed. All 13 `__all__` entries
resolve. Suite 1708/278, ruff green. **Collected test IDs identical — 0 added, 0 removed** —
despite ~160 patch lines rewritten.

**New process finding for the remaining carriers (Stage 0).** `attestation.py` imported its
fragments under aliases (`_trust_runtime`) where `metadata.py` used bare names. A rebound
fragment resolves `trust_runtime.foo()` in the *carrier's* globals, so every cross-fragment
conversion would have raised `NameError` until those 17 imports were renamed first. **Check
import aliasing before starting the decoder and route carriers.**

Also: `attestation_parts` had **no** `global` statements, locks or caches — unlike
`metadata_parts` — so the state-extraction stage was trivial (two constants).
Enumeration cross-checked two ways: ruff F821 against a runtime walk of every fragment
function's `co_names` including nested code objects, intersected with `vars(attestation)`.
They agreed exactly, confirming F821 is authoritative for this job.

**Tech-lead verification of the structural win.** The agent's illustration
(`_certificate_fingerprint`) was a poor example — it works pre-phase too, since it only used
names it already had. I found one that genuinely failed: `serialize_attestation_certificate`
called from a bare fragment import raises
`NameError: name '_build_unknown_public_key_info' is not defined` at `origin/main`, and works
after. Fragments really are independently usable now.

**Fault injection — smaller number than metadata, and the agent explained why rather than
dressing it up.** Across 14 private helpers tests patch (41 sites): silent passes **3 to 0**,
failures 38 to 41, and crucially **failures at the patch line 0 to 41**. Metadata's injected
symbol was mutable state reset to a value it already held (vacuous even when working);
attestation's are functions replaced with behaviour-changing stubs, so losing the stub trips an
assertion a few frames downstream instead. The win here is diagnostic: with `raising=False`
gone, all 41 now raise `AttributeError` naming the missing symbol **on the patch line itself**.

**Metric to track: `raising=False` repo-wide is 868.** That is the remaining silent-no-op
surface; each carrier unwind cuts into it (attestation contributed 131).

**Found but not fixed:** `_check_pqc_certificate_constraints` is called from a sibling inside
its own module, so its 5 patches could not move during the cross-fragment stage — an intra-file
call still routes through the carrier until deletion. **The remaining carriers have the same
ordering constraint.** `decoder/decode.py` still snapshots 7 names from `attestation.py` into
its own carrier globals — a cross-carrier dependency for the decoder phase.
Dropped `attestation._HASH_NORMALISE_PATTERN`, an alias nothing read.

### Phase 8 — M3: unwind the `decoder/decode.py` carrier — DONE (2026-09-17), verified
The third and largest carrier, over 26 commits, and **the one that retires F821**.
`decode.py` 517 -> **272 lines**, now a re-export shim in the same shape as `attestation.py`.

| Metric | Before | After |
|---|---|---|
| F821 repo-wide | 382 | **0** |
| F821 in `decode_parts` | 366 | **0** |
| F821 in `decode.py` | 16 | **0** |
| `ignore = ["F821"]` in ruff.toml | present | **removed** |
| ruff per-file-ignores | 3 modules | **2** |
| `# pyright: reportUndefinedVariable=false` markers | 7 | **0** |
| `raising=False` in `tests/app/decoder/` | 88 | **0** |
| `raising=False` repo-wide | 868 | **780** |
| carrier machinery (`types.FunctionType` rebinding) | 79 functions | **0** |
| global-mutation relays around the CBOR parser | 2 (stacked) | **0** |

**F821 is now gated, unsuppressed, at zero.** It read 1008 before `metadata.py`, 557 before
`attestation.py`, 382 before this phase. The progress meter has run out, so the `ignore` entry
and its explanatory comment are gone; the comment now records the history instead. Verified live
by appending an undefined name and watching the gate fail.

**Collected test IDs diffed across the phase: zero added, zero removed** (1708 before and after),
despite ~180 patch lines being rewritten and a new `tests/app/decoder/conftest.py` of 19
fragment fixtures. Suite unchanged at 1708 Python / 278 JS.

**Stage 0 again, and worse than Phase 7.** `decode.py` imported all nine fragment modules under
`_`-prefixed aliases, so every cross-fragment conversion would have raised `NameError` before
the rename. A *second* prerequisite showed up mid-phase that Phase 7 did not need: the carrier
also had to import the *leaf* fragments as modules (`binary_extract`, `summary_leaf`, ...), not
just names out of them, because a rebound fragment resolves `summary_leaf._append_simple_field`
in the carrier's globals too. Expect the same for the two route carriers.

**Stage B was empty, and saying so is the point.** `rg '^\s*global '` over
`server/app/decoder/` returns nothing and the seven rebound fragments had *zero* module-level
assignments. There were no caches and no locks to relocate, so no `decode_parts/runtime_state.py`
was created -- unlike the other two `*_parts/` packages. What had to move out of the carrier was
*code*: `decode_payload_text` -> `pipeline_runtime`, the CTAP prefix table + `_extract_ctap_prefix`
+ `_is_padding_bytes` + `_json_safe_with_stringified_keys` -> `cbor_runtime`, `_PEM_CERT_PATTERN`
-> `pipeline_runtime`, and the four `*_HANDLERS` converter tables -> `ctap_runtime_interpret`.

**The CBOR global-mutation dance is gone, not relocated.** There were **two** stacked copies:
`decode._parse_cbor_item` mutated three `cbor_core` globals around its call, and
`cbor_core._parse_cbor_item` mutated the same three on `cbor_strict`, each restoring in a
`finally`. `cbor_strict` itself was clean -- the relays existed only to push a carrier-level
patch down two module boundaries, and under gunicorn's 16 gthreads two concurrent decodes could
interleave the set/restore. The whole apparatus was held up by **one test and one symbol**
(`_read_cbor_length`); the `_ensure_cbor_available` and `_float_summary` halves were eight lines
of never-exercised code. Both relays deleted, both patches moved to the defining module, and
`cbor_core` is off the call path entirely. Its three pass-throughs stayed *delegating functions*
rather than becoming assignments: an assignment binds at import and would silently stop seeing a
`cbor_lenient` patch, which is the exact failure mode this work exists to remove.
The same one-hop relay over `ctap_repair_leaf` went the same way (held up by
`_locate_get_assertion_trailing_offset`, one test; its `_lenient_decode_from` half untested).

**Cross-carrier dependency resolved.** The 7 names `decode.py` took from `attestation.py` are
now ordinary imports in the fragments that use them, and all 7 were verified `is`-identical to
their defining `attestation_parts` module both before and after.

**Import cycles are real here and were not in Phase 7.** The seven fragments form cycles
(`pipeline <-> details`, `pipeline -> cbor_runtime -> ctap_parse -> pipeline`). `from . import
sibling` is safe under them on 3.12 because every use is inside a function body and CPython falls
back to `sys.modules`. Module-level *attribute* access is not: the `*_HANDLERS` tables cannot hold
`ctap_runtime_parse` function objects, because a fixture importing that fragment first leaves it
partially initialised when the table is built. They dispatch through a lambda instead, which also
keeps a patch on the defining module visible.

**Fault injection — 50 symbols, 144 patch sites.** Method as in Phase 7: rename a symbol at its
definition *and* every production reference, leaving the test patches on the old name.

| | Before | After |
|---|---|---|
| Failures | 165 | **186** |
| Failures naming the missing symbol | 127 | **186** (100%) |
| Symbols whose failures never named it | 2 | **0** |
| Failures the carrier absorbed entirely | 21 | **0** |

The shape differs from Phase 7 and the reason is `raising=False` *creating* the attribute: a
`setattr(decode_module, "_decode_cbor_sequence", fake, raising=False)` against a symbol that had
moved installed `fake` into the carrier's globals, the rebound fragment resolved the name there,
and the test passed exercising the stub as if nothing had moved. That is where the 21 missing
failures went -- 14 patch sites on that one symbol yielded 9 failures before and 11 after. So the
honest "before" is not a silent-pass *count* but a silent-pass *mechanism*, and it is closed.

One methodological note worth keeping: the first two sweep runs were not reproducible
(`_read_cbor_length` reported 174 failures once and 2 the next time). The cause was stale
`__pycache__` surviving the restore. Clearing it per iteration made two consecutive runs
byte-identical; the numbers above are from that stable measurement, not the first one.

**`raising=False` audit: 88 -> 0 in `tests/app/decoder/`, 868 -> 780 repo-wide.** Every one of
the 88 was droppable *before* the unwind -- each patched attribute already existed, so the flags
masked nothing at the time but would have masked exactly this phase's regressions. They came off
in commit 2, before any conversion, which is what made the rest self-checking. The new
`tests/app/decoder/conftest.py` leaves `raising` at its default everywhere for the same reason.

**Found but not fixed:**
- `decode_parts/cbor_core.py` had **no importers anywhere** in `server/` or `tests/`. It has since been deleted. It was
  left in place because file-level renames and merges are a later milestone; it is a deletion
  candidate for that one.
- `encode_parts/handlers_basic.py` and `handlers_cbor.py` import five *private* decoder names
  (`_binary_summary`, `_describe_authenticator_data_bytes`, `_hex_json_safe`,
  `_parse_attestation_object`, `_stringify_mapping_keys`) from `decode.py`. The shim keeps them
  working unchanged, but the encoder should import them from the defining fragments so the shim
  is a test and public surface only. Encoder scope.
- The `_CTAP_COMMAND_MAP` / `_CTAP_STATUS_MAP` tables are wrong -- 2 commands and 1 status
  against roughly 45 status codes in `fido2.ctap`. They moved next to their only caller
  (`cbor_runtime._extract_ctap_prefix`) so the codec milestone can fix them in one place.
- `cbor_strict._decode_cbor_structure` was dead (everything used `cbor_core`'s copy); taking
  `cbor_core` off the call path made it the live one and removed the duplicate.
- `key_utils`, `ctap_convert_leaf`, `conversion_cert_leaf` and `cbor_sequence` are still reached
  by name rather than through the module. No test patches anything they define, so there is
  nothing to intercept, and the sibling leaves already import them that way. Revisit if that
  changes.
- One `raising=False` remains on a decoder-package target: `encode._ENCODING_HANDLERS` in
  `tests/app/encoder/`. The attribute exists, so it is droppable; out of this phase's scope.
- `routes/advanced.py` and `routes/simple.py` are the last two carriers. They keep their
  `["F401", "UP035"]` ignores, and the per-file-ignores comment now describes only them.

### Phase 8 — M3: unwind the `decoder` carrier — DONE (2026-09-17). **F821 IS ZERO.**

| Metric | Before | After |
|---|---|---|
| **F821 repo-wide** | **382** | **0** |
| F821 `decode_parts` / `decode.py` | 366 / 16 | 0 / 0 |
| `decode.py` | 517 lines | **272** (shim) |
| `# pyright: reportUndefinedVariable=false` | 7 | **0** |
| `raising=False` in decoder tests | 88 | **0** (868 to 780 repo-wide) |
| ruff carrier ignores | 3 | **2** |

**`ignore = ["F821"]` is GONE from ruff.toml and the rule is genuinely enforced.** Tech-lead
verified live: appending `return _this_name_does_not_exist_anywhere` to a fragment makes
`uvx ruff check .` fail with 1 error; removing it returns to green. A zero count with the rule
ungated would have been meaningless — it is gated.

Collected test IDs identical (1708, 0 added / 0 removed) despite ~180 rewritten patch lines and
a new 19-fixture `tests/app/decoder/conftest.py`. Suite 1708/278, ruff green.
Stage B was empty again — no caches, locks or `global` statements anywhere in the decoder.

**`cbor_core` fully retired.** There were TWO stacked relays (`decode` -> `cbor_core` ->
`cbor_strict`), held up by one test and one symbol. It is now off the call path with **zero
importers anywhere** (tech-lead confirmed) — a deletion candidate for the file-level milestone.
The thread-unsafe `_parse_cbor_item` global-mutation hack is gone. The tech lead's correction
held: its pass-throughs stayed *delegating functions*; an assignment would have rebound at
import time and silently defeated patches on the definition.

**Process improvements worth carrying to the route carriers:**
1. **Drop `raising=False` FIRST, before any conversion.** The agent did this in commit 2. All 88
   were droppable already, so they masked nothing at that point — but they *would* have masked
   exactly this phase's regressions. It made the rest of the work self-checking and caught real
   silent passes later. Do this first in Phase 9.
2. **Stage 0 is bigger than Phase 7 suggested.** All nine fragments were imported under aliases
   (`_cbor_core`, `_pipeline_runtime`, ...), and a SECOND prerequisite appeared: the carrier also
   had to import the *leaf* fragments as modules, because a rebound fragment resolves
   `summary_leaf._append_simple_field` in carrier globals too. Expect both for the routes.
3. The intra-module sibling-call ordering constraint held exactly as predicted — 54 calls could
   not move until the carrier died.

**Fault injection, 50 symbols / 144 sites:** failures 165 to 186, failures *naming the missing
symbol* 127 to **186 (100%)**, failures the carrier silently absorbed **21 to 0**. The agent
explained the shape honestly: `raising=False` *creates* the attribute, so a patch against a
moved symbol installed the stub into carrier globals and the test passed as if nothing moved.
It also disclosed that its first two measurement sweeps were not reproducible (stale
`__pycache__`) and reported only numbers confirmed byte-identical across consecutive runs.

**Found but not fixed:** `encode_parts/handlers_basic.py:9` and `handlers_cbor.py:7` import five
PRIVATE names from `decode.py` (tech-lead confirmed), so the shim is load-bearing for
production, not just tests — encoder-milestone scope. `cbor_strict._decode_cbor_structure` was
dead and is now the live copy. One `raising=False` remains on `encode._ENCODING_HANDLERS`.

### Phase 9 — M3: unwind the `routes/advanced.py` and `routes/simple.py` carriers — DONE (2026-09-18). **M3 COMPLETE.**

These two coupled differently from the other three: no `types.FunctionType` rebinding, but 45
one-line forwarders shaped `return _foo_impl(_self_module(), ...)`, with the fragments reading
names off the parameter (`advanced_module.session`, `advanced_module.math`). To ruff that is
just a parameter, so the coupling produced **no F821 at all** and F821 could not be the meter.

| Metric | Before | After |
|---|---|---|
| `advanced_module.` / `simple_module.` attribute reads in `*_parts/` | **498** (296 + 202) | **0** |
| bare `advanced_module` / `simple_module` tokens in `server/` | **581** | **0** |
| carrier forwarders (`_self_module()`) | 45 (33 + 12) | **0** |
| `F401` + `UP035` on the two carriers, unsuppressed | **107** | **0** |
| `ruff.toml` per-file-ignores | 2 | **0** — the section is gone entirely |
| `advanced.py` / `simple.py` | 292 / 156 lines | **115 / 74** (route rules + shim) |
| `raising=False` repo-wide in `tests/` | 780 | **476** (304 dropped: 292 carrier-targeted + 12 same-file collateral) |
| F821 repo-wide | 0, gated | **0, still gated** — `[lint]` has no `ignore` key |

Suite 1708/278 throughout. **Collected test IDs identical: 1708, 0 added / 0 removed**, across
~380 rewritten patch lines and a new 30-fixture `tests/app/conftest.py`.
`tests/app/security/` 78 passed — challenge single-use, signCount regression, origin allowlist
and the `__session_state` binding all re-verified, with no ceremony behaviour touched.

**The per-fragment plan did not survive contact and had to change.** A test patches a *name* on
the carrier, so the moment any one fragment stops reading `advanced_module.create_fido_server`
that test silently stops affecting it. A patched name therefore has to move in **every** fragment
at once. Conversion ran by dependency package (metadata, credential_artifacts, device_logs, pqc,
attestation, storage, config), not fragment by fragment, with the test re-point in the same
commit. Names no test patches (stdlib, Flask, fido2) were free to move in one sweep.

**Externals that tests patch are imported as modules** (`from ... import config`, then
`config.create_fido_server(...)`), so each keeps one stable patch target whichever fragment a
flow runs through; everything else is a plain name import. The 11 pre-existing
`from .sibling import name` statements went too — the arity change forced it — so no name
anywhere in either package is bound at import time now.

**Three real defects the work exposed, none of them cosmetic:**
1. `register_begin_impl` had a local `attestation = public_key.get("attestation", "none")`
   shadowing the new `from ... import attestation`. Ruff's F401 autofix then deleted the import
   as unused. **F821 caught it** — 2 errors, and the fix was to rename the local.
2. Patches living in plain test *helpers* (not tests or fixtures) were being skipped by the
   re-point tooling, leaving them as dead no-ops that still resolved on the carrier. An audit
   pass for "carrier patches no fragment reads any more" now returns 0.
3. Pruning the now-unused `advanced_module = pytest.importorskip("server.app.routes.advanced")`
   locals removed the side effect that **registered the Flask routes**, so two files passed in a
   full run and 405'd on their own. The fixtures in `tests/app/conftest.py` now import
   `server.app.app` first. Every file under `tests/app/` was checked to run standalone.

**Fault injection — the sharpest before/after of the five phases.** Method: rename each patched
symbol at its definition and at every production call site in `server/`, leaving the test patches
on the old name; then run exactly the tests that patch it, attributing a patch to a test only if
it is in the test's own body or in a helper/fixture the test actually reaches.

| | Before (`e2c093a`) | After |
|---|---|---|
| patching tests | 374 | 377 |
| detected **at the patch line** | **0** | **377 (100%)** |
| detected downstream | 149 | 0 |
| **silently absorbed** | **225 (60%)** | **0** |

Zero at-patch before is the mechanism, not bad luck: `raising=False` *creates* the attribute, so
a patch against a moved symbol installed its stub into carrier globals, the fragment resolved it
there, and the test passed against the stub.

**On reproducibility, which took three tries.** The first two sweeps disagreed (346 vs 362
at-patch) and a third disagreed again. The cause was the Phase 8 trap: stale `__pycache__`.
Running the injected subprocesses with `PYTHONDONTWRITEBYTECODE=1` and clearing `__pycache__`
per symbol made the after-state measurement **byte-identical across two consecutive runs**. Two
earlier measurement bugs are also worth recording because both flattered the result in one
direction and hurt it in the other: attributing a helper's patches to every test in its file
inflated "absorbed", and pytest's `-rf` summary lines are *truncated to terminal width*, so a
regex anchored on the full path silently missed failures — the classifier reads `--junitxml`
now. The baseline measurement is itself ±1 unstable (225 vs 224 absorbed across two runs); the
after-state is not.

**Found but not fixed:** `advanced_parts/binary_helpers_impl.py` and
`simple_parts/binary_helpers_impl.py` are duplicated implementations — both define
`_select_first_impl` and `_decode_base64url_bytes_impl`, neither imports the other; merging them
is file-level milestone scope. Three advanced forwarders have no production caller at all and
exist only for tests: `_extract_credential_id`, `_is_custom_cose_algorithm`,
`_extract_requested_assertion_algorithm`. `encode_parts` still imports five private names from
`decode.py` — encoder scope, untouched as instructed.

### M3 status: 5 of 5 carriers unwound. The split-module runtime hack is gone.
No module in the repo passes itself into its own fragments or rebinds their globals.
`ruff.toml` has no `[lint.per-file-ignores]` section at all, and F821 is gated at zero with
nothing ignored. The next milestone is file-level: re-merging along responsibility lines
(P2.4) and retiring the duplicated `binary_helpers_impl` pair.

### Phase 9 — M3: unwind the route carriers — DONE (2026-09-18). **M3 COMPLETE.**

| Metric | Before | After |
|---|---|---|
| `advanced_module.`/`simple_module.` reads | 498 | **0** |
| bare `*_module` tokens in `server/` | 581 | **0** |
| `_self_module()` forwarders | 45 | **0** |
| `advanced.py` / `simple.py` | 292 / 156 lines | **115 / 74** |
| `ruff.toml` per-file-ignores | 2 | **0 — section deleted** |
| `raising=False` repo-wide | 780 | **476** |

Tech-lead verified: all counts zero; F821 still zero **and still gated** (injecting an undefined
name into `routes/simple.py` fails the gate, reverting returns green); `tests/app/security/`
**78 passed**; collected test IDs 1708 with 0 added / 0 removed; suites 1708/278, ruff clean.
**The original Phase-1 forged-registration PoC still returns HTTP 400** — ceremony behaviour
genuinely unchanged.

**The agent changed the plan mid-phase, correctly.** A per-fragment conversion axis does not
work here: a test patches a *name on the carrier*, so the moment any ONE fragment stops reading
`advanced_module.create_fido_server`, that test silently stops affecting it. A patched name has
to move in **every** fragment at once. Conversion ran by dependency package
(metadata, credential_artifacts, device_logs, pqc, attestation, storage, config) with the test
re-point in the same commit.

**Fault injection — the most striking number of the whole milestone.** Of 374 patching tests,
**225 (60%) were silently absorbed by the carrier before; 0 after, with 377/377 detected at the
patch line** (downstream detections 149 to 0). Zero-at-patch beforehand was mechanism, not luck:
`raising=False` *creates* the attribute, so the stub landed in carrier globals and the fragment
resolved it there.

**Measurement honesty worth recording.** Reproducibility took three attempts. Causes found and
fixed: stale `__pycache__` (the Phase 8 trap); attributing a helper's patches to every test in
its file, which inflated "absorbed"; and — a genuinely subtle one — **pytest's `-rf` summary
lines are truncated to terminal width**, so a path-anchored regex silently missed failures. The
classifier now reads `--junitxml`. The agent also flagged that the *baseline* number is +/-1
unstable while the after-state is byte-identical across consecutive runs.

**Three real defects the work exposed:**
1. `register_begin_impl` had a local `attestation = public_key.get("attestation", "none")`
   shadowing the new module import; ruff's F401 autofix then deleted the import as unused.
   **F821 caught it** — the metric earning its keep immediately after being gated.
2. Patches inside plain test *helpers* were skipped by the re-point tooling, leaving dead no-ops
   still resolving on the carrier. An audit for "carrier patches no fragment reads" now returns 0.
3. Pruning dead `advanced_module = pytest.importorskip(...)` locals removed the side effect that
   **registered the Flask routes** — two files passed in a full run and 405'd standalone. Fixed
   in `tests/app/conftest.py`; tech-lead spot-checked four route test files running standalone.

## MILESTONE M3 COMPLETE — the structural unlock is done

| | Start of M3 | End of M3 |
|---|---|---|
| F821 | 1008 (ungated) | **0, gated** |
| Namespace carriers | 5 | **0** |
| `raising=False` | 868 | **476** |
| ruff per-file-ignores | 5 modules | **0** |
| Suite | 1708 | 1708 (identical IDs throughout) |

Every module in `server/` now resolves its own names through real imports. Static analysis,
type checkers and IDEs can see the real call graph for the first time. **File re-merging (M4)
is now safe** — tools can verify what moves break.

**Found but not fixed:** `advanced_parts/binary_helpers_impl.py` and
`simple_parts/binary_helpers_impl.py` are duplicate implementations (both define
`_select_first_impl`, `_decode_base64url_bytes_impl`), neither importing the other. Three
advanced forwarders have no production caller and exist only for tests:
`_extract_credential_id`, `_is_custom_cose_algorithm`, `_extract_requested_assertion_algorithm`.
`encode_parts` still imports five private names from `decode.py` — encoder scope.

### Phase 10 — M4: one encoding module — DONE (2026-09-18), verified
New `server/app/encoding.py` with an explicit API (strict base64url/base64/hex, `decode_pem_body`,
`sniff` returning a `SniffResult` that records which encoding matched plus `ambiguous`/`lenient`
flags). Leniency and odd-length-hex padding must be asked for by name.

| Metric | Before | After |
|---|---|---|
| Decode call sites outside the module | **77** (30 files) | **0** |
| Encode call sites | 65 | **0** |
| Decoders each deciding strictness alone | 21 | **1 module** |
| pytest | 1708 | **1860 passed, 4 skipped** |

Tech-lead verified: suites 1860/278, ruff clean, `tests/app/security/` 78 passed, and
**`POST /api/decode` now returns 422 for prose, odd-length hex and mixed alphabets** instead of a
wrong 200. The single most embarrassing defect in the original audit — a CTAP decoder that
answered `success: true` for plain English — is closed.

**A finding the agent added beyond the brief, and it matters.** `validate=True` does NOT reject a
final quantum whose unused bits are non-zero. Verified: `"debug-metadata"` decodes to 10 bytes but
re-encodes to `"debug-metadatQ"` — it does not round-trip. The module now decodes, re-encodes and
requires equality modulo padding. That is the class of bug that silently corrupts a credential ID.

### Corrections to MY OWN audit — both were my errors
- **Finding 3 mechanism: WRONG.** I claimed `urlsafe_b64decode` before `b64decode` makes standard
  base64 containing `+`/`/` decode to wrong bytes. It does not: `urlsafe_b64decode` translates only
  `-_` to `+/`, and `+`/`/` are already standard-alphabet, so they pass through and decode
  correctly. The agent disproved it with 200k randomized payloads; I reproduced it independently —
  **0 mismatches**. The REAL bug in those files was `validate=False` silently dropping
  out-of-alphabet characters, so a credential ID of `"Hello, this is plain text!"` returned 15 junk
  bytes. Fixed. The agent kept the refutation as a passing test.
- **Finding 4: half wrong.** `_decode_base64url_bytes_impl` genuinely was duplicated with drifted
  behaviour (deduplicated into `routes/binary_helpers.py`). But `_select_first_impl` is NOT a
  duplicate — verified: the copies live in `simple_parts/binary_helpers_impl.py` and
  `advanced_parts/parsing_helpers_impl.py`, with different signatures and different `None`
  handling pinned by an existing test. The agent left both and documented why rather than churning.

**Externally visible changes:** `/api/decode` 422 for unparseable input; MDS certificate route now
decodes base64url certificates whole (were truncated); WebAuthn intake returns absent rather than
junk bytes for out-of-alphabet `rawId`/`id`; spaced/colon hex now decodes as hex. The origin
allowlist fails **closed** — unparseable `clientDataJSON` yields `None` then 400, strictly tighter.
Precedence narrowing: `"414243"` is not canonical base64 so it now reads as hex.

**`convert_bytes_for_json` deliberately left as standard base64.** Verified coupling: `binary.js`
`base64ToHex`/`base64ToUint8Array` pass the value to bare `atob`, which throws on `-`/`_`;
certificate rendering and credential detail views both route through them. Server and frontend must
move together — queued for the frontend milestone. It now flows through `encoding.encode_base64`,
so the flip is a one-line change when we do it.

**Found but not fixed:** the decoder pipeline's hex-before-base64 precedence is genuinely lossy
(`"AAEC"` is valid as both, with different bytes) — inherited, now pinned by a test with a comment.
`fido2/websafe_decode` is still non-validating (vendored, out of scope). `sniff`'s `ambiguous` flag
has no consumer — surfacing it in the decoder response would be frontend-visible.

### Phase 11 — M4: re-merge the fragment sprawl — DONE (2026-09-22), verified
67 commits, all bare-subject. `server/` **126 -> 78** `.py` files; all six `*_parts/` packages gone;
**zero** files carry a `_runtime`/`_impl`/`_leaf` suffix. New layout: `webauthn/{attestation,metadata,pqc}`,
`decoder/{decode,encode}`, `routes/{simple,advanced}` packages, `storage/`. Each facade became its
package's `__init__.py`, re-exporting the same function objects.

Tech-lead verification:
- Suites 1860 passed / 4 skipped, vitest 278, ruff clean, F821 0, `tests/app/security/` 78.
- **Flask URL map byte-identical (31 rules)** vs `origin/main` — the mid-phase bare-name sweep that
  rewrote a route to `/api/authentication/begin` is confirmed fixed.
- **Collected test IDs identical (1864, 0/0)** and **the same 4 skips with identical reasons**. The agent
  caught 15 tests silently skipping mid-phase (`1845 passed, 19 skipped` with collection still at 1864) —
  the `importorskip` hazard; collection parity alone would have missed it.
- **Container layout simulated** (Docker daemon was down): copied `server/app` to `server/` as the
  Dockerfile does; all 11 relocated modules import, and the gunicorn target `server.app:app` resolves to a
  Flask app with 31 rules.

Deviations the agent made, all justified: the approved metadata grouping was cyclic
(`blob -> sessions -> snapshots -> blob`), so it split into 7 acyclic modules; all seven CTAP fragments
merged into one `ctap.py` because they imported each other in a cycle — that plus `pipeline` removed
**two pre-existing import cycles**; three renames to avoid collisions (`cbor.py` vs `fido2.cbor` ->
`cbor_parser.py`, `result.py` vs a local -> `response.py`, `register_begin.py` vs a Flask view ->
`registration.py`). Six `_impl` suffixes on *functions* are load-bearing (they distinguish a
parameterised implementation from its same-named wrapper) and were left rather than restructure DI.

Agent disclosed one process error: a gate result piped through `grep` in an `&&` chain masked the exit
status and **one red commit landed** before being reverted; replaced with a wrapper that cannot be bypassed
that way. (The tech lead hit the same `grep`-exit-code trap repeatedly in this session.) Two corrections to
its own earlier analysis: 39 import-time function captures exist (not zero — its grep missed dict literals),
and the two `_build_certificate_summary_lines` copies were not identical (the unreachable one is deleted).

**NEW CONCERN — big files.** Files over 800 LOC went **1 -> 4**: `decoder/decode/ctap.py` 1725,
`routes/advanced/registration.py` 1288, `config.py` 1005 (pre-existing), `webauthn/attestation/certificates.py`
973. The fix is splitting along REAL seams, never by line count (that was the original disease). Plan:
`ctap.py` after M5 rewrites it; `config.py` in the `create_app()` phase; `advanced/registration.py` and
`certificates.py` in a later structure pass.

### Process gap (tech lead's) — six commits reached `origin/main` unreviewed
Between the Phase 5 push (base `1dfd244`) and the Phase 6 push (base `d83e5b7`), `origin/main` advanced by
six commits I did not push and did not review — the push base silently changed. They were fixes from the
first real GitHub CI run on Linux: remove coverage badges and their workflow (`3462911d`); omit the
macOS-only `fido2/hid/macos.py` from coverage so the floor holds on Linux (`69f3974f`); vitest 5 + jsdom 30,
npm audit tightened `high -> moderate` (`64e07c10`); stop Dependabot bumping vendored fido2 (`9f515278`);
all rolldown platform bindings in the lock + `npm ci` everywhere (`5b069ea9`); Node 22 (`d83e5b70`).
**Reviewed retroactively 2026-09-22: sound.** No gate was loosened — coverage floor still 95, vitest
thresholds unchanged, `npm audit` now **0 vulnerabilities** at `moderate`. Two of them close issues left
open in Phase 5 (`npm install` drift; the moderate `@vitest/mocker` advisory blocked on vitest).
**Process fix:** on every push, compare the push base to my previous tip and review anything in between.

### Phase 12 — split `config.py`, one import path per module — DONE (2026-09-23), verified
**Part A — container layout.** Image now copies `server/app` to `/app/server/app`; CMD is
`gunicorn ... server.app.app:app`, the same path as a checkout. Removed every dual-import fallback:
`gunicorn.conf.py`, two in `tools/update_mds_snapshot.py`, the lazy `__getattr__` shim in
`server/app/__init__.py`, the `fido2/` probe and script-mode branch in `app.py`, and a bare
`import update_mds_snapshot` fallback in `mds_provisioning.py`. Tech lead grep: **zero** remaining.
(Chose `COPY server/app` not `COPY server` because `server/runtime/` held 20 local credential files.)

**Part B — `config.py` (1005 lines) -> `server/app/config/` package of 12 modules**, largest
`relying_party.py` at 190: `application`, `session_secret`, `compression`, `proxy`, `session_cookie`,
`security_headers`, `origins`, `attestation_trust`, `mds`, `relying_party`, `paths`, plus a
re-export `__init__` with `__all__` unchanged. The MDS trust root was duplicated in `config.py` and the
updater; it now lives once in the leaf `server/app/mds_trust.py`, which the updater imports without
building the app or writing the session secret.

Tech-lead verification:
- Suites 1857 passed / 4 skipped, vitest 278, ruff clean, F821 0, `tests/app/security/` 78.
- **Response headers and cookies captured before (`7f2e8d52`) and after, for `/` and `/health` over
  http and https in both dev and Cloud Run mode: 0 diff lines across all 8 responses.** CSP, HSTS,
  Permissions-Policy, `session` (`HttpOnly; SameSite=Lax; Secure`) and `fido.mds.session` identical.
- `ProxyFix` still `x_for=1, x_proto=1, x_host=0`; spoofed `X-Forwarded-Host` still yields the real
  RP ID.
- Test IDs 1864 -> 1861: exactly the three the agent named, each testing a deleted shim.
- The first real `docker build` of the new layout ran in CI (daemon down locally): green.

Tech lead follow-up commit `dc6152fa`: `.dockerignore` now excludes `server/runtime`, `instance`
(the session secret), `node_modules` and `coverage`. None was copied into the image, but a local
build shipped them to the daemon as context.

### CI incident — main red 2026-09-23 (external cause), resolved in `85935b60`
Last green CI was `9827b4db` on 09-18. **poetry-core 2.5.0 was published 09-19** (confirmed on PyPI)
and renders the vendored fido2's `pyscard = "^1.9 || ^2"` as `pyscard (>=1.9,<2.0 || >=2,<3)`, which
uv and pip reject as invalid metadata. That broke `uv sync`, `docker build`, the image scan, the audit
export and the scheduled MDS workflow. First failing push was the tech lead's `7f2e8d52` simply
because nothing was pushed between 09-18 and 09-23. Fix: the identical range written out,
`>=1.9,<3` (uv.lock unchanged). Confirmed via `gh`: all five workflows green on `85935b60`, and the
MDS snapshot workflow re-ran successfully.

**Lessons, both mine:**
1. I had not been reading GitHub Actions results at all — the GitHub connector was down and I did not
   try the `gh` CLI, which works. **From now on every push is followed by a `gh run` check.**
2. The deeper cause is that the BUILD BACKEND floats: `[build-system] requires = ["poetry-core>=1.0.0"]`,
   and `uv.lock` does not lock build-system requirements. So a third-party release can break a build
   of an unchanged commit — a hole in the Phase 3 "reproducible builds" claim. Queued: pin the build
   backend so such breaks arrive as a failing Dependabot PR instead of a red `main`. Note Cloud Build
   runs its own tests, so production was never at risk — but the scheduled MDS workflow failed daily
   from 09-19 with nobody noticing, which is a monitoring gap too.

### Phase 13 — `create_app()` factory — DONE (2026-09-23), verified
21 commits. `server/app/factory.py::create_app(config=None)` builds a fresh app from each config
submodule's `config_from_env()` plus overrides, then runs `INIT_STEPS` in a pinned order:
logs, secret, ProxyFix, gzip, security headers, static assets, blueprints, RP warning. Routes moved to
four blueprints (`general`, `simple`, `advanced`, `static_assets`); `server.app.app:app = create_app()`
keeps the gunicorn target unchanged. Non-web modules log via `logging.getLogger(__name__)`; request
code reads settings via `current_app`. Dead `rp`/`server` singletons deleted.
`config.app` survives only as a lazy alias for the ~230 legacy test references; a test fails if any
server module reads it.

Tech-lead verification:
- Suites 1880 passed / 4 skipped, vitest 278, ruff clean, `tests/app/security/` 78.
- **URL map: 31 rules and methods, 0 diff** vs `a647ad41`. All 30 app endpoints gained a blueprint
  prefix; 0 `url_for` anywhere, so nothing referenced the old names.
- **Headers and cookies: 0 diff lines** across `/` and `/health`, http/https, dev and Cloud Run mode;
  spoofed `X-Forwarded-Host` still yields the real RP ID.
- **No disk writes on import:** importing all 90 non-entry-point modules in a clean `git archive`
  (bytecode off) leaves the tree byte-identical. The same probe on `origin/main` writes
  `instance/session-secret.key` and creates `server/runtime/session-metadata` — the two import-time
  side effects the agent found (I had briefed only one).
- **Fail-closed:** `K_SERVICE` set with no secret -> `RuntimeError: Refusing to start ...`; with a
  secret -> starts, 31 rules. Dev keeps generate-and-persist (mode 0600).
- **Pre-push production check:** the live `pqcwebauthn` service (project `feitian-project`) has
  `FIDO_SERVER_SECRET_KEY` from Secret Manager `pqcwebauthn-session-key`, version 1 `enabled`. Values
  were not read. Cloud Run will not shift traffic to a revision that fails to start, so even the worst
  case keeps the current revision serving.

**Part A — build reproducibility.** Root `pyproject.toml` pins `poetry-core==2.5.0` exactly; a test
enforces an exact pin. Dependabot CANNOT see it (dependabot-core skips `[build-system]` in a Poetry
project), so a weekly `update-build-backend.yml` builds fido2 with the new release through uv and pip,
runs pytest, and only then opens a bot PR — a breaking release fails that job while `main` stays green.
Scheduled-run failures are now surfaced: `ci-scheduled-runs.yml` (`actions: read` only) posts a warning
annotation on every push/PR while any scheduled workflow's latest run on `main` has failed. Issues are
disabled on this repo, so it warns rather than opening one. Replayed against history it would have
flagged the MDS failures AND a `ci-security` scheduled failure on 09-21 that also went unnoticed.
Removed unused trust anchors including the Baltimore root that expired 2025-05-12.

**Corrections to my briefing:** only 3 of the 19 `reload` matches were app reloads (13 reload
`fido2.features`, 3 are fake `Blob.reload()` methods); ~230 test references go through
`config_module.app`, hence the lazy alias; there were TWO import-time disk writes, not one.

**Found but not fixed:** `SESSION_METADATA_RECOVER_ON_START` is set but never read; `print()` instead of
logging at `certificates.py:909` and `device_logs.py:201,207`; images pinned by tag not digest (trivy,
uv, `python:3.12-slim`); builder `pip` unpinned; `setup-uv` `version:` and `uvx` pins invisible to
Dependabot.

**Still open from the original audit:** the live service runs with `GITHUB_TOKEN`, so every production
registration is logged to the hardcoded personal repo `rainzhang05/CredentialLogs`.

### Phase 13 deploy — verified in production (2026-09-23)
Cloud Build `3236ce10` SUCCESS; revision `pqcwebauthn-00428-9qw` ready and serving 100%; `/health` 200 on
both `run.app` and `webauthnlab.tech`; live `/` serves CSP, HSTS, X-Frame-Options, Permissions-Policy and
correctly flagged cookies. The fail-closed secret check shipped without incident. GitHub CI green on all
six workflows including the new `Scheduled runs` check.

### CRITICAL — the Cloud Build test gate has NEVER run
Found while watching this deploy. The production trigger `postquantum-webauthn-platform`
(project `feitian-project`) uses an **inline build config** with three steps — Build, Push, Deploy — and
**ignores the repository's `cloudbuild.yaml`**. So the Python and frontend test steps Phase 5 added (and the
Node 22 change to that file) have never executed: **every push to `main` has deployed to production
untested.** The tech lead "verified" the gate in Phase 5 by reading `cloudbuild.yaml` and never checked
what the trigger actually runs. Lesson: verify the deploy path by what the platform executes, not by what
the repo says.

Mitigating facts: the inline Build step runs the same Dockerfile, so an image that fails to build still
cannot deploy (that is what protected production during the poetry-core incident); and Cloud Run does not
shift traffic to a revision that fails to start.

Compared line by line: the inline and repo configs build and deploy the **same image to the same service
with the same command**; the repo file only adds the two test steps. Differences are cosmetic
(`--no-cache`, a `gcb-trigger-id` label). One real blocker was fixed pre-emptively in `4ee40e5a`: the
trigger defines substitutions the repo file does not use, which Cloud Build rejects unless
`substitutionOption: ALLOW_LOOSE` — now set, inert until the switch.

**Operator action (needs owner approval — persistent cloud config):** point the trigger at the file:
`gcloud builds triggers update github postquantum-webauthn-platform --project feitian-project --build-config=cloudbuild.yaml`
then confirm the next push runs five steps. Full trigger JSON is backed up for rollback. Also noted: the
trigger runs as the default compute service account, which has broad default permissions.

### Metric correction — `raising=False`
The raw count rose 476 -> 486, which looked like regression. It is not: the risky form is
`setattr(..., raising=False)` (silently creates a missing attribute); `delenv(..., raising=False)` is
idiomatic. Split correctly: **risky attr-patches 417 -> 419 -> 417 (flat)**; benign env/dict 59 -> 69.
Remaining risky sites: `app/session` 104, `app/metadata` 83, `app/core` 74, `app/storage` 30, and 110 in
vendored `fido2` tests.

### Phase 14 — M5a: codec labels, tables and canonical encoding — DONE (2026-09-24), verified
8 commits. COSE algorithm names now come only from `webauthn/pqc.py::describe_algorithm`; COSE key types
and curves from two small IANA tables; one new `server/app/decoder/ctap_tables.py` (request parameters,
response members, commands, statuses — derived from the vendored fido2's `Ctap2` signatures, response
dataclasses, `Ctap2.CMD` and `CtapError.ERR`) is read by both decoder and encoder; encoder bytes come only
from `encode/cbor_canonical.py`, CTAP2-canonical, with the cbor2 fallback removed.

Tech-lead verification through the real endpoints:
- An ES384 credential key inside an attestation object now reads `ES384 (ECDSA)` on `P-384`
  (was `ES256K`); ML-DSA-44 reads `ML-DSA-44 (PQC)`, `AKP (7)`, `parameterSet`; a truncated ML-DSA-65 key
  is flagged with `publicKeyBytesExpected: 1952`.
- makeCredential parameter 0x0B reads `attestationFormatsPreference`; `largeBlobKey` appears nowhere.
- `31` and `0x31` decode as `PIN_INVALID status`; `04` as `GET_INFO command or INVALID_SEQ status`.
- **Encoder ordering checked against an independent implementation of the CTAP2 rule**: `{24:0,"":0}`
  -> `a2 1818 00 6000`, and **0 mismatches over 2000 random maps** mixing positive, negative and text keys.
- **CTAP 2.2 field numbers checked against the published Proposed Standard (2025-07-14)**, since the agent
  cited them from memory: makeCredential request 0x0B `attestationFormatsPreference` (6.1), makeCredential
  response 0x06 `unsignedExtensionOutputs`, getAssertion request ends at 0x07 `pinUvAuthProtocol` (no 0x08,
  6.2), getAssertion response 0x08 `unsignedExtensionOutputs`, and the canonical key-sort rule verbatim.
  All correct.
- **New tests: 151; on the pre-change code 138 fail, 5 cannot load (they test the new module), 8 pass**
  (controls such as "a non-CTAP byte still reads as JSON"). The report omitted this number; measured by the
  tech lead per file, since one import error aborts a combined run.
- Suites 1880 -> **2031** passed / 4 skipped, vitest 278, ruff clean, security 78.

**Extra defect the agent found:** the encoder ignored the kind named in `ctapDecoded` and re-sorted fields by
number, so a decoded makeCredential request, getAssertion request or getAssertion response could not be
re-encoded at all — and it wrote `"8 (largeBlobKey)"` out as CBOR key 0x05. All four kinds now round-trip
byte for byte.

**Deliberate input-format change:** a whole input of exactly two hex digits that names a CTAP code is now read
as that byte, not a JSON number (`"10"`, `"99"` stay JSON), so PIN errors 0x30-0x39 typed as hex are named.

**Frontend tables found (not edited, queued):** `advanced/constants.js:29` labels kty 7 `'ML-DSA (7)'`
(should be `AKP`), kty 5/6 missing; **`decoder/codec/labels.js:17` strips the minus sign, so COSE labels
-1/-2/-3 display as 1/2/3** in the decoder UI. The frontend has no CTAP tables and reads none of the changed
fields, so the server changes break nothing there.

**Found but not fixed:** a getAssertion request without an allowList still decodes as a makeCredential
*response* (the `ctapDecoded` builder ignores the command byte); the `cose` encoder format is broken; the
encoder's decoded-JSON path silently drops unknown fields; the vendored `fido2.cbor` sorts by first byte,
which differs from the CTAP2 rule for array/map keys (the spec notes exactly this); importing `ctap_tables`
loads `fido2.hid` and the platform HID backend into the web server.

### Phase 15 — M5b: the decoder is honest — DONE (2026-09-24), verified
17 commits. `decode/cbor_parser.py` is the only parser: strict by default, failing with 422
`{error, offset, path}` where input stops being well-formed; best-effort only when a request sends
`"lenient": true`, and the response then lists what was skipped. `decode/canonical.py` reports CTAP2
canonical-form violations as `findings` on every decode (never changing the value); `decoder/ctap2_order.py`
is the key order shared with the encoder. The decoder no longer uses `fido2.cbor`, cbor2 or fido2's
`AttestationObject`/`AuthenticatorData` to parse (only its FLAG constants); a test scans for regressions.

**The "repair" layer is deleted, not made opt-in.** Git history showed every repair branch (2025-10-09..11)
existed to make six dumps in a since-removed `CBOR_hexcode.txt` decode — and the agent recovered that file
and showed **every one of those dumps is corrupt**: a lost `0x88` in the rpIdHash, `credIdLen = 0x19f7`, and
`"alg"` missing its `g` so the `-7` byte became the third character — which is exactly where the `"al&"`
magic string came from. The ML-DSA-65 dump is one byte short. The "repairs" were fitting code to broken
captures. Deleted: the `"al&"` merge, the `-50`/`-7` default algorithm, the trailing-signature merge, raw-byte
getAssertion recovery (a hex search for `0358`), reading authData's tail back as response members,
status-byte promotion, re-reading a user field via cbor2, and the lines that erased warnings.

Tech-lead verification through `/api/decode`:
- `a201010102` -> `duplicate-map-key` finding (offset 3); `a1180102` -> `non-shortest-integer`;
  `bf0102ff` -> `indefinite-length`; `48aabb`, `8a01`, `1e` -> 422 with offset and path; `f6`/`f7`/`fa..`/
  `fb..`/`8201f6` -> `null` / undefined / 1.5 / 1.5 / `[1, null]` (were `false` via fido2.cbor); a
  getAssertion request without allowList is labelled a getAssertion request; trailing `deadbeef` after a
  makeCredential response is reported at its offset and kept; `"lenient": true` returns the partial value
  plus a `skipped` finding; a non-boolean `lenient` is a 400; prose is still rejected.
- **Valid input is unchanged:** nine realistic payloads (none and packed ML-DSA attestation objects, authData,
  a COSE key, a PublicKeyCredential JSON, clientDataJSON, a makeCredential response, a getAssertion request,
  plain JSON), built once and fed to both trees: **all nine byte-identical** apart from the new
  `decodeMode`/`findings` keys.
- Frontend: minus sign kept (`-1` is no longer shown as `1`); kty 5 `HSS-LMS`, 6 `WalnutDSA`, 7 `AKP`; the
  new findings list and lenient checkbox add **no `innerHTML`** and **no inline handlers** (template count
  96 -> 96); the checkbox has a proper `<label for>`.
- Suites 2031 -> **2125** passed / 4 skipped, vitest 278 -> **287**, ruff clean, security 78.
- Agent-reported: 73 of 77 new Python test functions fail on the pre-change tree (run per file); 7 of 9 new
  frontend tests. The 11 coverage-chasing decoder files were triaged per file (kept / rewritten as behaviour
  specs / deleted); `test_decoder_ctap_repair_edges.py` deleted outright.

**Found but not fixed:** `fido2/cbor.py` is still wrong (`load_bool` for all of major type 7, silent
truncation in `load_bytes`, `struct.error` in `load_int` on short data) and the WebAuthn ROUTES still parse
real browser input with it — authenticators never send floats/null in CTAP so practical risk is low, but it
belongs in the un-fork phase. `keys.get_mapping_entry`/`_resolve_ctap_label` match keys across types (a byte
key `h'01'` or text `"1"` reads as member 1). Bytes left inside authData show as `trailingBytesHex` but are
not a finding; the COSE key and extensions inside authData are not canonical-checked. An attestationObject
nested in PublicKeyCredential JSON does not surface its findings. The CTAP nesting limit (4) is not reported.

### Phase 16 — M5c: decoder features — DONE (2026-09-24), verified. **M5 (codec) COMPLETE.**
25 commits. New interpretation modules, each beside (never replacing) the decoded value:
`decode/get_info.py` (authenticatorGetInfo), `decode/extensions.py` (CTAP 2.2 §12, WebAuthn L3 §10),
`decode/attestation_statement.py` with `tpm_structures.py`, `android_key.py`, `safetynet.py`,
`apple_anonymous.py` (WebAuthn L3 §8.2-8.9), and `decoder/cose_tables.py` (IANA/RFC 9052/9053/8230/9964,
shared with the encoder). Everything "shows, does not verify" and each attestation view lists what it did
not check. DER is read only through `cryptography` (`x509`, `hazmat.asn1`). `decode/ctap.py` 900 -> 891.

Tech-lead verification:
- **getInfo members checked against the published CTAP 2.2 PS §6.4: all 29 (0x01-0x1D) match exactly.**
- **Extension identifiers checked against §12: all 7 covered** (credBlob, credProtect, hmac-secret,
  hmac-secret-mc, minPinLength, pinComplexityPolicy, thirdPartyPayment); the repo's extra names are the
  legitimate related identifiers (getCredBlob, hmacCreateSecret/hmacGetSecret, largeBlob, largeBlobKey).
- Real Yubico getInfo vector decodes as `GetInfo response` with GUID
  `f8a011f3-8c0a-4d15-8006-17111f9edc7d` and explained options ("absent means: not supported").
- Part B: text-keyed `"2"`/`"3"` no longer read as CTAP members; 5-level nesting -> `nesting-depth`
  finding; bytes left inside authData -> `authdata-trailing-bytes` at `${2}`.
- **Valid input unchanged:** the nine fixed payloads decode identically on `5775d0bb` and HEAD, ignoring only
  the two new keys (`PYTHONPATH` set explicitly for the old tree).
- No `innerHTML` added; template inline-handler count 96 -> 96, now pinned by a test.
- Suites 2125 -> **2325** / 4 skipped, vitest 287 -> **293**, ruff clean, security 78, coverage 96%.
- Agent-reported: 54 of 65 new Part B tests fail on the old tree (the 11 others are controls or pin
  already-correct behaviour); 19-payload valid-input diff including real tpm/u2f/packed/safetynet/apple vectors.

Honesty notes from the agent, correctly flagged: there is **no real android-key vector** in the repo, nor a
real packed self-attestation, ED-flag authData or clientExtensionResults — those tests use WebAuthn L3 §16
spec test vectors, labelled as such. The TCG TPM spec PDFs are bot-walled, so TPM constants are cross-checked
against fido2's verifier and the real Windows Hello vector (Part 2 §6.3/§6.9 unchecked). Two real vectors
break their own format's syntax and the decoder now says so: the fido2 TPM capture has no `ver` (§8.3), and
the Apple capture carries an `alg` §8.8 does not define.

**Shared memory:** the agent added `pre-change-tree-comparisons` — the editable fido2 install puts the repo on
`sys.path`, so an old-tree *script* can silently import current code. The tech lead re-checked that its own
earlier old-vs-new probes used `sys.path.insert(0, cwd)` and did import the old tree (a worktree at
`7f2e8d52` correctly lacks `factory.py`), so past diffs stand.

**Found but not fixed — decoder input honesty, queued for Phase 17:**
- **JSON can silently drop a map entry:** integer key `1` and text `"1"`, or `h'01'` and `"01"`, collapse to
  one JSON key and an entry disappears from `decodedValue`/`ctapDecoded`. This breaks the decoder's own
  "never drop a field" rule.
- **Hex made only of digits is read as JSON** (e.g. `818181...`); Phase 14 fixed only the single-byte case.
- Text member names still label CTAP members ("fmt", "rpId"); user/descriptor maps read integer keys 1-4 as
  id/name; the encoder ignores unknown top-level keys of decoded JSON; bare authData with trailing bytes falls
  through to plain CBOR; getInfo checks none of §6.4's MUSTs; "uvm" (WebAuthn L2) is labelled unknown;
  ML-DSA is not in AOSP's Algorithm enum yet; interpreted fields display alphabetically (Flask sorts keys).

### Phase 17 — decoder input honesty and queued correctness bugs — DONE (2026-09-24)
18 commits, each gated on pytest, vitest and ruff exit codes; every commit's tree re-run afterwards.

**Part A, decoder input honesty.**
- *JSON key collisions.* Map keys become JSON keys only through `keys.json_keys`. Where nothing collides the
  spelling is unchanged; where two keys of one map would share a spelling, each is spelled with its type --
  `1`, `"1" (text)`, `h'01' (bytes)`, `true (boolean)`, `1.5 (float)`, `[1, 2] (array)` -- and
  `decode/key_collisions.py` adds a `json-key-collision` finding (category `rendering`) with the map's offset,
  path and the typed keys. It applies in decodedValue, ctapDecoded, expandedJson, user and descriptor maps,
  getInfo (members, options, certifications), extension blocks and attestation-statement views. Array, map and
  tag keys are now keys of their own type (they used to be `str()`-ed into text keys that could replace a real
  text key). The response goes through `keys.json_ready`, so an attestation statement with integer and text
  keys no longer crashes `jsonify` with HTTP 500 (it did: `sort_keys` cannot order `int` and `str`).
- *Hex that is also a JSON number* (`decode/ambiguous_input.py`): read as hex when its bytes are one
  well-formed CBOR item after at most one CTAP command/status byte, with nothing after; otherwise as the JSON
  number. Either way an `ambiguous-input` finding names the reading not taken. `818181` stays JSON (the
  innermost array is empty-handed), `81818101` is `[[[1]]]`, `31` is PIN_INVALID, `99` stays JSON. **This
  reverses the Phase 14 note that "10" stays JSON: `10` is now the CBOR integer 16, with the JSON reading
  named.** sniff()'s base64/base64url `ambiguous` flag, which nothing read, now labels a nested binary field
  `"base64 or base64url"` instead of asserting `"base64"` for a base64url WebAuthn field.
- *Cross-type labels.* CTAP member labels apply only to integer keys of a CTAP message; a text `"fmt"` or
  `"rpId"` is not a member, and text keys named `attStmt`/`signature` in expandedJson no longer add
  "MakeCredential response"/"GetAssertion response" to the type. User entities and credential descriptors are
  read by their text keys only (integer 1..4 are not id/name), and a non-bytes `id` is shown instead of dropped.
  A text-keyed attestation object whose authData does not parse is still interpreted as a WebAuthn
  attestation object (attestationStatementDecoded, authData findings), just not labelled a CTAP response.
- Valid-input diff: 37 fixed payloads through `/api/decode` on `8d76ff14` and HEAD: **33 byte-identical**;
  the 4 that differ are exactly where a rule fires (`31` and `99` gain the finding; two PublicKeyCredential
  payloads say `base64 or base64url` on 4 fields).

**Part B, queued correctness bugs.**
- `/api/credentials`: a store that cannot be read is 500 with a message (was 200 `[]`); a record that cannot
  be shown is skipped, logged and counted in `X-Unreadable-Credentials`; DELETE reports `status: partial`
  with the failed users (500), and `storage.delkey` now raises when a copy it should delete stays (it ignored
  every error). No frontend code calls this endpoint.
- A name the store refuses raises `storage.common.InvalidStorageIdentifier` (a `ValueError`); one app error
  handler (`routes/errors.py`) answers 400 with one warning line, no traceback. Covers downloadcred,
  deletepub, simple register/authenticate complete. The advanced register flow read the store by user name
  and discarded the result: deleted, so any WebAuthn `user.name` registers there (`team/alice` was a 500).
- The credential list shows `sign_count` (last authentication), not authData's registration-time counter.
- Advanced register/complete now stamps and consumes its challenge and reports `challengeStatus`; both
  advanced completes consume before anything can fail and report on every response. Reported, not rejected.
- signCount save is compare-and-swap: `storage.read_for_update`/`save_if_unchanged`, a GCS generation
  precondition (client-library retry off, so a landed-then-retried upload cannot read as a lost race) or a
  local `flock` on `<file>.lock` held across the digest check and the rename. A lost race re-reads and
  re-checks once (the clone is then rejected against the winner's counter); losing twice is 409. **Real race
  test:** two genuinely signed assertions with counter 6, held by a barrier until both have read counter 5:
  `8d76ff14` answers `[200, 200]`, HEAD `[200, 400]` (stored 6, received 6). Also 8 threads and 3 spawned
  processes race `save_if_unchanged` on one file: exactly one writes, 15/15 runs.
- `checks.py`'s uncompared `metadata_aaguid_bytes`: **deleted**, not compared. Every entry that function sees
  was looked up by the credential's own AAGUID (fido2 `ca_lookup`, the PQC path, the fallback), so they cannot
  differ; the one chain lookup runs only when the credential has no AAGUID (fido-u2f: zero by definition),
  where a comparison would flag every legitimate registration. The entry's AAGUID is still reported.

**Part C.** `print()` in `device_logs.py` and `certificates.py` (user registration parse errors to stdout)
now go to module loggers; a test scans `server/` for `print(`. Deleted: `SESSION_METADATA_RECOVER_ON_START`
(and `mds` from `CONFIG_SOURCES`), the `backports.zoneinfo` fallback, `MetadataDownloadError`, and
`_extract_credential_id`, `_is_custom_cose_algorithm`, `_extract_requested_assertion_algorithm` (no caller
but tests; the functions went with their forwarders).

**Tests.** 2325 -> **2420** passed / 4 skipped, vitest 293 -> 293, ruff clean. 106 new or rewritten test cases:
74 fail on the pre-change tree, 14 cannot load there (they test the new `ambiguous_input` module and the new
storage API), 18 pass there by design (controls, and item 9's deletion, which changes no behaviour).

**Process note:** one commit was made with a failing gate (a `;`-chained command committed after pytest
exited 1: five device-log tests pinned stdout). It was local, amended green before anything else, and every
commit of the phase was then re-run on its own tree: all green.

**Found but not fixed:**
- A duplicate CBOR map key still keeps only the later value (reported as `duplicate-map-key`; the earlier
  value is not shown). JSON input with a duplicate object key loses one silently (`json.loads`).
- The encoder's generic CBOR path writes every decodedValue key as text (the integer 1 becomes "1"), and
  would write a typed spelling such as `"1" (text)` literally; it never round-tripped integer keys.
- ctapDecoded for makeCredential/getAssertion responses omits non-integer keys (expandedJson has them).
- Simple registration's readkey-append-savekey is still not compare-and-swap: two concurrent registrations
  for one user can lose a record (writes are now serialised locally, but not re-checked).
- `storage.iter_credentials`/`readkey` still skip a blob or file they cannot read, so a transient GCS error
  can read as fewer credentials; a failed counter read still lets authentication fall back to the client copy.
- `malformed` (legacy) repeats every finding message, including the new rendering/input notes.

**Phase 17 — tech-lead verification (2026-09-24):**
- Suites 2325 -> **2420** passed / 4 skipped, vitest 293, ruff clean, `tests/app/security/` 78 -> **93**.
- **Every one of the 18 commits passes pytest on its own** (run commit by commit in a worktree). The agent
  disclosed, in its memory notes rather than its chat report, that a `;`-chained command committed after
  pytest failed; it was amended before push, and no red commit survives in history.
- `{1:"a","1":"b"}` decodes to `{"1":"a", "\"1\" (text)":"b"}` with a `json-key-collision` finding — no
  entry lost. `81818101` -> CBOR `[[[1]]]`; `818181`, `99` -> JSON; `10` -> CBOR 16; all with an
  `ambiguous-input` finding naming the reading not taken.
- `/api/downloadcred` and `/api/deletepub` with `email=../x` -> **400, no traceback logged**.
- **Compare-and-swap raced independently at the storage layer:** 20 trials x 8 writers all holding the same
  read version -> exactly one write won in **20/20**. (Local file-lock path; the GCS generation-precondition
  path cannot be exercised from here and rests on the agent's tests.)
- Valid-input diff on the nine fixed payloads: eight identical; the PublicKeyCredential payload differs only
  where the reported rule fires (an ID with no `+/-_` is now `base64 or base64url`).
- The agent amended the shared memory entry recording the owner's commit/push rule. The rule itself is intact
  (main only, commit AND push, small bare-subject commits, no co-author); the additions record that a phase
  brief's no-push applies to that phase, and that commits must be gated on exit codes.

### Phase 18 — silent patches, race-safe credential writes, decomposed routes, size ratchet — DONE (2026-09-24)
29 commits, each gated on pytest, vitest and ruff exit codes, and each re-run afterwards on its own tree in a
worktree (all green; the worktree's own `server.app` and `fido2` were imported, checked by path).

**Step 1, no silent patches.** tests/ had **417** `monkeypatch.setattr(..., raising=False)` calls by AST (the
brief's 282 is the single-line subset). A pytest plugin wrapping `MonkeyPatch.setattr`, run on macOS and in a
Linux container: 406 always patched an existing attribute; the rest were a vacuous patch
(`test_metadata_session_binding.py` set `SESSION_METADATA_DIR` on the `metadata` package, which has none — dropped),
two FreeBSD tests adding `sysctlbyname` to the host libc (glibc has none, so removing `raising=False` would have
broken Linux CI — they now bring a fake `libc`), and 12 calls that must create an attribute (builtin `open`/`range`
shadowed in one module; Windows-only `ctypes.WinDLL`/`WinError`/`HRESULT`). `raising=False` setattr calls
**417 -> 12**, all in `test_no_silent_monkeypatch.py`'s `ALLOWED` (9 file/attribute entries, each with its
reason); the ratchet also refuses positional `raising`, non-literal `raising`, and `mock.patch(create=True)`. On
the pre-change tree it flags 407 calls. No test was deleted.

**Step 2, race-safe credential writes.** Simple registration appends to the user's list by `read_for_update` /
`save_if_unchanged`, retrying a lost race up to 8 times (N racing writers lose at most N-1 times each), 409 after
that. A read error is now a 500 — on GCS `readkey` used to swallow a download error, return `[]`, and let the
save replace every stored credential. A save that raised is re-read, so a write whose reply was lost counts as
saved. `delkey` removes the current file under the store's lock (a delete could land between a CAS check and its
rename, and the rename wrote the records back). Credential-artifact merges (the browser's merge upload and the
snapshot PUT hit one record) are conditional on the GCS generation, and hold an `flock` locally; a merge that
cannot read the record refuses rather than overwrite it. The lock helpers moved to `storage/common.py`. The other
credential writes are not read-modify-writes: `deletepub` and the delete-all loop are blind deletes, the advanced
registration artifact is a create under a fresh random id. **Race tests on the pre-change tree: 15 fail, 12 pass**
(controls and the existing CAS tests): 8 genuine registrations racing for one user answer 8x200 and store **2 of 9**
credentials (local and fake GCS); the artifact merge loses the other instance's key; a delete during a save leaves
the records behind; and two processes merging one local artifact lose a key — or fail outright, since the old
store wrote every artifact through one fixed `<path>.tmp`. All pass now. Tests that neutralised persistence by
patching `readkey`/`savekey` (which the new code no longer calls, so they wrote real files under `instance/`) were
retargeted; four `readkey` patches in advanced tests that nothing had read since Phase 17 were removed.

**Step 3, decomposition.** Built first, on the untouched tree: `tests/app/characterization/` — 35 scenarios through
the simple and advanced ceremonies, the decoder and the attestation serialisers, each recorded byte for byte
(status, headers, decoded cookies, body, every JSON file written to either store, device-log events) with the
clock fixed, randomness reseeded per request, stores in a temporary directory and the MDS stubbed (an audit hook
fails a scenario that opens anything under `frontend/static`). Keys and certificates are deterministic (derived EC,
seeded Ed25519/Ed448, RSA from derived primes, Ed25519-signed certificates); only echoed ML-DSA signatures are
frozen. Stable across three hash seeds, alone and in the full suite, and on Linux; kept as a test. **Characterization
diff: empty at every commit of the phase**, steps 1 and 2 included; the only scrub beyond time is the memory
address cryptography puts in a SafetyNet certificate's SCT extension text. Then: advanced registration
(1309 lines) became orchestrators over `registration_options`, `registration_inputs`, `registration_attestation`,
`registration_record` and `registration_persistence`, with the algorithm offer in `algorithms.py`; advanced
authentication over `assertion_credentials`, `assertion_options`, `assertion_verification`; simple registration
over `registration_record` and `registration_persistence`; `certificates.py` (977) over `certificate_names`,
`certificate_extensions`, `certificate_public_keys`, `certificate_summary`; `checks.py` split in place. Every
moved name is gone from its old module (checked with `hasattr`); moved code is called through module objects;
seven test patches were retargeted to the module that now defines the name (left alone, each fails with an
`AttributeError` or, for a logger, an unmet assertion — no longer a silent pass). URL map identical (31 rules); no collected
test ID vanished (2424 -> 2484); the same 4 skips.

**Step 4, size ratchet.** `test_code_size_ratchet.py`: functions <= 80 lines, modules <= 700, except entries at
their current length that may only shrink. Functions over 80 in `server/app` **34 -> 14**, modules over 700
**6 -> 3**. Largest function **328** (`advanced_authenticate_complete`) -> **191** (simple `authenticate_complete`,
out of the brief's scope); largest module **1309** (`advanced/registration.py`) -> **811** (`decode/ctap.py`, which
the test now holds at its size). Remaining entries: `routes/simple/authentication.py::authenticate_complete` 191,
`mds_snapshot.py::build_explorer_entry` 131, `classical._evaluate_classical_attestation_root` 122,
`pqc._evaluate_mldsa_attestation_root` 120, `credential_list` builders 114/85, `decode/pipeline._decode_public_key_credential`
109, `advanced/parsing._parse_client_supplied_credentials` 100, `advanced/tracing._log_authenticator_attestation_response`
94, `pqc._attempt_pqc_attestation_signature_validation` 89, `decode/response._build_credential_payload` 88,
`decode/ctap._try_decode_cbor` 85, `session_secret._resolve_secret_key` 84, `cbor_parser._structure_to_value` 82;
modules `decode/ctap.py` 811, `storage/credentials.py` 771, `decode/pipeline.py` 763.

**Tests.** 2420 -> **2480** passed / 4 skipped (Linux 2406 -> 2466 / 5), `tests/app/security/` 93 -> **105**,
vitest 293 -> 293, ruff clean, coverage 96.15% -> **96.45%**.

**Found but not fixed:**
- The certificate view shows a SafetyNet certificate's SCT extension as Python `repr` text with memory addresses
  (`<...Sct object at 0x...>`): different on every run, and meaningless to a reader.
- `test_challenge_replay.py::test_advanced_registration_reports_a_replayed_challenge` leaves a directory in
  `server/runtime/session-metadata/` on every run (it does not redirect `SESSION_METADATA_DIR`); five session tests
  patch `config.SESSION_METADATA_DIR`, which `storage/session_metadata.py` copied at import, so nothing reads it.
- Legacy credential copies carry no version, so a save racing a delete can still write back deleted legacy records.
- A conditional GCS upload is one attempt: an artifact merge whose write landed but whose reply was lost answers
  "Unable to store artifact" (registration re-reads to tell; the merge does not).
- Local credential artifacts are stored by storage id alone; on GCS they are scoped by session.
- `mds_snapshot.py` keeps its own copies of three algorithm-name helpers now in `certificate_names.py`.
- The characterization goldens are 2.1 MB and change with cryptography's extension `str()` and parse-error text:
  a bump that moves them is regenerated with `CHARACTERIZATION_WRITE=1` and the diff reviewed.
- Still open from Phase 17: `readkey`/`iter_credentials` skip unreadable blobs; authentication falls back to the
  client's counter when the server read fails.

**Phase 18 — tech-lead verification (2026-09-24):**
- macOS 2480 passed / 4 skipped, coverage 96%, vitest 293, ruff clean, `tests/app/security/` 105.
  **Linux (python:3.14 in Docker, run independently) 2466 passed / 5 skipped.**
- **Every one of the 29 commits passes pytest on its own** (run commit by commit in a worktree).
- **The golden records describe the old code:** the harness, copied onto the untouched 550a5e8f tree,
  passes 35/35 there. A one-byte change to one advanced-registration response field on that tree fails
  9 of 35, so the harness is sensitive.
- **The race tests fail on the old code for the stated reason**, not on fixtures: with the new tests and
  conftests copied onto 550a5e8f, 14 fail. Eight concurrent registrations keep only the existing
  credential and one of the eight, and the artifact merges lose the other writer's key. On the new code
  they passed 15/15 repeated runs.
- My own AST count agrees with the report: `raising=False` setattr/setitem 417 -> 12, functions over 80
  lines 34 -> 14, modules over 700 lines 6 -> 3. The nine allowlisted pairs are builtins shadowed in one
  module and Windows-only `ctypes` names.
- The URL map (31 rules) and the decoder's output on the nine fixed payloads are identical to 550a5e8f.
- The golden files contain no private key and no machine path.
- Queued: when the server's credential read fails, simple authentication checks the signature counter
  against the client-supplied value alone, which the client can omit. A missing record may fall back; a
  failed read should fail closed.

### Phase 19 — backend correctness leftovers — DONE (2026-09-24)
11 commits, 56d87b96..the record's own, each gated on pytest, vitest and ruff exit codes and each re-run
afterwards on its own tree in a worktree. (231f6f99 and ed279cdc, between Phase 18 and this phase, were made
in the same checkout by another session and are not this phase's.) Every new test was also run on the
untouched 383f4a15 tree, adapted only where it imports a name that did not exist yet.

**Step 1, fail-closed signature counter.** A failed read of the stored records now rejects simple
authentication: 503 `{"error": ...}`, nothing saved, no session key but the ceremony's own consumed, one
warning line naming the cause and no traceback. A read that works but holds no record for the credential
still falls back to the browser's copy; `InvalidStorageIdentifier` stays 400. The counter stage moved out of
`authenticate_complete` into `enforce_sign_count` (191 -> 137 lines). **On 383f4a15** the read-failure test
fails both ways (with and without a client `signCount`): a credential stored at counter 10 authenticates
at 5 with `200 {"status": "OK", "signCount": 5}`.

**Step 2, reads that fail are not "fewer credentials".** `download_bytes` returns `None` for a missing
object and raises otherwise; locally only `FileNotFoundError` is "not there". The store now tells three
cases apart: not found (fine); unreadable (`common.StorageReadError`, an `OSError`, raised from the cause,
naming the copy); undecodable (a warning naming the file or object and the reason, never the content --
an unpickling error's own message quotes the bytes -- then skipped and counted). The first copy that
exists is the user's: an older, stale copy never stands in for a newer undecodable one.
`read_for_update` refuses an undecodable current copy (`CredentialsUndecodable`) rather than let the save
replace it unread; the counter check then fails closed too. A failed GCS listing raises instead of warning.
`GET /api/credentials` answers 503 on a read error and `{"credentials": [...], "unreadableCount": n}`
when copies did not decode (the `X-Unreadable-Credentials` header stays); `DELETE` deletes undecodable
users too; `routes/errors.py` answers `StorageReadError` with 503 everywhere else (`downloadcred` said 404).
The record format moved to `storage/record_format.py` first, which took `credentials.py` from 771 to under
700 lines (its ratchet entry is gone). Frontend: no code requests `/api/credentials` (none ever did), so there
was no list to add the line to. `attachments.build_credential_attachment_map` lets `StorageReadError` out
rather than return a map missing credentials, which a hint check would read as "no attachment recorded".
**On 383f4a15**: 26 of 32 storage tests fail (`readkey` returns the stale legacy copy or `[]` instead of
raising, `iter_credentials` skips an unreadable entry, a failed listing lists the rest); with the real store,
one user's unreadable file gives `200` and the other user's credentials alone, `downloadcred` gives 404,
`DELETE` reports `removed: 1` and leaves the undecodable user.

**Step 3, legacy records cannot be resurrected.** A save from a legacy read holds "there is no current copy"
as its version; a delete that removed the legacy copy (and any current copy) made that true again. `delkey`
now empties the current copy instead of removing it whenever any copy existed, and removes every legacy
copy, locally under the current copy's lock. That also closes the case where another save made the
current copy and dropped the session `.pkl`, so the delete found no legacy copy at all. A deleted user is
not listed (an emptied copy holds no records). Race test in the style of `test_registration_race.py`, local
and fake GCS: a real registration held after its read while a real `/api/deletepub` runs. **On 383f4a15**
the deleted credential comes back beside the new one on both backends, and the save after
"save, discard `.pkl`, delete" returns `True`.

**Step 4, artifacts.** A merge whose conditional upload raised re-reads the record and reports success only
if it holds every merged value (**on 383f4a15**: `False` for a write that landed). Local artifacts live under
`<artifact dir>/<session>/`, as on GCS; the old flat files are not read -- local development data only. **On
383f4a15** session B loads, overwrites and deletes session A's artifact by its id. **Deviation:** the
characterization harness records the paths of files a request writes, so this regenerated nine route
goldens; the diff is 17 `stored[].file` values, `artifacts/<sha>.json` -> `artifacts/<session>/<sha>.json`,
contents identical (checked field by field). It is its own commit (2e1e3f44).

**Step 5, SCTs as data.** Each SCT is its version, log ID (hex), timestamp (ISO 8601 UTC, milliseconds), entry
type, signature hash and signature algorithm. The harness's memory-address scrub is gone. Only
`golden/certificates.json` was regenerated; its diff is two fields of `safetynet-0`, the SCT extension's
`value` and the SCT lines of `summary`.

**Step 6, one source for algorithm names.** The three helpers in `mds_snapshot.py` spell X.509 signature
algorithms from OIDs; `describe_algorithm` and `cose_tables` name COSE algorithm identifiers, which the MDS
entry does not carry, and `cose_tables` imports Flask through the decoder package. The spellings moved to
`webauthn/signature_algorithms.py`, a Flask-free leaf that `certificate_names` and `mds_snapshot` both use
(`certificate_names` itself cannot be imported without Flask, and from `mds_snapshot` not at all: circular).
The copy had drifted: **on 383f4a15** an Ed25519- or Ed448-signed root raises `AttributeError` in the MDS
summary; now `ED25519_SHA512` / `ED448_SHAKE256`, as in the certificate view. New: a fresh-interpreter test that
`tools.update_mds_snapshot` imports no `flask` module. The existing in-process check cannot see it: with a
probe `import flask` added to `mds_snapshot`, it still passed and the new test failed.

**Step 7, tests do not write into the checkout.** `tests/conftest.py` fails the run when anything under
`server/runtime/`, `instance/` or the MDS snapshot files was created, changed or removed, comparing listings;
it deletes nothing. The leaks: `test_advanced_registration_reports_a_replayed_challenge` (a session directory
per run) and `test_prune_helper_and_request_session_identifier_paths` (refreshed `cookie-session`'s marker);
the security `simple_storage` / `advanced_storage` fixtures and that test now use `tmp_path`. Three fixtures
(17 tests) that also patched `config.SESSION_METADATA_DIR`, which nothing reads, dropped it. Worse than
writes: the suite **deleted** session directories in the checkout -- a cleanup thread removes sessions
inactive for 14 days from whatever directory it lists, and can outlive the test that started it. A stale
probe directory planted in a worktree was removed by the 383f4a15 suite; `tests/app/conftest.py` now points
the session-metadata store at the run's own directory for the whole session, and three runs later the probe
was intact. **On 383f4a15** the guard fails the run: 4 entries created, the stale probe removed. During this
phase, before the guard, the suite removed 101 of the 102 pre-existing directories in
`server/runtime/session-metadata/` (each held only an empty `.last-access` marker; names such as
`victim-namespace` are test fixtures) and my runs added 21; neither was undone, per the brief.

**Tests.** macOS 2480 -> **2556** passed / 4 skipped; Linux (python:3.14, Docker) 2466 -> **2542** / 5;
`tests/app/security/` 105 -> **120**; vitest 293 -> 293; ruff clean; coverage 96.45% -> **96.49%**; vitest
coverage unchanged. Functions over 80 lines still 14 (`authenticate_complete` 191 -> 137); modules over 700
**3 -> 2**.

**Found but not fixed:**
- Both certificate views spell RSA-PSS `RSASSA-PKCS1-v1_5`: cryptography names the OID `rsassaPss`, which the
  `"rsassa-pss"` test misses. Fixing it changes certificate goldens.
- Credential artifacts still read a GCS download error as "no artifact" (`_read_record`), and a non-merge store
  then overwrites; step 2 covered the credential store only.
- Registration answers 500, not 503, when the store cannot be read (authentication and the list say 503).
- `build_credential_attachment_map` has had no caller since 73afe6ac (2025-09-26).
- A GCS listing lists every object under `user-data/`, every session's, to find the flat legacy copies.
- The guard does not cover the legacy stores in the source tree (`server/app/session-credentials/`,
  `server/app/*_credential_data.pkl`); `test_storage_local_contracts.py` reads the former unredirected.

**Phase 19 — tech-lead verification (2026-09-24):**
- macOS 2556 passed / 4 skipped, coverage 96%, vitest 293, ruff clean, `tests/app/security/` 120.
  **Linux (python:3.14 in Docker, run independently) 2542 passed / 5 skipped.**
- **Every one of the 11 commits passes pytest on its own.** The two commits between 383f4a15 and the
  phase (`231f6f99`, `ed279cdc`) are the tech lead's; the agent named them rather than claiming them.
- The new tests, copied onto the pre-phase tree, fail there for the stated reasons: a credential stored
  at counter 10 authenticates at 5 (`200 OK`) when the store read fails; a deleted credential comes back
  beside a racing registration's (local and fake GCS).
- The checkout guard works: a full run left `server/runtime/session-metadata/` at the same 22 entries.
- `2e1e3f44` regenerated route goldens against the brief's rule; the diff is exactly 17 artifact paths
  (`artifacts/<sha>.json` -> `artifacts/<session>/<sha>.json`) and nothing else. Accepted: per-session
  scoping changes those paths by design. The session folder is a validated name under a contained path.
- `GET /api/credentials` changed from a bare list to `{"credentials": [...]}`; nothing in the frontend,
  docs or tools reads it.
- Not new: the simple flow takes `email` from the complete request's query string, so a client can point
  the counter check at a user with no record. That is the Phase 1 known limitation (server records keyed
  by browser namespace, client-supplied public keys), not a regression.

### Phase 20 — the codec reports what it read and rebuilds what it showed; Phase 19 leftovers — DONE (2026-09-24)
64 commits, 7e805ba8..the record's own, all this phase's, each gated on pytest, vitest and ruff exit codes.
The first 39 were re-run afterwards on their own trees in fresh worktrees (all pass; vitest too for the three
frontend commits); the 23 fixes after the review were each gated on main as they were committed. New tests
were run on 7e805ba8 (or on the commit before their fix), adapted only for new import names, and fail there.

**Part B.** B6: the checkout guard covers `server/app/session-credentials/`, `server/app/*_credential_data.pkl`
and `.hypothesis/`; the fixture that read the legacy store unredirected is redirected. B4: the attachment map
and `extract_credential_data` are gone. B3: simple registration answers 503 when the store cannot be read or
does not decode (golden `simple-register-store-unwritable`: 500 -> 503). B2: credential artifacts keep the
three cases on both backends; a merge over a record it cannot read or decode refuses (503). B5: the legacy
GCS pass lists `user-data/` with the `/` delimiter; S1: sessions are listed as prefixes. B1: RSA-PSS is spelled
`RSASSA-PSS_<hash from the PSS parameters>`; ML-DSA and SHA3 by name too (goldens `certificates`,
`certificate-helpers`; new RSA-PSS, ECDSA-SHA3 and RSA-SHA3 certificates in the material).

**Part A.** `data.edn` is the item in EDN beside `decodedValue`, self-checked; the encoder's EDN input writes
exactly the bytes a text notates (`decoder/edn/`, heads from `decoder/cbor_head.py`). Hypothesis proves
decode -> EDN -> encode over generated items (3000 examples at the module, 1000 through the API, on Python
3.14 and 3.12) and a corpus of 412 items (every CBOR input in tests, fixtures and golden records; 404 read as
CBOR with EDN, 3 as CBOR after a CTAP byte, 5 as lone CTAP bytes). Keys are equal by RFC 8949 section 5.6.1;
`duplicate-map-key` carries every earlier entry; `duplicate-json-key` names path, kept and dropped. The
encoder never reads a plain map as CTAP; typed key spellings are read only by `keys.read_json_key`; CTAP
response views show every key and `ctap-non-integer-key`; `malformed` holds only form findings; the UI shows
EDN in a collapsible section and keys as the decoder wrote them. 0x41 before one byte that is not CBOR is
read from the first byte (`41ab` is h'ab'). Golden `decoder-attestation-objects` gains `edn` (8 bodies).

**Review and fixes.** A six-dimension adversarial review with a skeptic per finding confirmed 23 defects,
fixed in 23 commits: the EDN reader accepted `(_ 1)`, crashed on deep nesting and hex-float overflow,
counted offsets from stripped text, accepted `-0(1)`; `spell` wrote exact-looking EDN for unmarked lenient
damage; a duplicate key's message quoted authData-relative offsets; duplicates inside dropped values
claimed a kept value; the encoder respelled the keys it echoed and could not take its own output back;
`NaN_2` and `invalid(...)` keys were written as text; non-object client data and a non-scalar COSE `kty`
answered 500; and pre-existing: registration deleted an undecodable legacy `.pkl` unread.

**Tests.** macOS 2556 -> **3912** passed / 4 skipped; Linux (python:3.14, Docker) 2542 -> **3898** / 5;
`tests/app/security/` 120 -> **126**; vitest 293 -> **301**; ruff clean; coverage 96.49% -> **96.59%**; vitest
coverage unchanged (82.58 / 66.44 / 91.33 / 82.69). Modules over 700 lines 2 -> **0**.

**Found but not fixed:**
- Tests write `instance/session-secret.key` into a fresh checkout: the `tests/app/conftest.py` `_app()` helper
  builds the entry-point app without a secret, and the guard lists after collection, when
  `test_security_headers.py` has already written it. A subset run in a fresh worktree fails the guard.
- The CTAP decode -> encode loop still guesses inside nested maps (attStmt `ver` "14574037" becomes bytes,
  a null user `icon` is dropped, nested integer keys become text); a bare response map comes back with a
  `00` status byte; `ctap.trailingBytesHex` is dropped; `expandedJson` invents `{"sig": ...}`/`{"value": [...]}`.
- The SafetyNet JWS header and payload are read with `json.loads`: a repeated key is not reported.
- JSON NaN is emitted as invalid JSON; getInfo's label style differs from the typed spelling.
- `signature_algorithms` still spells the names `RSA-PSS` and composite/HashML-DSA names wrongly and leaves
  DSA-with-SHA384/512 and DSA-with-SHA3 as dotted OIDs (no caller passes them; unchanged from before).
- Lenient decoding: a byte-string key with a skipped chunk still merges with the bytes it lost.
- `delete_credential_artifact` and `_user_root_prefix` are reached only by tests; no scenario covers a failed
  write after a successful read in registration.

**Phase 20 — tech-lead verification (2026-09-24):**
- macOS 3912 passed / 4 skipped in about 29 s, coverage 96.6%, vitest 301, ruff clean, `tests/app/security/` 126.
  **Linux (python:3.14 in Docker, run independently) 3898 passed / 5 skipped.**
- **Every one of the 64 commits passes pytest on its own**, all run in a worktree (the agent re-ran 39).
- **Independent round trip.** My own CBOR generator, written apart from `tests/app/cbor_items.py`,
  through the real API (decode, take `data.edn`, encode as EDN, compare): **4481 of 4481 exact** over three
  seeds, covering about 16,000 wide heads, 10,000 tags, 3,000 duplicate keys, 1,000 zero-chunk strings and
  5,700 raw-bit floats (NaN payloads, subnormals, infinities).
- The four behaviours are as reported. Every EDN refusal I tried is a 422 with the offset in the text as sent
  (with leading spaces too), never a 500; 1000-deep nesting stops at depth 65.
- On the nine fixed payloads the only change is the new `data.edn` on the five CBOR readings; findings and
  values are identical to 7e805ba8.
- Goldens: the spelling fixes change only spelling fields (an RSA-PSS certificate was shown as
  RSASSA-PKCS1-v1_5, ML-DSA certificates as "DSA"); `6f5aec50` changes only `edn`, the body hashes and
  lengths; simple registration's unreadable store went 500 -> 503.
- The Hypothesis profile is derandomized with no deadline and no database, so it cannot flake the Cloud Build
  gate; the runtime image is built `--no-dev`, so Hypothesis stays out of production; no `.hypothesis/`
  appeared in the checkout.
- The decoder UI shows both key-collision and duplicate-key findings and the EDN section
  (`{1: "a", "1": "b", 1: "c"}`), served from an export of `main`.
- Found, all older than this phase, queued for Phase 21: a 37-byte input that is one well-formed CBOR item is
  read as authenticator data with no finding naming the CBOR reading; JSON *input* containing NaN or Infinity
  is echoed back bare, so the response is not valid JSON; the app sets no `MAX_CONTENT_LENGTH` (the EDN encoder
  took a 400 KB input).

### Local development
Tests previously ran against the global interpreter, whose packages matched nothing in
`requirements.txt` (cryptography 44.0.3, fido2 2.1.1, gunicorn 23). A project venv now exists:
`.venv` (gitignored), built from `requirements.txt`. Run tests with
`.venv/bin/python -m pytest -q`. It currently carries `cryptography` 50.0.1 (see C1).

### Follow-ups raised during batch 1
- `routes/general.py:494` `downloadcred` still serves `pickle.dumps(credentials)` as a `.pkl`
  download — the mirror image of S10; anything that loads it gets code execution.
- A traversal `?email=` now raises `ValueError` in storage → HTTP 500. Map to 400 in routes. **Done in Phase 17.**
- `session_metadata_store.py` builds paths via the same shared prefix helpers; not yet contained.
- `storage.py` `convert_bytes_for_json` emits standard base64 while storage uses base64url.
  Unifying needs a paired frontend change: `binary.js` decodes it with bare `atob()`.
- CSP ships with `script-src 'self' 'unsafe-inline'` — **not strict**. Blockers: 125 inline
  `on*=` handlers in templates, the inline bootstrap `<script>` in `index.html`, 5 inline
  `style=` attributes. `test_csp_script_src_is_documented_as_not_strict` fails once they are gone.
- `_schedule_session_cookie` still sets `SameSite=None` on the metadata cookie over HTTPS.
- `fido2/server.py:438` eagerly f-string-logs every authenticated credential ID.
- A custom `FIDO_SERVER_CREDENTIAL_DIR` inside the repo is not gitignored.

---

## P0 — Security. Ship before anything else.

The repository currently accepts forged WebAuthn registrations. Restructuring a
system that does that would be the wrong order of work.

### S1. `__session_state` challenge bypass — CRITICAL, PoC-confirmed
Every `/begin` returns the server state (containing the challenge) to the client;
every `/complete` accepts it back when the Flask session is empty. The server ends up
comparing the client's challenge against the client's own value.

A cold POST to `/api/register/complete` — no session cookie, no prior `/begin`,
attacker-chosen challenge — returns `HTTP 200 {"status":"OK"}`.

Sites: `simple_parts/register_begin_impl.py:39`, `simple_parts/register_complete_impl.py:44-51`,
`simple_parts/authenticate_impl.py:35,50-52`, `advanced_parts/register_begin_impl.py:175`,
`advanced_parts/register_complete_state_impl.py:17-21`,
`advanced_parts/authenticate_begin_impl.py:241`, `advanced_parts/authenticate_complete_impl.py:122-126`.

**Design:** simple flow strict (remove entirely). Advanced flow keeps the capability
— it is a request editor and legitimately needs client-supplied challenges — but must
stamp `challengeSource: "server-session" | "client-supplied"` on every response.
Permissive is acceptable; dishonest is not.

### S2. Custom-algorithm signature bypass — CRITICAL
`advanced_parts/authenticate_complete_impl.py:178-208`. On verification failure the
handler substring-matches the error for `("signature","algorithm","unsupported","verify")`
and, if the client-declared algorithm is outside the known-name map, returns `status: OK`.
It logs its own behavior: *"Accepting assertion ... without signature verification."*

`stored_alg_value` comes from `entry.get("algorithm")` (`parsing_helpers_impl.py:109-110`),
a field independent of the COSE key's own label `3` — so a real ML-DSA key plus
`"algorithm": -12345` reaches it. **Delete the branch.**

### S3. RP ID / origin from attacker-controlled input — CRITICAL
`config.py:303-326` derives RP ID from the `Host` header; `register_complete_state_impl.py:46-53`
and `authenticate_complete_impl.py:149-156` further fall back to the request body.
No origin allowlist exists. Add `FIDO_SERVER_ALLOWED_ORIGINS`; keep Host-derivation
as a dev-only fallback with a startup warning.

### S4. Stored XSS in credential UI — CRITICAL, confirmed
`credential-display/list-render.js:234` interpolates `cred.userName` unescaped into
`innerHTML` (line 249) while lines 196/223/232 of the *same literal* call `escapeHtml`.
Same bug at `credential-detail-runtime/sections-main.js:43-44`. Value flows from the
server response and the advanced tab's editable `publicKey.user.name`, persists to
localStorage, replays on every page load.

Further sinks: `sections-main.js:29,31,33,71,84,85,98,121,133`;
`mds/status-controls.js:25,37` (raw `error.message`); and
`registration-result.js:76-78`, which persists *composed HTML* into localStorage —
`snapshot-sanitize.js:206-217` passes it through with only `truncateString`.

### S4-followup. Latent remote-HTML sink and deferred snapshot refactor
Raised during the S4 fix; **not** regressions, but tracked so they are not lost.

1. **Cross-layer safety dependency (do next).**
   `credential-detail-runtime/snapshot-context.js:25-30` accepts
   `registrationDetailHtml` / `registration_detail_html` /
   `registrationDetailCombinedHtml` / `registration_detail_combined_html` as **raw HTML**
   into `modalBody.innerHTML`. Nothing produces them today only because a Python strip-list
   at `routes/advanced_parts/constants.py:82-87` removes them — but
   `advanced/credentials/index.js:110-140` `hydrateCredentialFromServer` copies **every**
   key from the server artifact onto `cred`. The safety property lives in a different
   language and layer from the code that depends on it, with no test linking the two.
   One strip-list edit makes this a live remote-HTML sink. Fix on the **frontend** side
   (stop accepting raw HTML keys) so the invariant is local.

2. **Snapshot stores composed HTML — deferred, needs a schema change.**
   `registration-result.js:72-78` persists rendered HTML to localStorage. Every
   interpolation currently passes through `escapeHtml`, so it is inert today and a
   regression test now locks that. Storing structured data instead requires extending the
   snapshot schema with new sanitised fields plus a node-based renderer, because
   `snapshot-sanitize.js:134-189` and `shared/storage/local/constants.js` strip the
   underlying data — the composed HTML is currently the only retained record of three
   rendered sections. Design change, not an edit.

3. `snapshot-sanitize.js:206-217` truncates stored HTML with `slice(0, 120000)`, which can
   cut a tag or entity in half. Not an XSS vector; can yield malformed markup.

4. **125 inline `on*=` handlers remain, now all in `frontend/templates/*.html`** — zero
   remain in `frontend/static/scripts`. Clearing the templates is the remaining
   prerequisite for a CSP without `'unsafe-inline'` (Q3/S7).

### S5. Advisory checks never gate — MAJOR
`attestation_parts/checks_*.py` compute `origin_mismatch`, `algorithm_not_allowed`,
`attestation_signature_invalid`, `cose_key_error` into `results["errors"]` — which no
caller reads (`advanced_parts/register_complete_impl.py:84-88`,
`simple_parts/register_complete_impl.py:111-115`). Failures return HTTP 200.

Related: `expected_origin = request.headers.get("Origin")` (`register_complete_impl.py:74`,
`simple_parts/register_complete_impl.py:82`) is self-referential — the attacker sets
both the header and `clientDataJSON.origin`.

### S6. PQC attestation error laundering — MAJOR
`checks_attestation_runtime.py:37-48`: on failure a PQC fallback re-runs a bare signature
check and on success sets `signature_valid = True` **and clears `attestation_errors = []`**
(line 46). The fallback skips the packed-attestation cert policy (Subject OU, AAGUID
extension match, Basic Constraints). Never clear errors; report `pqcSignatureValid` separately.

### S7. Transport-layer hardening — MAJOR
No CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, or
Permissions-Policy on any response. `SESSION_COOKIE_SECURE` never set;
`PERMANENT_SESSION_LIFETIME` 31 days. Needs `ProxyFix` for Cloud Run's TLS-terminating proxy.
Note: a real CSP is blocked until the 145 inline `on*=` handlers are removed (see Q3).

### S8. Unconditional secret-adjacent logging — MAJOR
`fido2/cose.py:761-785` `_log_signature_debug` `print()`s authenticatorData,
clientDataJSON (contains the challenge), signature and public key on **every** ML-DSA
verification (`:903,946,988`), mirrored at `fido2/server.py:432-436`. No flag, no logger.

### S9. Metadata session IDOR — MAJOR
`metadata_parts/session_identity_runtime.py:57-63` accepts the `fido.mds.session` cookie
verbatim as the session id. Path traversal is blocked; namespace isolation is not.

### S11. signCount regression and challenge replay are absent from the PRODUCT — MAJOR
Not merely untested. `grep` for any comparison of `signCount` against a stored value across
`server/` and `fido2/` returns nothing; it is parsed and echoed into responses
(`simple_parts/authenticate_impl.py:97-124`) but never validated. Cloned-authenticator
detection (WebAuthn L3 §7.2 step 21) does not exist. The words "replay", "already used" and
"challenge reuse" appear nowhere in `server/`, `fido2/` or `tests/`.

### S10. Path traversal + pickle deserialization in credential storage — CRITICAL
Found by the tech lead after the audits; **no audit agent surfaced this**.

`storage.py:156` builds the path as `os.path.join(directory, f"{name.strip()}_credential_data.pkl")`
with **no separator or `..` sanitization**. `name` is `request.args.get("email")`
(`simple_parts/register_complete_impl.py:16`, `simple_parts/authenticate_impl.py:7`,
`general.py:485`). Verified: `?email=../../../../../../private/tmp/X` resolves outside the
repository root.

The stored format is `pickle` (`storage.py:171` `pickle.dumps`, `:214` and `:295`
`pickle.loads`). So the chain is:
- **arbitrary file write** via `savekey` (`register_complete_context_b_impl.py:79`)
- **arbitrary file delete** via `delkey` (`general.py:479`, `credentials_route_impl.py:18`)
- **arbitrary file read into `pickle.loads`** via the authenticate path → code execution
  if an attacker can land crafted bytes at any reachable path (e.g. via the custom-metadata
  upload endpoint) and then traverse to it

Reachable **unauthenticated** — S1 already proved `/api/register/complete` needs no session.

Fix: reject any `name` containing a path separator, `..`, or a null byte; resolve and assert
the final path stays under the credential root (the codebase already imports
`werkzeug.security.safe_join` in `static_assets.py` — use it). Separately, **replace pickle
with JSON**; pickle is not a safe format for data that crosses a trust boundary, and the
stored value is a plain list of credential records.

Also relocate the store: `storage.py:45` writes into `basepath` = `server/app/`, i.e. the
**source tree**. It belongs under `instance/`.

---

## P1 — Crypto modernization. The highest-leverage change in the repo.

### C1. Migrate ML-DSA from liboqs to `cryptography` >= 50
`cryptography` 50.0.1 ships native ML-DSA-44/65/87: `MLDSA{44,65,87}PublicKey`
with `from_public_bytes()`/`verify()`, ML-DSA OIDs in both `SignatureAlgorithmOID`
and `PublicKeyAlgorithmOID`, and ML-DSA in `PublicKeyTypes` (so `load_der_public_key()`
and `cert.public_key()` handle it natively).

The blocker is one constraint: `cryptography>=2.6,<45` in `requirements.txt:3` and
`pyproject.toml:33`, inherited from upstream Yubico python-fido2 1.x and never revisited.

Lifting it deletes, in one move:
- `prebuilt_liboqs/` — a committed 13MB binary blob, `liboqs.so.0.14.1-dev` (a *dev*
  build, untagged, no checksum/SBOM/provenance), **linux-x86_64 only**
- the `liboqs_python-0.14.0` wheel
- `LD_PRELOAD=/opt/liboqs/lib/liboqs.so` in the Docker CMD, plus the `ldconfig` +
  symlink + `LD_LIBRARY_PATH` layers — four overlapping mechanisms for one library load
- **~670 lines of hand-rolled DER/ASN.1 parsing** at `fido2/cose.py:56-726`
  (`_parse_der_length`, `_decode_der_oid`, `_parse_spki_algorithm_info`, and
  `_scan_certificate_for_subject_public_key_info`, which *heuristically scans* a
  certificate for anything the right length). Origin: commit `09ae779 "Bypass x509 for
  MLDSA metadata and attestation"` — it exists only because cryptography 44 lacked the OIDs.
- the `SystemExit`-catching import guards at `pqc.py:27`, `cose.py:49`, `base.py:156`,
  which defend against `oqs/oqs.py:225` running `subprocess.call(shell=True)` to
  **git-clone and CMake-build liboqs from the internet** on import

And it unlocks:
- **PQC that works on macOS/ARM.** Today `import oqs` fails outside the x86-64
  container, so `detect_available_pqc_algorithms()` returns an empty set locally.
- **PQC that can be tested in CI at all** (see T1).

**Verified 2026-09-16 on the tech lead's machine (macOS arm64, Python 3.14):**
- The **entire current suite passes on `cryptography` 50.0.1 with zero code changes**
  (1623/1623). The `<45` cap was never load-bearing.
- Native ML-DSA-44/65/87: generate, sign, verify; a one-bit-flipped signature raises
  `InvalidSignature`; a truncated public key raises `ValueError` (liboqs zero-padded it);
  SPKI DER round-trips via `load_der_public_key`; and `x509.CertificateBuilder().sign(sk, None)`
  produces ML-DSA-signed certificates — so real packed-attestation tests are possible.
- API detail: `from_public_bytes` lives on the public ABC (`mldsa.MLDSA44PublicKey`), **not** on
  the Rust-backed concrete type that `type(public_key)` returns.

### C2. Un-fork the library — ML-DSA as a plugin, not a 13,611-line fork
The vendored `fido2/` is python-fido2 **v1.2.1-dev.0** and it *shadows* the pip-installed
`fido2` 2.2.1 on import, making the `requirements.txt` pin dead weight. Upstream has no
ML-DSA, so the fork cannot simply be deleted — but upstream's `CoseKey.for_alg()`
resolves via recursive `__subclasses__()`, so **ML-DSA can be a small plugin package
registering `CoseKey` subclasses**. Target: depend on upstream fido2, ship ~150 lines
of ML-DSA COSE keys, delete the fork.

Sequencing: C1 first (it removes most of the fork's delta), then C2.

### C3. Error taxonomy
ML-DSA failure raises `ValueError`, not `cryptography.exceptions.InvalidSignature`, so
`packed.py:150` never catches it and `@catch_builtins` relabels a **forged signature**
as `InvalidData`. Fail-closed today, but any future `except InvalidData: warn` becomes a hole.

### C4. liboqs `details` keys are dead
`attestation_parts/certificate_public_key_leaf.py:51,54,87,90` reads hyphenated keys
(`"claimed-nist-level"`, `"length-signature"`) that do not exist in liboqs-python 0.14.0,
which uses underscored ones. Every lookup returns `None`, so the PQC certificate panel
silently omits NIST level, key size and mechanism name. `fido2/cose.py:417-418` uses the
correct spelling — the two modules disagree. Moot if C1 lands; fix now if C1 slips.

### C5. ML-DSA signature lengths are pre-standard Dilithium sizes — display bug
`fido2/cose.py:389-391` lists signature lengths `2420 / 3293 / 4595`. FIPS 204 final is
**`2420 / 3309 / 4627`** (verified against `cryptography` output). 3293 and 4595 are
CRYSTALS-Dilithium Round 3 sizes; FIPS 204 widened the challenge seed to 48 and 64 bytes for
the higher levels, adding exactly 16 and 32 bytes. Display-only: `signature_length` feeds
`ml_dsa_parameter_details` in the certificate panel and is never enforced.

Compounding it, `_get_mldsa_parameter_details` claims to consult oqs, but uses
`details.setdefault(...)` (`:420-421`), which never overwrites the hardcoded default — so even
correct oqs values are unreachable. `tests/fido2/cose/test_cose_additional_branch_contracts.py:71,85,153`
assert the wrong values. Moot once C1 lands; the replacement must use FIPS 204 constants.

---

## P2 — Structural. Blocked on P2.0.

### P2.0. Undo the globals-injection machinery — MUST precede any file moves
`attestation.py:132-156`, `metadata.py:105` and `decoder/decode.py:284` rebuild every
split function with the *parent's* globals:
`types.FunctionType(func.__code__, globals(), ...)`.

Consequences, verified by execution:
- `metadata_parts/env_runtime.py` imports **only** `from __future__ import annotations`,
  yet its functions use `os`, `app`, `timedelta`. Calling one directly:
  `NameError: name '_SESSION_METADATA_CLEANUP_ASYNC_ENV' is not defined`.
- **163 cross-module calls** whose callee lives in a sibling that is never imported
  (decode_parts 90, attestation_parts 55, metadata_parts 18).
- 7 modules carried `# pyright: reportUndefinedVariable=false` (all removed since) as a self-admission.
- Routes use a parallel hack: 33 one-line forwarders passing `sys.modules[__name__]`
  back into their own fragments — **539 references** to `advanced_module`/`simple_module`.

No type checker, IDE or linter can see any of this. Until it is reversed, no tool can
tell you what a file move broke.

### P2.1. The split was mechanical, not semantic — DONE, re-merged
Measured before the re-merge:
- **33 of 90 parts modules had exactly one importer. Zero were imported by any test.**
- **All were ≤400 LOC (max 401)** while 5 *unsplit* server files exceeded 400 (up to
  `config.py` at 1005). The ceiling applied only to files that were split — a line
  budget, not a design.
- 23 commits titled `refactor: split …` over 2026-04-08→10.
- 15,752 of 22,770 server LOC lived in `*_parts/`; 866 façade LOC was pure plumbing.
- Suffixes that named a mechanism rather than a responsibility: 28 `_runtime`, 28
  `_impl`, 10 `_leaf` files, plus 62 functions.

After: the six `*_parts/` packages are gone. Each façade became its package's
`__init__.py` and the fragments were merged along responsibility lines. `server/`
went from **126 to 76 `.py` files**; no file, function or fixture carries a
`_runtime`/`_impl`/`_leaf` suffix except the six noted in P2.6.

Kept separate on purpose: `decoder/encode/` (all 9 submodules — already named for
responsibilities), `webauthn/metadata/state.py` (shared mutable caches and locks;
it is a deliberate leaf), `webauthn/attestation/formatting.py` and `constants.py`,
`decoder/decode/{binary,keys}.py`, `routes/binary_helpers.py`, and `encoding.py`.

### P2.2. `config.py` is a god module (563 LOC, 13 concerns)
Flask app singleton + session-secret persistence + embedded PEM trust anchors + RP-ID
resolution + gzip middleware + path discovery. **Importing it writes a file to disk**
(`_resolve_secret_key()` at line 148). It carries a re-import guard so `importlib.reload`
works, because tests reload it. `tests/conftest.py` has **no app fixture**; 146
`test_client` calls reach for the global. `pqc.py` imports the web framework solely for
`app.logger`. Extract `create_app()`.

### P2.3. Container layout — 1 line, removes 3 hacks
`Dockerfile:62` `COPY server/app /app/server` collapses a directory level, so `server.app`
means a package in a checkout and a module in the image. Fix to `COPY server /app/server`,
which deletes the `gunicorn.conf.py:23-26` dual-import fallback, the
`server/app/__init__.py:9-20` `__getattr__` shim, and the `fido2`-directory probe at
`app.py:13-24`. Already caused commit `4491f6a`.

### P2.4. Layout — as shipped
```
server/app/
  encoding.py            THE base64url/hex module (42 importers)
  config.py app.py startup.py static_assets.py env_flags.py
  challenge_registry.py attachments.py device_logs.py github_client.py
  credential_artifacts.py mds_snapshot.py mds_provisioning.py
  webauthn/
    pqc.py               ML-DSA adapter
    sign_count.py        WebAuthn L3 §7.2 step 21
    attestation/         __init__ (public surface) + certificates, checks, trust,
                         pqc, classical, aaguid, formatting, constants
    metadata/            __init__ + blob, effective, entries, sessions, uploads, state
  decoder/
    decode/              __init__ + cbor_parser, ctap, pipeline, response,
                         summary, certificates, binary, keys
    encode/              __init__ + the 9 encoder submodules, unchanged
  routes/
    simple/              __init__ (Flask rules) + registration, authentication,
                         credential_list, parsing, binary
    advanced/            __init__ (Flask rules) + registration, authentication,
                         artifacts, algorithms, parsing, summary, tracing,
                         constants, binary
    general.py binary_helpers.py
  storage/               credentials, session_metadata, cloud, common
```
Still open from the original sketch: splitting `config.py` (1005 LOC) into a
`config/` package and extracting `create_app()` into `wsgi.py`. Both are *splits*,
not merges, and `create_app()` changes behaviour, so neither was in scope here.

### P2.6. Suffixes that are load-bearing and stayed
Six functions keep `_impl` because it distinguishes a parameterised implementation
from its same-named bound wrapper, and dropping it collides:
`decoder/decode/certificates.py` (`_convert_certificate_payload_impl`,
`_convert_certificate_bytes_impl`, `_convert_certificate_chain_impl`,
`_convert_attestation_statement_impl`, `_convert_attestation_entry_impl`) and
`decoder/decode/cbor_parser.py` (`_decode_cbor_sequence_impl`). Resolving the clash
would mean restructuring the injection, which is a behaviour change.
`webauthn/attestation/trust.py:_extract_attestation_leaf` merely ends in the word
"leaf" — a leaf certificate — and is not a suffix at all.

### P2.5. Dead code — NOT this repo's problem
Python: ~2 LOC prod-dead. JS: 31 unused exports, ~754 LOC. Commented-out code:
effectively zero. Unreachable branches: zero. The problem is fragmentation and
duplication, not accumulation.

---

## P3 — Codec. The tool's defining job, currently unperformed.

A CTAP developer tool exists to tell you whether bytes on the wire are spec-legal.
This one answers `success: true` for **plain English prose**.

### D1. Canonicity is enforced nowhere — CRITICAL
All verified through `decode_payload_text`, each returning `success: true, malformed: []`:
non-minimal int length; map keys out of CTAP2 order; **duplicate map key (entry silently
lost)**; indefinite-length (forbidden by CTAP2); bytestring declaring 8 bytes with 2
present; array declaring 10 with 1; reserved additional-info 30. Despite its name,
`cbor_strict.py` is the most permissive parser in the repo.

### D2. The 4-decoder fallback cascade destroys validation — CRITICAL
`cbor_sequence.py:23-52` tries 4 decoders in order, taking the first that doesn't throw.
Decoder 4 (`cbor_lenient.py`) **never throws** — 200/200 random blobs "decoded". Only
level 4 sets a marker; a 1→2 fallback is invisible.

### D3. `fido2/cbor.py:166` silently corrupts major type 7 — CRITICAL
All of major type 7 maps to `load_bool` (`return ai == 21`): `null` → `False`,
`undefined` → `False`, any float → `False` **consuming zero payload bytes** → stream
desync. No exception, so the cascade never falls through. This is decoder #1, tried first.

### D4. "Repair" silently fabricates data — CRITICAL
Zero repair markers reach the response. `ctap_repair_make.py:77` fabricates `alg = -7`;
`:115,169` fabricate `alg = -50` (ML-DSA-87) for unidentifiable input. `:205-255` takes
**trailing garbage** and injects it as an attestation signature, then returns `b""` as
the remainder — **suppressing the "Trailing N bytes" warning**, the one honest diagnostic.
`:21` pattern-matches the literal magic string `"al&"`. Verified: authData with AT clear
but attested data present → **127 of 164 bytes dropped**, `malformed: []`.

### D5. Wrong COSE algorithm labels — CRITICAL, one-line fix
`decode_parts/binary_extract.py:13-15` has `-35: ES256K, -36: ES384, -37: ES512`.
Correct: `-35: ES384, -36: ES512, -37: PS256`; ES256K is `-47`. **Every P-384, P-521 and
RSA-PSS credential is displayed with the wrong algorithm name.** The repo's own
`pqc.py::describe_algorithm` is correct — delete the table and call it. Net line removal.

### D6. Base64 accepts arbitrary text — CRITICAL
`pipeline_runtime.py:239-242` calls `urlsafe_b64decode` without `validate=True`; Python
silently discards non-alphabet characters. `"Hello, this is plain text!"` → accepted as
base64url → `{"success": true, "type": "CBOR"}`. Same class of bug on the credential-ID
intake path (`advanced_parts/binary_helpers_impl.py:21-30`,
`simple_parts/binary_helpers_impl.py:53-61`) and at `routes/general.py:454-460`, where a
base64url cert decodes *successfully but wrong* (36 bytes for a 39-byte cert).

### D7. Two incompatible "canonical" orderings — MAJOR
`fido2/cbor.py:77-79` sorts major-type-first (CTAP2-correct);
`encode_parts/cbor_canonical.py:118` sorts length-first (RFC 7049). Verified divergence
on `{24: 0, "": 0}`. The encoder's output is not CTAP2-canonical.

### D8. Feature gaps — MAJOR
No ML-DSA in the decoder (`-48/-49/-50` render as bare strings; COSE kty 7 unhandled) —
squarely at odds with the project's name. CTAP2 command table has **2 entries**, status
table **1**, no error table (`fido2/ctap.py:111-171` has all ~45, unused).
`authenticatorGetInfo` entirely unsupported. **Two fabricated CTAP field labels** that
the encoder will *emit*, producing CBOR no authenticator accepts: `11: "largeBlobKey"`
in makeCredential (0x0B is `attestationFormatsPreference` in CTAP 2.2) and
`8: "largeBlobKey"` in getAssertion (**0x08 does not exist**). Extensions: only
`credProtect`. Attestation formats: no dispatch on `fmt` at all.

### D9. Highest-value single feature
A canonicity validator that runs on every decode and **reports** (not rejects):
non-minimal lengths, key order, duplicate keys, indefinite-length, reserved
additional-info, trailing bytes. This is the subsystem's largest gap.

---

## P4 — Tests. Better than feared, with one precisely shaped blind spot.

**Correction to an earlier hypothesis of mine:** I inferred from "1412 tests in 4 seconds"
that the suite must be shallow. A mutation campaign (150 mutants sabotaging real security
checks) disproved that. The suite is fast because it is a well-isolated unit suite.

| Measure | Result |
|---|---|
| Real behavior assertions | 1291/1385 = **93.2%** |
| Tautological (mock-only) | 3 = **0.2%** |
| Mutation score, `server/app/routes/` | **100%** |
| Mutation score, `server/app/` overall | **88.2%** |
| Mutation score, `server/app/decoder/` | **80.0%** |
| Frontend real-behavior assertions | **98.8%**, badge honest (82.73% with excludes stripped) |

Classical crypto is genuinely defended: mutations making `CoseKey.verify()`, `ES256.verify()`,
`verify_rp_id()` or the server's origin/challenge/RP-ID-hash/UP/UV checks unconditionally
pass were **all caught**, largely by the vendored upstream Yubico tests using real vectors.

### T1. ML-DSA has no real cryptographic test — CRITICAL
`tests/pqc/test_mldsa_registration_authentication.py`, despite its "end-to-end" docstring:
- `:43` key is `bytes(idx % 256 for idx in range(key_length))` — literally 0,1,2,3…
- `:58` "signature" is a SHA-256 digest
- `:71` monkeypatches `_verify_attestation`
- `:105` **monkeypatches `cose_cls.verify` itself**

Proof it is hollow: the "signature verification always succeeds" mutation **failed zero**
`tests/pqc/` tests. `oqs` is not installed in CI (`ci-python.yml:27-30`) or locally.
Real ML-DSA sign/verify: zero occurrences repo-wide. **If oqs integration broke tomorrow,
1412 tests would still pass.** Line `:105` is the single line most responsible for false
confidence. (Fix lands with C1, which makes ML-DSA testable on every platform.)

### T2. Negative tests are serialized, masking parallel holes — MAJOR
5 of the 8 guards in `fido2/server.py` are covered by a **single** 165-LOC test function
(`tests/fido2/server/test_server_edge_contracts.py:238`) containing ~10 sequential
`pytest.raises` blocks. Demonstrated: deleting the origin check, the RP-ID-hash check and
the user-present check **simultaneously — three auth bypasses — produced exactly ONE test
failure.** Split into one parametrized case per guard.

Those tests also use `_FakeClientData`/`_FakeAuthData`/`_PublicKey(raise_invalid=True)`
(`:17,:40,:64`) — they prove the `if` statements are wired, not that verification works.

### T3. The suite pins the current internal structure — blocks P2
- **1104/1803 (61%)** of `monkeypatch.setattr` calls patch an attribute **on the module
  under test**; **466 (26%)** patch a **private helper** of it. Some use `raising=False`,
  so after a rename they will silently stop patching and still pass.
- **2021 references to private production symbols** (`decode_module._parse_cbor_item` 41,
  `_lenient_decode_from` 39, `advanced_module._decode_client_binary` 19…).
- Example of a test asserting nothing: `tests/app/decoder/test_decoder_coverage_uplift_branches.py:17`
  stubs `_describe_authenticator_data_bytes` to return `{"parsed": True}` then asserts the
  result contains `{"parsed": True}`.
- `tests/app/advanced/test_advanced_branch_focus_contracts.py` patches
  `_parse_client_supplied_credentials` **14 times** — the route tests never parse a real credential.
- **`tests/conftest.py` is 33 lines and defines zero fixtures**; 51 fixtures total across
  200 files. The substitute is 854 `importorskip` preambles.
- 15 tests exceed 100 LOC (worst: `test_general_route_contracts.py:147`, 279 LOC, 37 asserts).

### T4. Surviving mutants are all boundary conditions, in the decoder
The 16-point gap between 96% line coverage and 80% decoder mutation score is entirely
boundary discrimination: `ctap_runtime_parse.py:202` `<=`→`<` survives (infinite-loop guard),
`ctap_repair_leaf.py:31`, `cbor_strict.py:54`, `ctap_repair_make.py:57`,
`details_runtime.py:211` `return False`→`True`.

### T5. Coverage is reported, never enforced
`tools/generate_coverage_badges.py:64-83` writes a shields payload with no minimum and no
non-zero exit. No `fail_under` in `.coveragerc`, no `thresholds` in `vitest.config.mjs`.
Coverage can go 95% → 5% with every check green.

### T6. The module that touches `navigator.credentials` is untested and invisible
`frontend/static/scripts/shared/webauthn/json-ponyfill.js` (193 LOC) is absent from the
coverage denominator in every configuration — its trailing `sourceMappingURL` remaps outside
`coverage.include` — and it is `vi.mock`ed in all three tests that touch it. It performs the
actual `navigator.credentials.create/get` calls and base64url⇄ArrayBuffer conversion.
Also, `vitest.config.mjs:23,24,26` exclude three files deleted in past refactors — silent no-ops.

## P5 — CI/CD and automation. The user's "all future updates automated" goal.

### A1. Seven dependency declaration sites, none authoritative
`requirements.txt`, root `pyproject.toml` (which is the *vendored library's* manifest —
the app has no package identity of its own), `server/pyproject.toml`, a hardcoded bare-name
list at `Dockerfile:41-47`, `package.json`, and two vendored binaries.

- **`server/pyproject.toml:13` `Flask = "^2.0"` vs `requirements.txt:1` `Flask>=3.1.3,<4.0`
  are mutually exclusive.** The Dockerfile installs `./server` and never reads
  `requirements.txt`, so the image resolves Flask 2.x while CI tests Flask 3.x. Not drift
  risk — current divergence.
- **`.gitignore:11` ignores `poetry.lock`.** No lockfile, no SBOM; every build re-resolves
  against live PyPI. Two builds of one commit can differ.
- Dependabot PRs update a file production never reads.
- `pyproject.toml:37-39` declares `pycose`, `pyjwt`, `requests` — **zero imports** repo-wide.
- Three Python versions in play (`^3.8` EOL in both pyprojects, 3.12 in Docker/CI, 3.11 in
  two workflows), zero matrix.

**Target:** one source of truth (root `pyproject.toml` or `uv`), commit the lock, un-ignore
it, Dockerfile installs only from the lock, delete `requirements.txt`, `requires-python = ">=3.12"`.

### A2. No linting, type-checking or security scanning anywhere
No ruff/mypy/bandit/pip-audit/npm-audit/CodeQL/Trivy in any of six workflows. No config
file for any of them — `.ruff_cache/0.15.6/` proves ruff has been run locally, ad hoc,
on defaults, gating nothing.

### A2-scoping. Ruff baseline (measured 2026-09-16, ruff 0.16.8, default rules)
A lint gate cannot be switched on directly — the current tree has never been linted. Top categories:

| Rule | Count | Note |
|---|---|---|
| F821 undefined-name | **1008** | the globals-injection hack (P2.0); 65 of 67 files are split-fragments |
| UP006/UP035/UP045/UP007 | ~1509 | pre-PEP585/604 typing — gated on the `requires-python >= 3.12` bump (A1) |
| F401 unused-import | 321 | autofixable, low-risk |
| BLE001 blind-except | 181 | the broad `except Exception` the audits flagged |
| S110/S112 try-except-pass/continue | 37 | the silent-swallow antipattern |
| F822 undefined-export | 26 | `__all__` entries with no matching name — check for real dead exports |

**F821 is a progress meter for P2.0**: it is ~100% caused by the runtime `FunctionType(..., globals())`
rebinding and should collapse toward 0 when the reflection hack is undone. Do not enable F821 until then.

**Phased rollout:** (1) a minimal ruleset that is cheap to reach green — F401, I001, RUF100, F811,
obvious bug-catchers — gated in CI first; (2) UP* typing modernization *after* A1 sets the Python floor;
(3) F821 *after* P2.0. Autofixing the ~1500 UP* now would create a repo-wide diff that collides with
every in-flight workstream, so it waits.

### A3. Daily unreviewed auto-commits deploy straight to production — CRITICAL
`update-fido-mds.yml`, `update-coverage-badges.yml` and `update-footer-year.yml` all hold
`contents: write` and push directly to `main`. Pushes authored by `GITHUB_TOKEN` do **not**
re-trigger workflows, so these bypass all CI — while still firing the Cloud Build
push-to-main trigger. `update-fido-mds.yml:42` uses `git add -A`. These must open PRs.

### A4. `cloudbuild.yaml` has no test step
GitHub Actions and Cloud Build are independent pipelines. **A red CI does not block a
production deploy.**

### A5. MDS snapshots are ~30MB of tracked files rewritten daily
`blob.jwt` (10M), `fido-mds3.verified.json` (7.1M), `explorer.full.json` (7.1M),
`explorer.json` (5.5M). 79 "Update FIDO MDS snapshot" commits; `.git` is **189MB** and
grows unboundedly. Every daily commit invalidates the Docker layer — directly at odds with
the cold-start work in `deploy/README.md` on a `minScale: "0"` service. Move to the GCS
bucket that already exists (`deploy/service.yaml:52`).

### A6. Other gaps
Dependabot has **no npm ecosystem** despite `package-lock.json`. All actions pinned to
mutable major tags, never SHAs, in workflows holding `contents: write`. No release
automation, tags, or changelog — the deployed artifact is identified only by `$COMMIT_SHA`.
No preview/staging; `cloudbuild.yaml:26-35` shifts 100% of traffic immediately with no
health gate and no rollback. `render.yaml` is stale (pre-rename project name, no secret
key). `docker-compose.yml` bind-mounts `./instance`, sharing the developer's real secret
into the container. Container **runs as root**, no `HEALTHCHECK`. `ci-*.yml` run twice per
same-repo PR. No dependency caching anywhere.
Undocumented: every registration attempts to upload to a hardcoded personal GitHub repo,
`rainzhang05/CredentialLogs` (`github_client.py:25-26`) — should be opt-in and configurable. **Owner decision 2026-09-24: keep as it is.**

---

## Q — Quality / UX

### Q1. Browser analysis is measuring the wrong APIs — CRITICAL
`shared/browser/analyze.js:3-11` tests **WebUSB / WebHID / Web NFC / Web Bluetooth /
Web Serial** — none of which are WebAuthn transports. Consequences: USB/HID/Cable listed
on every Chromium desktop with no authenticator present; never listed on Safari/Firefox,
which do drive USB keys. `'nfc' in navigator` is never true anywhere (the shipped surface
is `NDEFReader`), so NFC is never reported even on Android. `smart-card` (L3) missing.

`detectCrossPlatformAuthenticator:300-335` returns `true` on every Chromium desktop
unconditionally, and its `isConditionalMediationAvailable()` branch is **dead code** —
both paths return `null`.

`getClientCapabilities()` results are collected at `:274-292` then discarded except
`hybridTransport`; `passkeyPlatformAuthenticator`, `conditionalCreate/Get`,
`extension:prf`, `extension:largeBlob` are all thrown away.

Misidentification: **Brave/Arc/Samsung/Vivaldi/Yandex all report "Google Chrome"**
(`:186` applies the UA-CH brand only when UA parsing already failed); Edge and Opera show
the **Chromium** build number (`:53-59` checks `/Chrom(e|ium)/` before `Edg`); **iPad
reports macOS** (`:72-75` — the `maxTouchPoints` discriminator is defeated by an
`&&` with a UA check that is always false in desktop mode).

Note this is masked by the test suite: `analyze-browser.test.js:237` sets a synthetic UA so
the brand path opens; the Brave case passes in test and fails in Brave.

### Q2. UI has no dark mode and fails contrast
Zero `prefers-color-scheme`/`[data-theme]`/`color-scheme` anywhere. 46 CSS custom
properties and 684 `var()` uses, against **134 hardcoded color literals in CSS + 43 in JS**.
The credential UI is styled entirely by **68 inline `style="..."` attributes emitted from
JS** — unthemeable by construction. Six tokens fail AA (`--muted-light` 2.54,
`#11b66d` 2.65, `--primary-light` 2.19, `--accent-color` 3.19). The true/false green/red
pair is **color-only** with no text or icon differentiator, in a tool whose entire purpose
is signalling pass/fail.

### Q3. Accessibility
Primary tab bar has no `role="tablist"/"tab"`, no `aria-selected`, no `aria-controls`
(the *decoder* sub-tabs got it right). The three largest modals have no `role="dialog"`,
`aria-modal` or `aria-labelledby`. **No focus management anywhere** — `openModal`
(`shared/ui/core.js:244-263`) only toggles classes: no focus move, no trap, no inert
background, no restore. 14 form controls with neither `<label for>` nor `aria-label`.
23 `outline: none`. Zero `prefers-reduced-motion`.

### Q4. Frontend architecture
**54 window globals** (42 from `main.js:441-483`, 7 from `mds/runtime/bootstrap.js:130-136`).
The `bootstrap.js` seven are not template handlers — they are a **hidden circular dependency
laundered through `window`**: `credential-display/navigation.js:50,54,65,196` reaches the
MDS module via `window.*` instead of importing it.

**145 inline `on*=` attributes** across 24 templates, plus 2 generated into `innerHTML` at
`list-render.js:228,232` — these hard-block any CSP.

No build step: `tools/build_static_assets.py` only hashes and gzips. **All 167 modules
(852 KB) are eagerly reachable from `main.js` with zero dynamic `import()`**; the ~75-module
MDS subtree loads even though it is not the default tab. Max import depth 7 → ~8 serialized
waves. Only `main.js` is preloaded; no `modulepreload` for the other 166. A single global
`BUILD_ID` over all static files means one CSS edit invalidates all 167 cached JS modules.

### Q5. Duplication (the real cleanup target)
| Concept | Implementations |
|---|---|
| base64url decode | 13 named (PY) + 30 inline + 5 JS |
| base64url encode | 3 PY + 32 inline + 4 JS |
| CBOR codecs | 5 |
| Credential sanitizers | 16 JS + 4 PY |
| AAGUID normalization | 4 PY + 3 JS — **dashed vs dashless, used as Map keys on opposite sides of the UI** |
| env-flag parsing | 3 parsers + 4 wrappers — **deny-list vs allow-list: `ENABLE_GITHUB_LOGGING=y` means *off* in one and *on* in the other** |

---

## Rejected findings — do not re-raise

- **`instance/session-secret.key` is not committed.** `git log --all` empty, `.gitignore:35`
  covers it, local file is `0600`. The secret-key resolution (`config.py:69-145`,
  env → file → atomic generate with `fsync`) is genuinely well-written.
- **The 854 `pytest.importorskip` calls do not mask breakage.** They target *first-party*
  modules (`server.app.config` etc.). Verified by injecting a `raise` into `config.py`:
  pytest exits **1** with 701 failures. It is a style smell — `importorskip` is for optional
  third-party deps — not a correctness hole. The "tests/pqc skips wholesale" claim is false;
  nothing skips today.
- **COSE algorithm IDs are correct and consistent.** `-48`=ML-DSA-44, `-49`=65, `-50`=87
  across `pqc.py`, `fido2/cose.py`, `advanced_parts/constants.py`, `packed.py` and three
  frontend modules, matching IANA. (An earlier brief of mine stated these reversed; that was
  my error, not the code's.)
- **"ML-DSA key/signature lengths are correct per FIPS 204"** (PQC audit) — **false** for
  signature lengths; see C5. Key lengths are correct.
- **The ML-DSA verification core is sound.** Real liboqs calls, correct
  `authenticatorData || clientDataHash` message, `kty=7` (AKP) enforced, key at label `-1`,
  fail-closed error handling throughout. The crypto is not theater — the harness around it is.
- **`static_assets.py` is well-built** (`safe_join`, ETags, gzip, correct
  immutable-vs-revalidate). Preserve it through any refactor.
- **The test suite is NOT a coverage farm.** 93.2% real assertions, 100% mutation score on
  route handlers, 88.2% on app code, classical crypto defended by real vectors. My inference
  from the 4-second runtime was wrong; it is fast because it is well-isolated unit tests.
  The blind spot is specific (ML-DSA), not general.
- **Dead code is not this repo's problem** (~2 LOC Python, ~754 LOC JS).
- **Zero JS import cycles.**

---

## Execution order

1. **P0 security** — S1/S2/S3/S5/S6 (backend), S4 (frontend). *In flight.*
2. **S7/S8/S9** — headers, cookies, debug logging, IDOR.
3. **C1** — lift the `cryptography` cap, migrate ML-DSA, delete liboqs + 670 DER lines.
4. **T1/T2** — real ML-DSA round trip with bit-flip rejection; split the serialized negative tests; implement signCount + replay checks (S11).
5. **A1** — dependency single source of truth + committed lock + resolve Flask 2/3.
6. **A2/A3/A4** — lint/type/security gates; bots open PRs; test gate before deploy.
7. **D5/D6/D3** — one-line correctness fixes in the codec.
8. **P2.0** — undo globals injection. **Gate for everything below.**
9. **P2.3/P2.2** — container layout, `create_app()`.
10. **P2.4** — re-merge along responsibility lines; unify encoding (Q5).
11. **D1/D2/D4/D9** — make the codec honest; canonicity validator.
12. **Q1** — rewrite browser/capability detection.
13. **C2** — un-fork fido2, ML-DSA as a plugin.
14. **A5/A6** — MDS out of git, release automation, preview/rollback.
15. **Q2/Q3/Q4** — design tokens, dark mode, a11y, CSP (needs Q4 inline handlers gone).
