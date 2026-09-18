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
- `decode_parts/cbor_core.py` now has **no importers anywhere** in `server/` or `tests/`. It is
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

### Local development
Tests previously ran against the global interpreter, whose packages matched nothing in
`requirements.txt` (cryptography 44.0.3, fido2 2.1.1, gunicorn 23). A project venv now exists:
`.venv` (gitignored), built from `requirements.txt`. Run tests with
`.venv/bin/python -m pytest -q`. It currently carries `cryptography` 50.0.1 (see C1).

### Follow-ups raised during batch 1
- `routes/general.py:494` `downloadcred` still serves `pickle.dumps(credentials)` as a `.pkl`
  download — the mirror image of S10; anything that loads it gets code execution.
- A traversal `?email=` now raises `ValueError` in storage → HTTP 500. Map to 400 in routes.
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
- 7 modules carry `# pyright: reportUndefinedVariable=false` as a self-admission.
- Routes use a parallel hack: 33 one-line forwarders passing `sys.modules[__name__]`
  back into their own fragments — **539 references** to `advanced_module`/`simple_module`.

No type checker, IDE or linter can see any of this. Until it is reversed, no tool can
tell you what a file move broke.

### P2.1. The split is mechanical, not semantic
- **73 of 87 parts modules (83%) have exactly one importer. Zero are imported by any test.**
- **All 87 are ≤400 LOC (max 398)** while 5 *unsplit* server files exceed 400 (up to
  `mds_snapshot.py` at 698). The ceiling applies only to files that were split — a line
  budget, not a design.
- 23 commits titled `refactor: split …` over 2026-04-08→10.
- 14,720 of 20,645 server LOC (71%) now live in `*_parts/`; 849 of the 1,523 façade LOC
  (55%) is pure plumbing.

Genuine exceptions — leave alone: `encode_parts` (fan-in 3-8), `shared/storage/local`,
`decoder/codec`.

### P2.2. `config.py` is a god module (563 LOC, 13 concerns)
Flask app singleton + session-secret persistence + embedded PEM trust anchors + RP-ID
resolution + gzip middleware + path discovery. **Importing it writes a file to disk**
(`_resolve_secret_key()` at line 148). It carries a re-import guard so `importlib.reload`
works, because tests reload it. `tests/conftest.py` has **no app fixture**; 146
`test_client` calls reach for the global. `pqc.py` imports the web framework solely for
`app.logger`. Extract `create_app()`.

### P2.3. Container layout — 1 line, removes 3 hacks
`Dockerfile:70` `COPY server/app /app/server` collapses a directory level, so `server.app`
means a package in a checkout and a module in the image. Fix to `COPY server /app/server`,
which deletes the `gunicorn.conf.py:23-26` dual-import fallback, the
`server/app/__init__.py:9-20` `__getattr__` shim, and the `fido2`-directory probe at
`app.py:13-24`. Already caused commit `4491f6a`.

### P2.4. Target layout
```
server/app/
  config/     settings.py, rp.py, secrets.py, trust_anchors.py
  wsgi.py     create_app()
  encoding.py THE base64url/hex module (kills 16 decoders, 7 encoders)
  webauthn/   attestation.py, trust.py, pqc.py, metadata.py
  decoder/    cbor.py, ctap.py, certificates.py, summary.py
  routes/     simple.py, advanced.py, general.py  (thin)
  storage/    credentials.py, sessions.py, cloud.py
```

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
`rainzhang05/CredentialLogs` (`github_client.py:25-26`) — should be opt-in and configurable.

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
