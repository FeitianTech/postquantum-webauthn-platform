import { defineConfig } from 'vitest/config';

const FULL = { statements: 100, branches: 100, functions: 100, lines: 100 };

export default defineConfig({
  test: {
    environment: 'jsdom',
    environmentOptions: {
      jsdom: {
        url: 'http://localhost/',
      },
    },
    setupFiles: ['./tests/frontend/setup.js'],
    include: ['tests/frontend/**/*.test.js'],
    // The Cloud Build gate runs pytest, this suite and web's at once on one
    // two-vCPU machine. Under that load (reproduced locally on 2026-09-27) the
    // heaviest tests here (the import smoke test, the page actions, the MDS
    // explorer's) passed five seconds, vitest's default. A test that hangs still
    // fails, after thirty seconds.
    testTimeout: 30_000,
    coverage: {
      provider: 'v8',
      all: true,
      reportsDirectory: './coverage/frontend',
      reporter: ['text', 'json-summary', 'html'],
      include: [
        'frontend/static/**/*.js',
      ],
      exclude: [
        'tests/frontend/**',
      ],
      // A floor, not a target. Set just under the numbers measured on
      // 2026-09-28, once the current UI's views had gone (99.96 statements /
      // 99.79 branches / 100 functions / 99.96 lines), so a real regression
      // fails the run but ordinary churn does not. Raise these when coverage
      // rises; never lower them to go green.
      thresholds: {
        statements: 99.5,
        branches: 99.5,
        functions: 99.5,
        lines: 99.5,
        // The Codec's logic, which the new UI in web/ imports: every line and branch.
        'frontend/static/scripts/decoder/codec/{constants,labels,request,result,values}.js': FULL,
        'frontend/static/scripts/decoder/codec/encoding/{binary,can-encode,format,summary}.js': FULL,
        // The MDS explorer's logic, which web/ imports: every line and branch.
        'frontend/static/scripts/advanced/mds/explorer/*.js': FULL,
        'frontend/static/scripts/advanced/mds/{constants,raw-data,raw-stringify,sort-filter-normalise}.js': FULL,
        'frontend/static/scripts/advanced/mds/metadata/{explorer-source,metadata-helpers}.js': FULL,
        'frontend/static/scripts/advanced/mds/utils/{extractors,formatters,resolvers}.js': FULL,
        // The saved credentials' storage, which both UIs read and write: every line and branch.
        'frontend/static/scripts/shared/storage/{artifacts-client,records}.js': FULL,
        'frontend/static/scripts/shared/storage/local/*.js': FULL,
        // The Simple tab's ceremonies and what they rest on, which web/ imports: every line and branch.
        'frontend/static/scripts/simple/ceremony.js': FULL,
        'frontend/static/scripts/shared/ceremony/result.js': FULL,
        'frontend/static/scripts/shared/auth/random-username.js': FULL,
        'frontend/static/scripts/shared/api/failed-response.js': FULL,
        'frontend/static/scripts/shared/debug/auth.js': FULL,
        'frontend/static/scripts/shared/utils/{base64,binary}.js': FULL,
        // What the browser says of itself and of WebAuthn, which the Analyze Browser panel shows: every line and branch.
        'frontend/static/scripts/shared/browser/*.js': FULL,
        'frontend/static/scripts/shared/state.js': FULL,
        // What a saved credential's card shows, deleting and clearing, which web/ imports: every line and branch.
        'frontend/static/scripts/advanced/credentials/{algorithm-tag,delete-flow,saved-list,utils}.js': FULL,
        'frontend/static/scripts/advanced/credential-display/{attestation-context,certificate-core}.js': FULL,
        // A saved credential's details and registration view, which web/ imports: every line and branch.
        'frontend/static/scripts/advanced/credential-display/{certificate-text,data-utils,decode-payload,registration-state,sanitize-attestation-object,sanitize-common,state}.js': FULL,
        'frontend/static/scripts/advanced/credential-display/registration-view.js': FULL,
        'frontend/static/scripts/advanced/credential-display/credential-detail-runtime/{compose,detail-sections,helpers,registration-candidates,registration-context,snapshot-context}.js': FULL,
        'frontend/static/scripts/advanced/credentials/hydrate.js': FULL,
        'frontend/static/scripts/advanced/{constants,cose-labels}.js': FULL,
        // The Advanced tab's form with no page, which web/ imports: every line and branch.
        'frontend/static/scripts/advanced/auth/{allow-credentials,assertion,capabilities,ceremony,fake-credentials,hex-input,hint-rules}.js': FULL,
        'frontend/static/scripts/advanced/credential-display/registration-snapshot.js': FULL,
        'frontend/static/scripts/advanced/editor/json-editing.js': FULL,
        'frontend/static/scripts/advanced/json-editor/{algorithm-options,authentication-request,editor-model,registration-request,request-patch,schema}.js': FULL,
        'frontend/static/scripts/advanced/json-editor/validation-{authentication,common,registration}.js': FULL,
      },
    },
  },
});
