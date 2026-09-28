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
      // 2026-09-17 (82.59 statements / 66.46 branches / 91.33 functions /
      // 82.71 lines) so a real regression fails the run but ordinary churn
      // does not. Raise these when coverage rises; never lower them to go green.
      thresholds: {
        statements: 82,
        branches: 66,
        functions: 91,
        lines: 82,
        // The Codec's logic, which the new UI in web/ imports: every line and branch.
        'frontend/static/scripts/decoder/codec/{constants,labels,request,result,values}.js': FULL,
        'frontend/static/scripts/decoder/codec/encoding/{can-encode,format,summary}.js': FULL,
        // The MDS explorer's logic, which web/ imports: every line and branch.
        'frontend/static/scripts/advanced/mds/explorer/*.js': FULL,
        'frontend/static/scripts/advanced/mds/{constants,raw-data,raw-stringify,sort-filter-normalise}.js': FULL,
        'frontend/static/scripts/advanced/mds/metadata/{explorer-source,metadata-helpers}.js': FULL,
        'frontend/static/scripts/advanced/mds/utils/{extractors,formatters,resolvers,status-reports}.js': FULL,
        // The saved credentials' storage, which both UIs read and write: every line and branch.
        'frontend/static/scripts/shared/storage/{artifacts-client,local,records}.js': FULL,
        'frontend/static/scripts/shared/storage/local/*.js': FULL,
        // The Simple tab's ceremonies and what they rest on, which web/ imports: every line and branch.
        'frontend/static/scripts/simple/ceremony.js': FULL,
        'frontend/static/scripts/shared/ceremony/result.js': FULL,
        'frontend/static/scripts/shared/auth/random-username.js': FULL,
        'frontend/static/scripts/shared/api/failed-response.js': FULL,
        'frontend/static/scripts/shared/debug/auth.js': FULL,
        'frontend/static/scripts/shared/utils/{base64,binary}.js': FULL,
        'frontend/static/scripts/shared/state.js': FULL,
        // What a saved credential's card shows, deleting and clearing, which web/ imports: every line and branch.
        'frontend/static/scripts/advanced/credentials/{algorithm-tag,delete-flow,saved-list,utils}.js': FULL,
        'frontend/static/scripts/advanced/credential-display/{attestation-context,certificate-core}.js': FULL,
        // A saved credential's details and registration view, which web/ imports: every line and branch.
        'frontend/static/scripts/advanced/credential-display/{certificate-text,data-utils,decode-payload,registration-state,sanitize-attestation-object,sanitize-common,state}.js': FULL,
        'frontend/static/scripts/advanced/credential-display/credential-detail-runtime/snapshot-context.js': FULL,
        'frontend/static/scripts/advanced/{constants,cose-labels}.js': FULL,
      },
    },
  },
});
