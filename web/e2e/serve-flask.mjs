// Starts the Flask app for the browser tests, as production runs it but with
// every store in a temporary directory (nothing is written to the checkout), the
// MDS fixture as its snapshot and the relying party pinned to localhost. Stops
// Flask and removes the directory when Playwright stops it.
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { cpSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const repo = resolve(import.meta.dirname, '..', '..');
const port = process.env.E2E_PORT ?? '5151';
const python = process.env.E2E_PYTHON ?? join(repo, '.venv', 'bin', 'python');
const stores = mkdtempSync(join(tmpdir(), 'pqc-e2e-'));
// The small synthetic MDS snapshot (tests/fixtures/mds), copied so nothing Flask
// does lands in the checkout: the same entries on every machine, never the
// developer's real snapshot, and none in CI without it.
const mdsSnapshot = join(stores, 'mds-snapshot');
cpSync(join(repo, 'tests', 'fixtures', 'mds', 'snapshot'), mdsSnapshot, { recursive: true });

const flask = spawn(
  python,
  ['-m', 'flask', '--app', 'server.app.app:app', 'run', '--host', '127.0.0.1', '--port', port],
  {
    cwd: repo,
    stdio: 'inherit',
    env: {
      ...process.env,
      FLASK_DEBUG: '0',
      FIDO_SERVER_SECRET_KEY: randomBytes(32).toString('hex'),
      FIDO_SERVER_RUNTIME_ROOT: join(stores, 'runtime'),
      FIDO_SERVER_CREDENTIAL_DIR: join(stores, 'credentials'),
      FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR: join(stores, 'artifacts'),
      FIDO_SERVER_SESSION_METADATA_DIR: join(stores, 'session-metadata'),
      FIDO_SERVER_GCS_ENABLED: '0',
      FIDO_SERVER_RP_ID: 'localhost',
      FIDO_SERVER_ALLOWED_ORIGINS: `http://localhost:${port}`,
      FIDO_SERVER_WEB_EXPORT_ROOT: join(repo, 'web', 'out'),
      FIDO_SERVER_MDS_SNAPSHOT_DIR: mdsSnapshot,
      FIDO_SERVER_MDS_FETCH_UPSTREAM: '0',
    },
  },
);

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => flask.kill(signal));
}
flask.on('exit', (code, signal) => {
  rmSync(stores, { recursive: true, force: true });
  process.exit(signal ? 0 : (code ?? 0));
});
