import { existsSync } from 'node:fs';
import { join } from 'node:path';

// /beta serves web/out; without a build every /beta test would fail on a 404.
export default function globalSetup() {
  const index = join(import.meta.dirname, '..', 'out', 'index.html');
  if (!existsSync(index)) {
    throw new Error(`No export at ${index}. Run \`npm run build\` before \`npm run e2e\`.`);
  }
}
