import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

const repoRoot = path.resolve(import.meta.dirname, '..', '..');
const frontendRoot = path.join(repoRoot, 'frontend');
const scriptsRoot = path.join(frontendRoot, 'static', 'scripts');

function collectJavaScriptFiles(root) {
  const entries = fs.readdirSync(root, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectJavaScriptFiles(fullPath));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith('.js')) {
      files.push(fullPath);
    }
  }

  return files;
}

describe('frontend import smoke test', () => {
  it('imports every frontend JavaScript module without throwing', async () => {
    const files = collectJavaScriptFiles(scriptsRoot);
    files.push(path.join(frontendRoot, 'static', 'fido-mds3.explorer.bootstrap.js'));

    for (const file of files) {
      const moduleUrl = pathToFileURL(file).href;
      await expect(import(moduleUrl)).resolves.toBeDefined();
    }
  });
});
