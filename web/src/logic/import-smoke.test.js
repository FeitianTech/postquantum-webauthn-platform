import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

// Every logic module loads on its own (its tests, beside it, are not modules).
const logicRoot = import.meta.dirname;

function collectModules(root) {
  const files = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectModules(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.js') && !entry.name.endsWith('.test.js')) {
      files.push(fullPath);
    }
  }
  return files;
}

describe('the logic modules', () => {
  it('each import without throwing', async () => {
    const files = collectModules(logicRoot);
    expect(files.length).toBeGreaterThan(90);

    for (const file of files) {
      await expect(import(pathToFileURL(file).href)).resolves.toBeDefined();
    }
  });
});
