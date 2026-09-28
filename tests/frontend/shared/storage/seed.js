import { vi } from 'vitest';

// The saved credentials' storage with fresh modules, seeded as a page may seed it
// before its first read (the current UI's page data did, until Phase 30).
let seed = null;

export function seedRecords(records) {
  seed = records;
}

export async function loadStorage() {
  vi.resetModules();
  const core = await import('../../../../frontend/static/scripts/shared/storage/local/storage-core.js');
  core.seedUnifiedCredentialRecords(seed);
  return import('../../../../frontend/static/scripts/shared/storage/records.js');
}
