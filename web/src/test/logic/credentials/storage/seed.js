import { vi } from 'vitest';

// The saved credentials' storage with fresh modules, seeded as a page may seed it
// before its first read: every module's functions in one object.
let seed = null;

export function seedRecords(records) {
  seed = records;
}

export async function loadStorage() {
  vi.resetModules();
  const core = await import('@/logic/credentials/storage/local/storage-core.js');
  core.seedUnifiedCredentialRecords(seed);
  return {
    ...core,
    ...(await import('@/logic/credentials/storage/local/simple-credentials.js')),
    ...(await import('@/logic/credentials/storage/local/advanced-credentials.js')),
    ...(await import('@/logic/credentials/storage/local/advanced-sync.js')),
    ...(await import('@/logic/credentials/storage/records.js')),
  };
}
