import { join } from 'node:path';

// A file of the repository by its path from the root, wherever vitest runs from.
// Not new URL(…, import.meta.url): Vite rewrites that form into an asset URL.
export const repoFile = (path) => join(import.meta.dirname, '..', '..', '..', '..', path);
