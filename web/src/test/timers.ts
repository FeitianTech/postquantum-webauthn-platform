import { vi } from 'vitest';

// Hold a transient message while its answer lands and is read. Setup and user
// interactions that need the clock happen before this scope.
export async function holdingTimers(read: () => Promise<void>) {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  try {
    await read();
  } finally {
    vi.useRealTimers();
  }
}

export function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}
