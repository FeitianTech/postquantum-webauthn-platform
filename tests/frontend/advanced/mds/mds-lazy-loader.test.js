import { beforeEach, describe, expect, it, vi } from 'vitest';

import { createMdsLazyLoader, MdsLazyLoader } from '../../../../frontend/static/scripts/advanced/mds-lazy-loader.js';

describe('mds-lazy-loader', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('initializes state and supports raw entry access and parsing marks', () => {
    const loader = createMdsLazyLoader();
    expect(loader).toBeInstanceOf(MdsLazyLoader);

    const metadata = { entries: [{ aaguid: 'AA-BB' }, { aaid: 'CCDD' }] };
    loader.initialize(metadata);

    expect(loader.getAllRawEntries()).toEqual(metadata.entries);
    expect(loader.getRawEntryByIndex(0)).toEqual(metadata.entries[0]);
    expect(loader.getRawEntryByIndex(99)).toBeNull();

    loader.markEntryFullyParsed(0, 'aabb');
    expect(loader.isEntryFullyParsed(0)).toBe(true);
    expect(loader.isEntryFullyParsed(1)).toBe(false);

    const stats = loader.getStats();
    expect(stats.total).toBe(2);
    expect(stats.fullyParsed).toBe(1);
    expect(stats.pending).toBe(1);
    expect(stats.percentComplete).toBe(50);

    expect(loader.isFullyLoaded()).toBe(false);
    loader.markEntryFullyParsed(1, 'ccdd');
    expect(loader.isFullyLoaded()).toBe(true);
  });

  it('finds entries by key and certificate normalization', () => {
    const loader = new MdsLazyLoader();
    loader.initialize({
      entries: [
        {
          aaguid: 'AA-BB',
          metadataStatement: {
            aaguid: 'AA-BB',
            attestationRootCertificates: ['-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----'],
          },
        },
        {
          aaid: 'CC-DD',
          metadataStatement: {
            attestationRootCertificates: ['XYZ'],
          },
        },
      ],
    });

    expect(loader.getRawEntryByKey('aabb')).toEqual(loader.allEntries[0]);
    expect(loader.getRawEntryByKey('ccdd')).toEqual(loader.allEntries[1]);
    expect(loader.getRawEntryByKey('missing')).toBeNull();

    // cache path
    loader.fullyParsedKeys.set('cached', { cached: true });
    expect(loader.getRawEntryByKey('cached')).toEqual({ cached: true });

    expect(
      loader.findEntriesWithCertificate('-----BEGIN CERTIFICATE-----ABC-----END CERTIFICATE-----'),
    ).toHaveLength(1);
    expect(loader.findEntriesWithCertificate('')).toEqual([]);
    expect(loader.findEntriesWithCertificate(null)).toEqual([]);
  });

  it('runs background loading batches, progress, and completion callbacks', async () => {
    const loader = new MdsLazyLoader();
    const entries = Array.from({ length: 205 }, (_, i) => ({ id: i }));
    loader.initialize({ entries });

    const batchCalls = [];
    const progressCalls = [];
    const completeCalls = [];

    loader.onProgress((parsed, total, percent) => {
      progressCalls.push({ parsed, total, percent });
    });
    loader.onComplete(() => completeCalls.push(true));

    const yieldSpy = vi.spyOn(loader, 'yieldToBrowser').mockResolvedValue();

    await loader.startBackgroundLoading({
      onBatchProcessed: async (indices) => {
        batchCalls.push(indices);
      },
    });

    expect(loader.backgroundLoadComplete).toBe(true);
    expect(loader.isBackgroundLoading).toBe(false);
    expect(loader.fullyParsedIndices.size).toBe(entries.length);
    expect(batchCalls.length).toBe(2);
    expect(progressCalls.length).toBeGreaterThan(0);
    expect(completeCalls).toEqual([true]);
    expect(yieldSpy).toHaveBeenCalled();
  });

  it('supports aborting background loading and start guarding', async () => {
    const loader = new MdsLazyLoader();
    loader.initialize({ entries: [{ id: 1 }, { id: 2 }] });

    loader.abortBackgroundLoading();
    expect(loader.backgroundLoadAborted).toBe(true);

    // Reset and abort through signal
    loader.initialize({ entries: [{ id: 1 }, { id: 2 }] });
    const signal = { aborted: true };
    await loader.startBackgroundLoading({ signal, onBatchProcessed: vi.fn() });
    expect(loader.backgroundLoadAborted).toBe(true);

    // already complete returns same promise
    loader.backgroundLoadComplete = true;
    loader.backgroundLoadPromise = Promise.resolve('done');
    const p = loader.startBackgroundLoading();
    await expect(p).resolves.toBe('done');
  });

  it('normalizes keys/certificates and yields using available scheduling APIs', async () => {
    const loader = new MdsLazyLoader();

    expect(loader.normalizeKey(' AA-BB ')).toBe('aabb');
    expect(loader.normalizeKey(null)).toBe('');

    expect(loader.normalizeCertificate('-----BEGIN CERTIFICATE-----\nAB C\n-----END CERTIFICATE-----')).toContain('ABC');
    expect(loader.normalizeCertificate(123)).toBe('');

    // requestIdleCallback branch
    const origIdle = globalThis.requestIdleCallback;
    globalThis.requestIdleCallback = (cb) => {
      cb();
      return 1;
    };
    await expect(loader.yieldToBrowser()).resolves.toBeUndefined();

    // requestAnimationFrame branch
    globalThis.requestIdleCallback = undefined;
    const origRaf = globalThis.requestAnimationFrame;
    globalThis.requestAnimationFrame = (cb) => {
      cb(0);
      return 1;
    };
    const timeoutSpy = vi.spyOn(globalThis, 'setTimeout').mockImplementation((fn) => {
      fn();
      return 1;
    });
    await expect(loader.yieldToBrowser()).resolves.toBeUndefined();

    // setTimeout fallback branch
    globalThis.requestAnimationFrame = undefined;
    await expect(loader.yieldToBrowser()).resolves.toBeUndefined();

    timeoutSpy.mockRestore();
    globalThis.requestIdleCallback = origIdle;
    globalThis.requestAnimationFrame = origRaf;
  });
});
