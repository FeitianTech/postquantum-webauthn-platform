import {
  type DeletionReport,
  type ListTone,
  clearSavedCredentials,
  deleteSavedCredential,
} from '@/logic/credentials/delete-flow.js';
import { describeCredentialRows, readSavedCredentials, warmSavedCredentials } from '@/logic/credentials/saved-list.js';
import { type ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';

import { useToast } from '@/components/ui/Toast';

import { type CredentialRowView, type SavedCredential, flashKey, followOtherTabs } from './model';

// How long a row keeps the tint of the ceremony it was just used in (the current
// cards' flash).
const FLASH_MS = 2200;

type ListNotice = { tone: Exclude<ListTone, 'success'>; text: string };
export type RowFlash = { key: string; variant: 'success' | 'failure' };

export type SavedCredentialsState = {
  /** False until the browser's storage has been read (after hydration). */
  loaded: boolean;
  rows: CredentialRowView[];
  /** A deletion or Clear All is running. */
  busy: boolean;
  /** What a deletion is doing ("Deleting credential..."). */
  progress: string | null;
  /** A deletion's warning or failure, until the next one. */
  notice: ListNotice | null;
  flash: RowFlash | null;
  /** Reads the storage again, then warms it up (as the current list does after each drawing). */
  refresh: () => void;
  remove: (credential: SavedCredential) => Promise<void>;
  clearAll: () => Promise<void>;
  /** Tints the row of the credential a ceremony just used: green for success, red for a refusal. */
  flashCredential: (credentialId: unknown, variant: RowFlash['variant']) => void;
};

const SavedCredentialsContext = createContext<SavedCredentialsState | null>(null);

// The saved credentials every section shows: one list, read from the browser's
// storage both tabs share, read again after each change, and warmed up after
// each read (heavy advanced records go to the server, missing snapshots come from it; the
// warm-up's own re-read does not warm up again). Deleting and clearing report
// here: a success as a toast, anything else under the list's header.
export function SavedCredentialsProvider({ children }: { children: ReactNode }) {
  const toast = useToast();
  const [loaded, setLoaded] = useState(false);
  const [credentials, setCredentials] = useState<SavedCredential[]>([]);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [notice, setNotice] = useState<ListNotice | null>(null);
  const [flash, setFlash] = useState<RowFlash | null>(null);
  const busyRef = useRef(false);
  const warming = useRef<Promise<boolean> | null>(null);

  const reload = useCallback(() => {
    setCredentials(readSavedCredentials());
    setLoaded(true);
  }, []);

  const refresh = useCallback(() => {
    reload();
    if (!warming.current) {
      warming.current = warmSavedCredentials(reload).finally(() => {
        warming.current = null;
      });
    }
  }, [reload]);

  // After hydration: on the server there is no storage, so the exported page
  // shows the list empty and reads it here.
  useEffect(refresh, [refresh]);

  // A change another tab makes (either interface) shows here without a reload.
  // Read again only: that tab warms its own change up.
  useEffect(() => followOtherTabs(reload), [reload]);

  const report = useMemo<DeletionReport>(
    () => ({
      isRunning: () => busyRef.current,
      setRunning: (running) => {
        busyRef.current = running;
        setBusy(running);
      },
      dismiss: () => setNotice(null),
      progress: setProgress,
      status: (text, tone) => {
        if (tone === 'success') toast({ tone: 'success', message: text });
        else setNotice({ tone, text });
      },
      reload: async () => refresh(),
    }),
    [refresh, toast],
  );

  const remove = useCallback((credential: SavedCredential) => deleteSavedCredential(credential, report), [report]);
  const clearAll = useCallback(() => clearSavedCredentials(report), [report]);

  const flashTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const flashCredential = useCallback((credentialId: unknown, variant: RowFlash['variant']) => {
    const key = flashKey(credentialId);
    if (flashTimer.current) clearTimeout(flashTimer.current);
    setFlash(key ? { key, variant } : null);
    flashTimer.current = setTimeout(() => setFlash(null), FLASH_MS);
  }, []);
  useEffect(() => () => {
    if (flashTimer.current) clearTimeout(flashTimer.current);
  }, []);

  const rows = useMemo(() => describeCredentialRows(credentials), [credentials]);
  const value = useMemo(
    () => ({ loaded, rows, busy, progress, notice, flash, refresh, remove, clearAll, flashCredential }),
    [loaded, rows, busy, progress, notice, flash, refresh, remove, clearAll, flashCredential],
  );
  return <SavedCredentialsContext.Provider value={value}>{children}</SavedCredentialsContext.Provider>;
}

export function useSavedCredentials() {
  const saved = useContext(SavedCredentialsContext);
  if (!saved) throw new Error('useSavedCredentials needs a SavedCredentialsProvider');
  return saved;
}
