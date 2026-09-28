import { useCallback, useEffect, useMemo, useReducer, useRef } from 'react';

import type { SavedCredential } from '@/components/credentials/model';
import { useSavedCredentials } from '@/components/credentials/useSavedCredentials';
import { APP_TITLE } from '@/lib/sections';

import {
  type EditedRequest,
  type RegistrationField,
  type RegistrationSettings,
  buildRequest,
  changeSetting,
  defaultSettings,
  extrasOf,
  fakeLength,
  fakeList,
  randomHex,
  randomName,
  readEdit,
  readRequest,
  textOf,
  withoutFake,
} from './model';

// A registration's request as the Advanced tab holds it: the JSON editor's text
// is the request (what the ceremony sends, as in the current tab), and the form
// is a view of it. A form change rebuilds the text from the form's settings,
// keeping the keys an edit added beside publicKey; an edit the form can follow
// updates the form at once, and the text stays as typed until the form changes
// or the editor is reset (the owner's choice: an edit applies as it parses).

type RequestState = {
  settings: RegistrationSettings;
  /** The fake credential IDs the request excludes after the saved ones (hex). */
  fakeExclude: string[];
  /** What the fake ID field says about the last length asked for. */
  fakeMessage: { tone: 'error' | 'info'; text: string } | null;
  /** The keys an accepted edit holds beside publicKey. */
  extras: Record<string, unknown>;
  /** The editor's text: the request. */
  text: string;
  /** What the last edit is, until the form rebuilds the text. */
  edit: EditedRequest | null;
};

type Context = { hostname: string; storedCredentials: SavedCredential[] };

type Action =
  | { type: 'start'; settings: RegistrationSettings; context: Context }
  | { type: 'change'; field: RegistrationField; value: RegistrationSettings[RegistrationField]; context: Context }
  | { type: 'settings'; settings: RegistrationSettings; context: Context }
  | { type: 'fake-add'; hex: string | null; message: RequestState['fakeMessage']; context: Context }
  | { type: 'fake-remove'; index: number; context: Context }
  | { type: 'edit'; text: string; context: Context }
  | { type: 'rebuild'; context: Context }
  | { type: 'reset-editor'; context: Context }
  | { type: 'reset'; settings: RegistrationSettings; context: Context };

/** The values the form draws at random: a User ID and challenge of 32 bytes, a ten-character name. */
function randomIdentity() {
  const name = randomName();
  return { userId: randomHex(32), userName: name, displayName: name };
}

function freshSettings(): RegistrationSettings {
  return { ...defaultSettings(), ...randomIdentity(), challenge: randomHex(32) };
}

function rebuilt(current: RequestState, context: Context): RequestState {
  const request = buildRequest(current.settings, {
    rpName: APP_TITLE,
    hostname: context.hostname,
    storedCredentials: context.storedCredentials,
    fakeExcludeCredentials: current.fakeExclude,
  });
  return { ...current, text: textOf({ ...current.extras, ...request }), edit: null };
}

function reduce(current: RequestState, action: Action): RequestState {
  switch (action.type) {
    case 'start':
    case 'reset':
      return rebuilt({ settings: action.settings, fakeExclude: [], fakeMessage: null, extras: {}, text: '', edit: null }, action.context);
    case 'change':
      return rebuilt({ ...current, settings: changeSetting(current.settings, action.field, action.value) }, action.context);
    case 'settings':
      return rebuilt({ ...current, settings: action.settings }, action.context);
    case 'fake-add':
      return rebuilt(
        { ...current, fakeExclude: action.hex ? [...current.fakeExclude, action.hex] : current.fakeExclude, fakeMessage: action.message },
        action.context,
      );
    case 'fake-remove':
      return rebuilt({ ...current, fakeExclude: withoutFake(current.fakeExclude, action.index) ?? current.fakeExclude, fakeMessage: null }, action.context);
    case 'rebuild':
      return current.edit ? current : rebuilt(current, action.context);
    case 'reset-editor': {
      // As the current editor's Reset: the form's request, with the keys beside
      // publicKey that the text holds, if it parses.
      const reading = readEdit(current.text, 'registration');
      return rebuilt({ ...current, extras: reading.status === 'unparsed' ? current.extras : extrasOf(reading.root) }, action.context);
    }
    case 'edit': {
      const edit = readEdit(action.text, 'registration');
      if (edit.status !== 'accepted') return { ...current, text: action.text, edit };
      const read = readRequest(edit.root.publicKey, current.settings, { storedCredentials: action.context.storedCredentials });
      return {
        ...current,
        settings: read.settings,
        fakeExclude: fakeList(read.fakeExcludeCredentials),
        extras: extrasOf(edit.root),
        text: action.text,
        edit,
      };
    }
  }
}

const EMPTY: RequestState = {
  settings: { ...defaultSettings(), userId: '', userName: '', displayName: '', challenge: '' },
  fakeExclude: [],
  fakeMessage: null,
  extras: {},
  text: '',
  edit: null,
};

export function useAdvancedRequest() {
  const saved = useSavedCredentials();
  const [current, dispatch] = useReducer(reduce, EMPTY);
  const storedCredentials = useMemo(() => saved.rows.map((row) => row.credential), [saved.rows]);
  const contextRef = useRef<Context>({ hostname: '', storedCredentials });
  contextRef.current = { ...contextRef.current, storedCredentials };
  const context = () => contextRef.current;

  // After hydration (the exported page has no host and no random values), as
  // the current tab fills its form once the page has loaded.
  useEffect(() => {
    contextRef.current = { ...contextRef.current, hostname: window.location.hostname };
    dispatch({ type: 'start', settings: freshSettings(), context: contextRef.current });
  }, []);

  // A change of the saved credentials changes what is excluded, unless the
  // text is the person's own edit.
  useEffect(() => {
    if (contextRef.current.hostname) dispatch({ type: 'rebuild', context: contextRef.current });
  }, [storedCredentials]);

  const change = useCallback(<F extends RegistrationField>(field: F, value: RegistrationSettings[F]) => {
    dispatch({ type: 'change', field, value, context: context() });
  }, []);

  const settingsRef = useRef(current.settings);
  settingsRef.current = current.settings;
  const update = useCallback((next: Partial<RegistrationSettings>) => {
    dispatch({ type: 'settings', settings: { ...settingsRef.current, ...next }, context: context() });
  }, []);

  const randomizeIdentity = useCallback(() => update(randomIdentity()), [update]);
  const randomizeChallenge = useCallback(() => update({ challenge: randomHex(32) }), [update]);
  const randomizePrf = useCallback((which: 'prfFirst' | 'prfSecond') => update({ [which]: randomHex(32) }), [update]);

  /** After a registration, the values the current tab draws again: those that are not empty. */
  const redraw = useCallback(() => {
    const current = settingsRef.current;
    update({
      ...(current.userId.trim() || current.userName.trim() ? randomIdentity() : {}),
      ...(current.challenge.trim() ? { challenge: randomHex(32) } : {}),
      ...(current.prfFirst.trim() ? { prfFirst: randomHex(32) } : {}),
      ...(current.prfSecond.trim() ? { prfSecond: randomHex(32) } : {}),
    });
  }, [update]);

  const addFake = useCallback(() => {
    const { bytes, error, notice } = fakeLength(settingsRef.current.fakeCredLength);
    const message = error ? ({ tone: 'error', text: error } as const) : notice ? ({ tone: 'info', text: notice } as const) : null;
    dispatch({ type: 'fake-add', hex: bytes ? randomHex(bytes) : null, message, context: context() });
  }, []);
  const removeFake = useCallback((index: number) => dispatch({ type: 'fake-remove', index, context: context() }), []);

  const editText = useCallback((text: string) => dispatch({ type: 'edit', text, context: context() }), []);
  const resetEditor = useCallback(() => dispatch({ type: 'reset-editor', context: context() }), []);
  const resetForm = useCallback(() => dispatch({ type: 'reset', settings: freshSettings(), context: context() }), []);

  return {
    ...current,
    change,
    randomizeIdentity,
    randomizeChallenge,
    randomizePrf,
    redraw,
    addFake,
    removeFake,
    editText,
    resetEditor,
    resetForm,
  };
}

export type AdvancedRequest = ReturnType<typeof useAdvancedRequest>;
