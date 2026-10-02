import { useCallback, useEffect, useMemo, useReducer, useRef } from 'react';

import { useSavedCredentials } from '@/components/credentials/useSavedCredentials';
import { APP_TITLE } from '@/lib/sections';
import type { SavedCredential } from '@/logic/credentials/saved-list.js';

import {
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
  withoutFake,
} from './model';
import { NO_TEXT, type RequestText, followedText, rebuiltText, resetText } from './requestEditor';

// A registration's request as the Advanced tab holds it: the JSON editor's text
// is the request (what the ceremony sends), and the form
// is a view of it. A form change rewrites in the text only what it changed in
// the form's request, everything else staying as typed (followForm); an edit
// the form can follow updates the form at once: an edit applies as it parses. The toolbar's Reset rebuilds the text from nothing;
// the editor's Reset from the form, keeping the keys beside publicKey.

type RequestState = RequestText & {
  settings: RegistrationSettings;
  /** The fake credential IDs the request excludes after the saved ones (hex). */
  fakeExclude: string[];
  /** What the fake ID field says about the last length asked for. */
  fakeMessage: { tone: 'error' | 'info'; text: string } | null;
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

function formRequestOf(settings: RegistrationSettings, fakeExclude: string[], context: Context) {
  return buildRequest(settings, {
    rpName: APP_TITLE,
    hostname: context.hostname,
    storedCredentials: context.storedCredentials,
    fakeExcludeCredentials: fakeExclude,
  });
}

function followed(current: RequestState, context: Context, background = false): RequestState {
  return followedText(current, formRequestOf(current.settings, current.fakeExclude, context), 'registration', background);
}

function reduce(current: RequestState, action: Action): RequestState {
  switch (action.type) {
    case 'start':
    case 'reset':
      return rebuiltText(
        { ...NO_TEXT, settings: action.settings, fakeExclude: [], fakeMessage: null },
        formRequestOf(action.settings, [], action.context),
      );
    case 'change':
      return followed({ ...current, settings: changeSetting(current.settings, action.field, action.value) }, action.context);
    case 'settings':
      return followed({ ...current, settings: action.settings }, action.context);
    case 'fake-add':
      return followed(
        { ...current, fakeExclude: action.hex ? [...current.fakeExclude, action.hex] : current.fakeExclude, fakeMessage: action.message },
        action.context,
      );
    case 'fake-remove':
      return followed({ ...current, fakeExclude: withoutFake(current.fakeExclude, action.index) ?? current.fakeExclude, fakeMessage: null }, action.context);
    case 'rebuild':
      return followed(current, action.context, true);
    case 'reset-editor':
      return resetText(current, formRequestOf(current.settings, current.fakeExclude, action.context), 'registration');
    case 'edit': {
      const edit = readEdit(action.text, 'registration');
      if (edit.status !== 'accepted') return { ...current, text: action.text, edit };
      const read = readRequest(edit.root.publicKey, current.settings, { storedCredentials: action.context.storedCredentials });
      const fakeExclude = fakeList(read.fakeExcludeCredentials);
      return {
        ...current,
        settings: read.settings,
        fakeExclude,
        extras: extrasOf(edit.root),
        text: action.text,
        edit: null,
        // What the form now says, which the next form change is measured from.
        formRequest: formRequestOf(read.settings, fakeExclude, action.context),
      };
    }
  }
}

const EMPTY: RequestState = {
  ...NO_TEXT,
  settings: { ...defaultSettings(), userId: '', userName: '', displayName: '', challenge: '' },
  fakeExclude: [],
  fakeMessage: null,
};

export function useAdvancedRequest() {
  const saved = useSavedCredentials();
  const [current, dispatch] = useReducer(reduce, EMPTY);
  const storedCredentials = useMemo(() => saved.rows.map((row) => row.credential), [saved.rows]);
  const contextRef = useRef<Context>({ hostname: '', storedCredentials });
  contextRef.current = { ...contextRef.current, storedCredentials };
  const context = () => contextRef.current;

  // After hydration: the exported page has no host and no random values.
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

  /** After a registration, the random values drawn again: those that are not empty. */
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
