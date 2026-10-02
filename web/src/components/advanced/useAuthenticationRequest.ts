import { useCallback, useEffect, useMemo, useReducer, useRef } from 'react';

import { useSavedCredentials } from '@/components/credentials/useSavedCredentials';
import {
  type AllowChoice,
  allowCredentialChoices,
  authenticationCredentials,
  keptChoice,
} from '@/logic/advanced/authentication/allow-credentials.js';
import { readEditedRequest, topLevelExtras } from '@/logic/advanced/editor/model.js';
import type { SavedCredential } from '@/logic/credentials/saved-list.js';
import { fakeCredentialLength, normaliseFakeCredentialList, withoutFakeCredential } from '@/logic/advanced/fake-credentials.js';
import { generateRandomHex } from '@/logic/shared/bytes.js';
import { authenticationAvailability } from '@/logic/advanced/authentication/capabilities.js';
import {
  type AuthenticationField,
  type AuthenticationSettings,
  authenticationDefaults,
  buildRequestOptions,
  changeAuthentication,
  readRequestOptions,
  withAvailability,
} from '@/logic/advanced/authentication/request.js';

import { NO_TEXT, type RequestText, followedText, rebuiltText, resetText } from './requestEditor';

// An authentication's request as the Advanced tab holds it, as the
// registration's is (./useAdvancedRequest.ts): the JSON editor's text is the
// request, the form a view of it; a form change rewrites in the text only what
// it changed, an edit the form can follow updates the form at once. The request
// is made from the saved credentials an authentication can use (the advanced
// ones, which its ceremony sends). Allow Credentials offers those the
// authentication's own hints allow (what the request sends, and what the server
// filters by), and falls back to All when its choice goes; whether largeBlob and
// prf can be asked for follows those credentials and the choice, clearing what
// they cannot ask for.

type RequestState = RequestText & {
  settings: AuthenticationSettings;
  /** The fake credential IDs allowCredentials carries after the saved ones (hex). */
  fakeAllow: string[];
  /** What the fake ID field says about the last length asked for. */
  fakeMessage: { tone: 'error' | 'info'; text: string } | null;
  started: boolean;
};

type Context = { hostname: string; storedCredentials: SavedCredential[] };

type Action =
  | { type: 'start'; settings: AuthenticationSettings; context: Context }
  | { type: 'change'; field: AuthenticationField; value: AuthenticationSettings[AuthenticationField]; context: Context }
  | { type: 'settings'; settings: AuthenticationSettings; context: Context }
  | { type: 'fake-add'; hex: string | null; message: RequestState['fakeMessage']; context: Context }
  | { type: 'fake-remove'; index: number; context: Context }
  | { type: 'edit'; text: string; context: Context }
  | { type: 'context'; context: Context }
  | { type: 'reset-editor'; context: Context };

function formRequestOf(settings: AuthenticationSettings, fakeAllow: string[], context: Context) {
  return buildRequestOptions(settings, { hostname: context.hostname, storedCredentials: context.storedCredentials, fakeAllowCredentials: fakeAllow });
}

/** What Allow Credentials offers with these settings: the credentials their hints allow. */
function choicesFor(settings: AuthenticationSettings, context: Context): AllowChoice[] {
  return allowCredentialChoices(context.storedCredentials, settings.hints);
}

/** The settings as the saved credentials leave them: a choice still offered, and only the extensions they can use. */
function settled(settings: AuthenticationSettings, context: Context): AuthenticationSettings {
  const allowCredentials = keptChoice(choicesFor(settings, context), settings.allowCredentials);
  return withAvailability({ ...settings, allowCredentials }, authenticationAvailability(context.storedCredentials, allowCredentials));
}

/** The settings with their choice still offered: a hint that refuses the chosen credential brings All back. */
function offered(settings: AuthenticationSettings, context: Context): AuthenticationSettings {
  const allowCredentials = keptChoice(choicesFor(settings, context), settings.allowCredentials);
  return allowCredentials === settings.allowCredentials ? settings : settled({ ...settings, allowCredentials }, context);
}

function followed(current: RequestState, context: Context, background = false): RequestState {
  return followedText(current, formRequestOf(current.settings, current.fakeAllow, context), 'authentication', background);
}

function reduce(current: RequestState, action: Action): RequestState {
  switch (action.type) {
    case 'start': {
      const settings = settled(action.settings, action.context);
      return rebuiltText(
        { ...NO_TEXT, settings, fakeAllow: [], fakeMessage: null, started: true },
        formRequestOf(settings, [], action.context),
      );
    }
    case 'change': {
      const changed = changeAuthentication(current.settings, action.field, action.value);
      // A credential chosen is judged alone: what it cannot ask for goes. The
      // hints change what is offered: a choice they refuse falls back to All.
      const settings =
        action.field === 'allowCredentials' ? settled(changed, action.context) : action.field === 'hints' ? offered(changed, action.context) : changed;
      return followed({ ...current, settings }, action.context);
    }
    case 'settings':
      return followed({ ...current, settings: action.settings }, action.context);
    case 'fake-add':
      return followed(
        { ...current, fakeAllow: action.hex ? [...current.fakeAllow, action.hex] : current.fakeAllow, fakeMessage: action.message },
        action.context,
      );
    case 'fake-remove':
      return followed({ ...current, fakeAllow: withoutFakeCredential(current.fakeAllow, action.index) ?? current.fakeAllow, fakeMessage: null }, action.context);
    case 'context':
      return followed({ ...current, settings: settled(current.settings, action.context) }, action.context, true);
    case 'reset-editor':
      return resetText(current, formRequestOf(current.settings, current.fakeAllow, action.context), 'authentication');
    case 'edit': {
      const edit = readEditedRequest(action.text, 'authentication');
      if (edit.status !== 'accepted') return { ...current, text: action.text, edit };
      // Read against every credential the request can name; then the edit's own
      // hints decide whether its one credential is offered, else All.
      const read = readRequestOptions(edit.root.publicKey, current.settings, {
        storedCredentials: action.context.storedCredentials,
        choices: ['all', 'empty', ...allowCredentialChoices(action.context.storedCredentials, []).map((choice) => choice.value)],
      });
      const settings = {
        ...read.settings,
        allowCredentials: keptChoice(choicesFor(read.settings, action.context), read.settings.allowCredentials),
      };
      const fakeAllow = normaliseFakeCredentialList(read.fakeAllowCredentials);
      return {
        ...current,
        settings,
        fakeAllow,
        extras: topLevelExtras(edit.root),
        text: action.text,
        edit: null,
        // What the form now says, which the next form change is measured from.
        formRequest: formRequestOf(settings, fakeAllow, action.context),
      };
    }
  }
}

const EMPTY: RequestState = {
  ...NO_TEXT,
  settings: { ...authenticationDefaults(), challenge: '' },
  fakeAllow: [],
  fakeMessage: null,
  started: false,
};

export function useAuthenticationRequest() {
  const saved = useSavedCredentials();
  const [current, dispatch] = useReducer(reduce, EMPTY);
  const storedCredentials = useMemo(() => authenticationCredentials(saved.rows.map((row) => row.credential)), [saved.rows]);
  const choices = useMemo(() => allowCredentialChoices(storedCredentials, current.settings.hints), [storedCredentials, current.settings.hints]);
  const contextRef = useRef<Context>({ hostname: '', storedCredentials });
  contextRef.current = { ...contextRef.current, storedCredentials };
  const context = () => contextRef.current;

  // Once the saved credentials have been read (after hydration), as the current
  // tab fills its form once it has loaded them: a challenge and a largeBlob
  // value to write, drawn at random.
  useEffect(() => {
    if (!saved.loaded || current.started) return;
    contextRef.current = { ...contextRef.current, hostname: window.location.hostname };
    dispatch({ type: 'start', settings: { ...authenticationDefaults(), challenge: generateRandomHex(32), largeBlobWrite: generateRandomHex(32) }, context: contextRef.current });
  }, [saved.loaded, current.started]);

  // The saved credentials changed: a choice that went falls back to All.
  const started = useRef(false);
  started.current = current.started;
  useEffect(() => {
    if (started.current) dispatch({ type: 'context', context: contextRef.current });
  }, [storedCredentials]);

  const change = useCallback(<F extends AuthenticationField>(field: F, value: AuthenticationSettings[F]) => {
    dispatch({ type: 'change', field, value, context: context() });
  }, []);

  const settingsRef = useRef(current.settings);
  settingsRef.current = current.settings;
  const update = useCallback((next: Partial<AuthenticationSettings>) => {
    dispatch({ type: 'settings', settings: { ...settingsRef.current, ...next }, context: context() });
  }, []);

  const randomizeChallenge = useCallback(() => update({ challenge: generateRandomHex(32) }), [update]);
  const randomizePrf = useCallback((which: 'prfFirst' | 'prfSecond') => update({ [which]: generateRandomHex(32) }), [update]);
  const randomizeLargeBlobWrite = useCallback(() => update({ largeBlobWrite: generateRandomHex(32) }), [update]);

  /** After an authentication, the random values drawn again: those that are not empty. */
  const redraw = useCallback(() => {
    const now = settingsRef.current;
    update({
      ...(now.challenge.trim() ? { challenge: generateRandomHex(32) } : {}),
      ...(now.prfFirst.trim() ? { prfFirst: generateRandomHex(32) } : {}),
      ...(now.prfSecond.trim() ? { prfSecond: generateRandomHex(32) } : {}),
      ...(now.largeBlobWrite.trim() ? { largeBlobWrite: generateRandomHex(32) } : {}),
    });
  }, [update]);

  const addFake = useCallback(() => {
    const { bytes, error, notice } = fakeCredentialLength(settingsRef.current.fakeCredLength);
    const message = error ? ({ tone: 'error', text: error } as const) : notice ? ({ tone: 'info', text: notice } as const) : null;
    dispatch({ type: 'fake-add', hex: bytes ? generateRandomHex(bytes) : null, message, context: context() });
  }, []);
  const removeFake = useCallback((index: number) => dispatch({ type: 'fake-remove', index, context: context() }), []);

  const editText = useCallback((text: string) => dispatch({ type: 'edit', text, context: context() }), []);
  const resetEditor = useCallback(() => dispatch({ type: 'reset-editor', context: context() }), []);
  // The toolbar's Reset: the defaults with a new challenge, the fake IDs and the
  // edit's keys gone; the Hash Algorithm stays.
  const resetForm = useCallback(() => {
    dispatch({
      type: 'start',
      settings: { ...authenticationDefaults(), hashAlgorithm: settingsRef.current.hashAlgorithm, challenge: generateRandomHex(32) },
      context: context(),
    });
  }, []);

  const availability = useMemo(
    () => authenticationAvailability(storedCredentials, current.settings.allowCredentials),
    [storedCredentials, current.settings.allowCredentials],
  );

  return {
    ...current,
    choices,
    availability,
    storedCredentials,
    change,
    randomizeChallenge,
    randomizePrf,
    randomizeLargeBlobWrite,
    redraw,
    addFake,
    removeFake,
    editText,
    resetEditor,
    resetForm,
  };
}

export type AuthenticationRequest = ReturnType<typeof useAuthenticationRequest>;
