import {
  type EditedRequest,
  type RequestScope,
  readEditedRequest,
  requestText,
  topLevelExtras,
} from '@/logic/advanced/editor/model.js';
import { followForm } from '@/logic/advanced/editor/request-patch.js';

// The part of a ceremony's request both the registration and the
// authentication keep alike: the JSON editor's text is the request, the keys an
// edit holds beside publicKey, what the text is when the form cannot follow it,
// and the form's request the text last followed (./useAdvancedRequest.ts,
// ./useAuthenticationRequest.ts).

type Json = Record<string, unknown>;
type FormRequest = { publicKey: Json };

export type RequestText = {
  /** The keys an accepted edit holds beside publicKey. */
  extras: Json;
  /** The editor's text: the request. */
  text: string;
  /** What the text is, when the form cannot follow it (unparsed or refused). */
  edit: EditedRequest | null;
  /** The form's request the text last followed; none before the first. */
  formRequest: FormRequest | null;
};

/** What the JSON editor shows and changes of a request. */
export type RequestEditor = {
  text: string;
  edit: EditedRequest | null;
  editText: (text: string) => void;
  resetEditor: () => void;
};

export const NO_TEXT: RequestText = { extras: {}, text: '', edit: null, formRequest: null };

/** The text rebuilt from the form's request, with the keys beside publicKey. */
export function rebuiltText<T extends RequestText>(current: T, request: FormRequest): T {
  return { ...current, text: requestText({ ...current.extras, ...request }), edit: null, formRequest: request };
}

/**
 * The text after the form's request changed: what changed is written over it,
 * the rest staying as typed. A change the person did not make (`background`:
 * the saved credentials, what they allow) leaves text that does not parse as it is.
 */
export function followedText<T extends RequestText>(current: T, request: FormRequest, scope: RequestScope, background = false): T {
  if (!current.formRequest) return rebuiltText(current, request);
  if (background && current.edit?.status === 'unparsed') return { ...current, formRequest: request };
  const text = followForm(current.text, current.formRequest, request, current.extras);
  const reading = readEditedRequest(text, scope);
  return { ...current, text, edit: reading.status === 'accepted' ? null : reading, formRequest: request };
}

/** The editor's Reset: the form's request, with the keys beside publicKey the text holds, if it parses. */
export function resetText<T extends RequestText>(current: T, request: FormRequest, scope: RequestScope): T {
  const reading = readEditedRequest(current.text, scope);
  return rebuiltText({ ...current, extras: reading.status === 'unparsed' ? current.extras : topLevelExtras(reading.root) }, request);
}
