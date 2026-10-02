// The JSON editor with no page: its titles and sentences, the text a request is
// written as, reading an edit (and where text that does not parse stops being
// JSON, the same in every browser), and the keys an edit adds beside
// `publicKey`. DOM-free.
import { isPlainObject } from './schema.js';
import { validateAuthenticationPublicKey } from '../authentication/validation.js';
import { validateRegistrationPublicKey } from '../registration/validation.js';

// A value with every object's keys in order, as the editor shows a request.
export function sortObjectKeys(value) {
    if (Array.isArray(value)) {
        return value.map(item => sortObjectKeys(item));
    }

    if (value && Object.prototype.toString.call(value) === '[object Object]') {
        const sorted = {};
        Object.keys(value)
            .sort((a, b) => a.localeCompare(b))
            .forEach(key => {
                sorted[key] = sortObjectKeys(value[key]);
            });
        return sorted;
    }

    return value;
}

export const EDITOR_TEXT = {
    title: 'JSON Editor',
    registrationTitle: 'JSON Editor (CredentialCreationOptions)',
    authenticationTitle: 'JSON Editor (CredentialRequestOptions)',
    invalidStructure: 'Invalid JSON structure.',
    missingPublicKey: 'Invalid JSON structure: Missing "publicKey" object.',
    saved: 'JSON changes saved successfully!',
    reset: 'JSON editor reset to current settings.',
};

/** The editor's heading for the sub-tab shown. */
export function editorTitle(scope) {
    if (scope === 'registration') {
        return EDITOR_TEXT.registrationTitle;
    }
    if (scope === 'authentication') {
        return EDITOR_TEXT.authenticationTitle;
    }
    return EDITOR_TEXT.title;
}

/** What an edit that cannot be taken says. */
export function validationFailedText(message) {
    return `JSON validation failed: ${message}`;
}

/** A request as the editor writes it: every object's keys sorted, two spaces of indent. */
export function requestText(options) {
    return JSON.stringify(sortObjectKeys(options), null, 2);
}

function checkEditorStructure(parsed) {
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error(EDITOR_TEXT.invalidStructure);
    }

    if (!parsed.publicKey || typeof parsed.publicKey !== 'object') {
        throw new Error(EDITOR_TEXT.missingPublicKey);
    }
    return parsed;
}

/** The keys an edit holds beside `publicKey`, which the editor keeps. */
export function topLevelExtras(root) {
    if (!isPlainObject(root)) {
        return {};
    }
    const { publicKey, ...extras } = root;
    return extras;
}

class JsonStop {
    constructor(offset) {
        this.offset = offset;
    }
}

// A reader of JSON that only finds where text stops being JSON (RFC 8259).
function findJsonStop(text) {
    let index = 0;
    /** @type {() => never} */
    const stop = () => {
        throw new JsonStop(index);
    };
    const skipSpace = () => {
        while (index < text.length && ' \t\n\r'.includes(text[index])) {
            index += 1;
        }
    };
    const expect = (character) => {
        skipSpace();
        if (text[index] !== character) {
            stop();
        }
        index += 1;
    };
    const readString = () => {
        index += 1;
        while (index < text.length) {
            const character = text[index];
            if (character === '"') {
                index += 1;
                return;
            }
            if (character === '\\') {
                if (/^\\(["\\/bfnrt]|u[0-9a-fA-F]{4})/.test(text.slice(index, index + 6))) {
                    index += text[index + 1] === 'u' ? 6 : 2;
                    continue;
                }
                stop();
            }
            if (character < ' ') {
                stop();
            }
            index += 1;
        }
        stop();
    };
    const readValue = () => {
        skipSpace();
        const character = text[index];
        if (character === '{' || character === '[') {
            const closing = character === '{' ? '}' : ']';
            index += 1;
            skipSpace();
            if (text[index] === closing) {
                index += 1;
                return;
            }
            for (;;) {
                if (closing === '}') {
                    skipSpace();
                    if (text[index] !== '"') {
                        stop();
                    }
                    readString();
                    expect(':');
                }
                readValue();
                skipSpace();
                if (text[index] === closing) {
                    index += 1;
                    return;
                }
                expect(',');
            }
        }
        if (character === '"') {
            readString();
            return;
        }
        const literal = /^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/.exec(text.slice(index));
        if (!literal) {
            stop();
        }
        index += literal[0].length;
    };

    try {
        readValue();
        skipSpace();
        if (index < text.length) {
            stop();
        }
        return null;
    } catch (/** @type {any} */ error) {
        return error.offset;
    }
}

/**
 * Where text stops being JSON: the line and column (from 1) of the first
 * character that cannot be read, or of the end when the text ends too soon;
 * null for JSON.
 */
export function locateJsonSyntaxError(text) {
    const offset = findJsonStop(text);
    if (offset === null) {
        return null;
    }
    const before = text.slice(0, offset);
    const lineStart = before.lastIndexOf('\n') + 1;
    return {
        offset,
        line: before.split('\n').length,
        column: offset - lineStart + 1,
    };
}

const VALIDATORS = {
    registration: validateRegistrationPublicKey,
    authentication: validateAuthenticationPublicKey,
};

/**
 * What an edit of the editor is: text that does not parse (`unparsed`, with
 * why and where), an object the form cannot follow (`refused`, with the
 * sentence: the structure's, or the first check the request fails), or one
 * it can (`accepted`). What parses is the request the ceremony sends either way.
 */
export function readEditedRequest(text, scope) {
    let root;
    try {
        root = JSON.parse(text || '{}');
    } catch (/** @type {any} */ error) {
        return {
            status: 'unparsed',
            message: validationFailedText(error.message),
            location: locateJsonSyntaxError(text),
        };
    }
    try {
        VALIDATORS[scope](checkEditorStructure(root).publicKey);
    } catch (/** @type {any} */ error) {
        return { status: 'refused', root, message: validationFailedText(error.message) };
    }
    return { status: 'accepted', root };
}
