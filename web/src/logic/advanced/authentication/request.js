// An authentication's request (CredentialRequestOptions) and the form's
// settings it is built from, with no page: the settings' defaults, the request
// they build, what a request says the settings are, and the rules one setting's
// change applies to others. DOM-free: the form keeps the settings as data.
import { extractHexFromJsonFormat, jsonBytes } from '../editor/byte-values.js';
import { getCredentialIdHex, getStoredCredentialAttachment } from '../../credentials/record-fields.js';
import { deriveAllowedAttachmentsFromHints } from '../hints.js';
import { decodeJsonBinaryToHex, requestTimeout } from '../registration/request.js';

/**
 * The settings the form starts from and a reset returns to, without the values
 * drawn at random (the challenge, and the largeBlob write value the page starts
 * with). Byte fields are hex text as typed; the timeout and the fake ID length
 * are text. Allow Credentials is `all`, `empty` or a saved credential's ID (hex).
 */
export function authenticationDefaults() {
    return {
        userVerification: 'preferred',
        allowCredentials: 'all',
        fakeCredLength: '256',
        timeout: '90000',
        hints: [],
        hashAlgorithm: 'SHA-256',
        largeBlob: '',
        largeBlobWrite: '',
        prfFirst: '',
        prfSecond: '',
    };
}

// A credential's ID in the request, as hex.
function descriptorFor(credentialIdHex) {
    return {
        type: 'public-key',
        id: jsonBytes(credentialIdHex),
    };
}

/**
 * The saved credentials an Allow Credentials choice puts in allowCredentials:
 * All (and a choice no saved credential has) gives every one whose attachment
 * the hints allow (every one without hints); a saved credential gives itself,
 * or none when the hints refuse its attachment.
 */
export function allowedCredentials(storedCredentials, selection, allowedAttachments) {
    const stored = storedCredentials || [];
    const allowedBy = cred => {
        if (allowedAttachments.length === 0) {
            return true;
        }
        const attachment = getStoredCredentialAttachment(cred);
        return Boolean(attachment) && allowedAttachments.includes(attachment);
    };
    const every = () => stored
        .filter(allowedBy)
        .map(cred => cred.credentialIdHex || getCredentialIdHex(cred))
        .filter(Boolean)
        .map(descriptorFor);

    if (selection === 'all') {
        return every();
    }
    const selected = stored.find(cred => (cred.credentialIdHex || getCredentialIdHex(cred)) === selection);
    if (!selected) {
        return every();
    }
    return allowedBy(selected) ? [descriptorFor(selected.credentialIdHex || getCredentialIdHex(selected))] : [];
}

/**
 * The request the settings build, `{ publicKey }`. context: hostname (the
 * relying party), storedCredentials (the list's records), fakeAllowCredentials
 * (hex), which follow the saved ones.
 */
export function buildRequestOptions(settings, context = {}) {
    const hints = settings.hints;
    /** @type {Record<string, any>} */
    const publicKey = {
        challenge: jsonBytes(settings.challenge),
        timeout: requestTimeout(settings.timeout),
        rpId: context.hostname,
        allowCredentials: [],
        userVerification: settings.userVerification || 'preferred',
        extensions: {},
    };

    let removeAllowCredentials = false;
    if (settings.allowCredentials === 'empty') {
        removeAllowCredentials = true;
    } else {
        publicKey.allowCredentials = allowedCredentials(
            context.storedCredentials,
            settings.allowCredentials,
            deriveAllowedAttachmentsFromHints(hints),
        );
    }

    const fakeAllowCredentials = context.fakeAllowCredentials || [];
    if (fakeAllowCredentials.length) {
        publicKey.allowCredentials.push(...fakeAllowCredentials.map(descriptorFor));
        removeAllowCredentials = false;
    }

    if (removeAllowCredentials && !publicKey.allowCredentials.length) {
        delete publicKey.allowCredentials;
    }

    if (settings.largeBlob === 'read') {
        publicKey.extensions.largeBlob = { read: true };
    } else if (settings.largeBlob === 'write' && settings.largeBlobWrite) {
        publicKey.extensions.largeBlob = { write: jsonBytes(settings.largeBlobWrite) };
    }

    if (settings.prfFirst) {
        publicKey.extensions.prf = { eval: { first: jsonBytes(settings.prfFirst) } };
        if (settings.prfSecond) {
            publicKey.extensions.prf.eval.second = jsonBytes(settings.prfSecond);
        }
    }

    if (hints.length > 0) {
        publicKey.hints = hints;
    }

    return { publicKey };
}

// The IDs (hex) of an allowCredentials list: the saved credentials' (lower
// case) and the others, each in the list's order.
function allowListIds(allowCredentials, storedCredentials) {
    const saved = new Set(
        (storedCredentials || [])
            .map(cred => (cred.credentialIdHex || getCredentialIdHex(cred)).toLowerCase())
            .filter(Boolean),
    );
    const savedIds = [];
    const others = [];
    allowCredentials.forEach(descriptor => {
        const hexValue = descriptor && typeof descriptor === 'object' ? extractHexFromJsonFormat(descriptor.id) : '';
        if (!hexValue) {
            return;
        }
        if (saved.has(hexValue.toLowerCase())) {
            savedIds.push(hexValue.toLowerCase());
        } else {
            others.push(hexValue);
        }
    });
    return { savedIds, others };
}

// The Allow Credentials choice a list says, the form's (`previous`) kept when
// it would build the same saved credentials (an edit elsewhere does not change
// it): one offered credential is that credential, any other list All.
function allowChoiceOf(savedIds, previous, hints, context) {
    const built = previous.allowCredentials === 'empty'
        ? []
        : allowedCredentials(context.storedCredentials, previous.allowCredentials, deriveAllowedAttachmentsFromHints(hints))
            .map(descriptor => extractHexFromJsonFormat(descriptor.id).toLowerCase());
    if (built.join(',') === savedIds.join(',')) {
        return previous.allowCredentials;
    }
    const offered = savedIds.length === 1
        ? (context.choices || []).find(choice => choice.toLowerCase() === savedIds[0])
        : undefined;
    return offered || 'all';
}

/**
 * The settings a request says, over the ones the form has (`previous`): what it
 * gives replaces them; what the form writes and the request leaves out is off
 * (no hints, no prf, no largeBlob), and what the form always writes stays.
 * Allow Credentials: Empty without allowCredentials; an empty list leaves it as
 * it was; a list the form's choice would build keeps that choice; one of the
 * offered credentials (context.choices, their IDs) is that credential; else
 * All. Also the IDs its allowCredentials holds that are no saved credential's
 * (context.storedCredentials), as the fake IDs, as they are spelled there.
 */
export function readRequestOptions(publicKey, previous, context = {}) {
    const settings = { ...previous };

    if (publicKey.challenge) {
        const challengeValue = decodeJsonBinaryToHex(publicKey.challenge);
        if (challengeValue) {
            settings.challenge = challengeValue;
        }
    }

    if (publicKey.timeout || publicKey.timeout === 0) {
        settings.timeout = publicKey.timeout.toString();
    }

    settings.hints = Array.isArray(publicKey.hints) ? publicKey.hints : [];

    let fakeAllowCredentials = [];
    if (!Object.hasOwn(publicKey, 'allowCredentials')) {
        settings.allowCredentials = 'empty';
    } else if (!Array.isArray(publicKey.allowCredentials)) {
        settings.allowCredentials = 'all';
    } else if (publicKey.allowCredentials.length > 0) {
        const { savedIds, others } = allowListIds(publicKey.allowCredentials, context.storedCredentials);
        settings.allowCredentials = allowChoiceOf(savedIds, previous, settings.hints, context);
        fakeAllowCredentials = others;
    }

    if (Object.hasOwn(publicKey, 'userVerification')) {
        settings.userVerification = publicKey.userVerification || 'preferred';
    }

    const extensions = publicKey.extensions || {};
    const prfFirst = decodeJsonBinaryToHex(extensions.prf?.eval?.first);
    settings.prfFirst = prfFirst;
    settings.prfSecond = prfFirst ? decodeJsonBinaryToHex(extensions.prf.eval.second) : '';

    // A Write with nothing to write builds no largeBlob: without one, it stays.
    const largeBlob = extensions.largeBlob;
    if (largeBlob?.read) {
        settings.largeBlob = 'read';
    } else if (largeBlob?.write) {
        settings.largeBlob = 'write';
        const largeBlobValue = decodeJsonBinaryToHex(largeBlob.write);
        if (largeBlobValue) {
            settings.largeBlobWrite = largeBlobValue;
        }
    } else if (!(previous.largeBlob === 'write' && !previous.largeBlobWrite)) {
        settings.largeBlob = '';
    }

    return { settings, fakeAllowCredentials };
}

/** The settings after one of them changes, with the form's rule: an empty first prf evaluation empties the second. */
export function changeAuthentication(settings, field, value) {
    const next = { ...settings, [field]: value };
    if (field === 'prfFirst' && !value.trim()) {
        next.prfSecond = '';
    }
    return next;
}

/**
 * The settings as the extensions' availability leaves them
 * (../auth/capabilities.js): no largeBlob, and no value to write, when it may
 * not be asked for; no prf evaluation when prf may not be.
 */
export function withAvailability(settings, availability) {
    const next = { ...settings };
    if (!availability.largeBlob.available) {
        next.largeBlob = '';
        next.largeBlobWrite = '';
    }
    if (!availability.prf.available) {
        next.prfFirst = '';
        next.prfSecond = '';
    }
    return next;
}

/** Which of the settings' fields the form cannot change as they stand, given the extensions' availability. */
export function authenticationControls(settings, availability) {
    return {
        largeBlob: !availability.largeBlob.available,
        largeBlobWrite: !availability.largeBlob.available || settings.largeBlob !== 'write',
        prfFirst: !availability.prf.available,
        prfSecond: !availability.prf.available || !settings.prfFirst.trim(),
    };
}
