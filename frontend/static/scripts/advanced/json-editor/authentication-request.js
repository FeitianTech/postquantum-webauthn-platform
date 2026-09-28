// An authentication's request (CredentialRequestOptions) and the form's
// settings it is built from, with no page: the settings' defaults, the request
// they build, what a request says the settings are, and the rules one setting's
// change applies to others. DOM-free: the current form reads and writes its
// fields around these (./request-options.js, ./form-sync.js, ../ui/resets.js)
// and the new UI keeps the settings as data.
import {
    convertFormat,
    currentFormatToJsonFormat,
    getCurrentBinaryFormat,
} from '../../shared/utils/binary.js';
import {
    extractHexFromJsonFormat,
    getCredentialIdHex,
    getStoredCredentialAttachment,
} from '../credentials/utils.js';
import { deriveAllowedAttachmentsFromHints } from '../auth/hint-rules.js';
import { decodeJsonBinaryToHex } from './registration-request.js';

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

// A credential's ID in the request, in the page's byte spelling.
function descriptorFor(credentialIdHex) {
    return {
        type: 'public-key',
        id: currentFormatToJsonFormat(convertFormat(credentialIdHex, 'hex', getCurrentBinaryFormat())),
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
    const publicKey = {
        challenge: currentFormatToJsonFormat(settings.challenge),
        timeout: parseInt(settings.timeout) || 90000,
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
        publicKey.extensions.largeBlob = { write: currentFormatToJsonFormat(settings.largeBlobWrite) };
    }

    if (settings.prfFirst) {
        publicKey.extensions.prf = { eval: { first: currentFormatToJsonFormat(settings.prfFirst) } };
        if (settings.prfSecond) {
            publicKey.extensions.prf.eval.second = currentFormatToJsonFormat(settings.prfSecond);
        }
    }

    if (hints.length > 0) {
        publicKey.hints = hints;
    }

    return { publicKey };
}

/**
 * The settings a request says, over the ones the form has (`previous`): what it
 * gives replaces them, what it leaves out stays. Allow Credentials becomes
 * Empty without allowCredentials, the one credential it names when that is one
 * of the choices (context.choices: the values the select offers), else All; an
 * empty list leaves it as it was. Also the IDs its allowCredentials holds that
 * are no saved credential's, as the fake IDs (hex).
 */
export function readRequestOptions(publicKey, previous, context = {}) {
    const settings = { ...previous };

    if (publicKey.challenge) {
        const challengeValue = decodeJsonBinaryToHex(publicKey.challenge);
        if (challengeValue) {
            settings.challenge = challengeValue;
        }
    }

    if (publicKey.timeout) {
        settings.timeout = publicKey.timeout.toString();
    }

    const choices = context.choices || [];
    if (!Object.prototype.hasOwnProperty.call(publicKey, 'allowCredentials')) {
        settings.allowCredentials = 'empty';
    } else if (!Array.isArray(publicKey.allowCredentials)) {
        settings.allowCredentials = 'all';
    } else if (publicKey.allowCredentials.length > 0) {
        let desired = 'all';
        if (publicKey.allowCredentials.length === 1) {
            const descriptor = publicKey.allowCredentials[0];
            const extractedHex = descriptor && typeof descriptor === 'object' ? extractHexFromJsonFormat(descriptor.id) : '';
            if (extractedHex && choices.includes(extractedHex)) {
                desired = extractedHex;
            }
        }
        settings.allowCredentials = desired;
    }

    if (Object.prototype.hasOwnProperty.call(publicKey, 'userVerification')) {
        settings.userVerification = publicKey.userVerification || 'preferred';
    }

    const extensions = publicKey.extensions;
    if (extensions) {
        if (extensions.prf && extensions.prf.eval) {
            const first = extensions.prf.eval.first ? decodeJsonBinaryToHex(extensions.prf.eval.first) : '';
            if (first) {
                settings.prfFirst = first;
            }
            const second = extensions.prf.eval.second ? decodeJsonBinaryToHex(extensions.prf.eval.second) : '';
            if (second) {
                settings.prfSecond = second;
            }
        }
        if (extensions.largeBlob) {
            if (extensions.largeBlob.read) {
                settings.largeBlob = 'read';
            } else if (extensions.largeBlob.write) {
                settings.largeBlob = 'write';
                const largeBlobValue = decodeJsonBinaryToHex(extensions.largeBlob.write);
                if (largeBlobValue) {
                    settings.largeBlobWrite = largeBlobValue;
                }
            }
        }
    }

    if (Array.isArray(publicKey.hints)) {
        settings.hints = publicKey.hints;
    }

    return { settings, fakeAllowCredentials: [] };
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
