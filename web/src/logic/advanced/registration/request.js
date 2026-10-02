// A registration's request (CredentialCreationOptions) and the form's settings
// it is built from, with no page: the settings' defaults, the request they
// build, what a request says the settings are, and the rules one setting's
// change applies to others. DOM-free: the form keeps the settings as data.
import { base64UrlToHex } from '../../shared/bytes.js';
import { extractHexFromJsonFormat, jsonBytes } from '../editor/byte-values.js';
import { getCredentialIdHex, getCredentialUserHandleHex } from '../../credentials/record-fields.js';
import { ALGORITHM_OPTIONS } from './algorithm-options.js';

/**
 * The registration form's settings: byte fields as hex text, numbers as text.
 * @typedef {object} RegistrationSettings
 * @property {string} userId
 * @property {string} userName
 * @property {string} displayName
 * @property {string} challenge
 * @property {string} timeout
 * @property {string} attachment
 * @property {string} residentKey
 * @property {string} userVerification
 * @property {string} attestation
 * @property {boolean} excludeCredentials
 * @property {string} fakeCredLength
 * @property {number[]} algorithms
 * @property {string[]} hints
 * @property {boolean} credProps
 * @property {boolean} minPinLength
 * @property {string} credProtect
 * @property {boolean} enforceCredProtect
 * @property {string} largeBlob
 * @property {boolean} prf
 * @property {string} prfFirst
 * @property {string} prfSecond
 */

/** @typedef {keyof RegistrationSettings} RegistrationField */

/**
 * What a request is built against: the relying party, the saved credentials and the fake IDs.
 * @typedef {object} RegistrationContext
 * @property {string} rpName
 * @property {string} hostname
 * @property {Array<Record<string, any>>} storedCredentials
 * @property {string[]} fakeExcludeCredentials
 */

/**
 * The settings the form starts from and a reset returns to, without the values
 * drawn at random (the user ID, name and display name, and the challenge).
 * Byte fields are hex text as typed; the timeout and the fake ID length are text.
 * @returns {Omit<RegistrationSettings, 'userId' | 'userName' | 'displayName' | 'challenge'>}
 */
export function registrationDefaults() {
    return {
        timeout: '90000',
        attachment: 'cross-platform',
        residentKey: 'discouraged',
        userVerification: 'preferred',
        attestation: 'direct',
        excludeCredentials: true,
        fakeCredLength: '128',
        algorithms: ALGORITHM_OPTIONS
            .filter(option => option.pqc || ['eddsa', 'es256', 'rs256'].includes(option.key))
            .map(option => option.alg),
        hints: [],
        credProps: true,
        minPinLength: false,
        credProtect: '',
        enforceCredProtect: true,
        largeBlob: '',
        prf: false,
        prfFirst: '',
        prfSecond: '',
    };
}

/** The timeout typed, in milliseconds; a field left empty (or not a number) is 90000. */
export function requestTimeout(text) {
    const timeout = parseInt(text);
    return Number.isNaN(timeout) ? 90000 : timeout;
}

// The saved credentials of this user (its user handle is the User ID) first,
// then the fake IDs, each as hex.
/**
 * @param {RegistrationSettings} settings
 * @param {Partial<RegistrationContext>} context
 */
function excludedCredentials(settings, { storedCredentials = [], fakeExcludeCredentials = [] }) {
    /** @type {Array<{ type: 'public-key', id: { $hex: string } }>} */
    const excludeList = [];
    const userIdHex = (settings.userId || '').toLowerCase();

    if (userIdHex && Array.isArray(storedCredentials) && storedCredentials.length > 0) {
        storedCredentials.forEach(cred => {
            const handleHex = getCredentialUserHandleHex(cred);
            const credentialIdHex = getCredentialIdHex(cred);

            if (handleHex && credentialIdHex && handleHex === userIdHex) {
                excludeList.push({
                    type: 'public-key',
                    id: {
                        $hex: credentialIdHex,
                    },
                });
            }
        });
    }

    fakeExcludeCredentials.forEach(hexValue => {
        if (!hexValue) {
            return;
        }

        excludeList.push({
            type: 'public-key',
            id: { $hex: hexValue },
        });
    });
    return excludeList;
}

/**
 * The request the settings build, `{ publicKey }`. context: rpName and
 * hostname (the relying party), storedCredentials (the list's records, whose
 * IDs of this user are excluded), fakeExcludeCredentials (hex).
 * @param {RegistrationSettings} settings
 * @param {Partial<RegistrationContext>} [context]
 * @returns {{ publicKey: Record<string, any> }}
 */
export function buildCreationOptions(settings, context = {}) {
    const publicKey = {
        rp: {
            name: context.rpName,
            id: context.hostname,
        },
        user: {
            id: jsonBytes(settings.userId),
            name: settings.userName,
            displayName: settings.displayName,
        },
        challenge: jsonBytes(settings.challenge),
        pubKeyCredParams: ALGORITHM_OPTIONS
            .filter(option => settings.algorithms.includes(option.alg))
            .map(option => ({ type: 'public-key', alg: option.alg })),
        timeout: requestTimeout(settings.timeout),
        authenticatorSelection: {},
        attestation: settings.attestation || 'direct',
        extensions: {},
    };

    const authenticatorAttachment = settings.attachment || 'cross-platform';
    if (authenticatorAttachment !== 'unspecified') {
        publicKey.authenticatorSelection.authenticatorAttachment = authenticatorAttachment;
    }

    const residentKeyValue = settings.residentKey || 'discouraged';
    publicKey.authenticatorSelection.residentKey = residentKeyValue;
    publicKey.authenticatorSelection.requireResidentKey = residentKeyValue === 'required';

    if (settings.userVerification) {
        publicKey.authenticatorSelection.userVerification = settings.userVerification;
    }

    publicKey.excludeCredentials = settings.excludeCredentials ? excludedCredentials(settings, context) : [];

    if (settings.credProps) {
        publicKey.extensions.credProps = true;
    }
    if (settings.minPinLength) {
        publicKey.extensions.minPinLength = true;
    }

    if (settings.credProtect) {
        publicKey.extensions.credentialProtectionPolicy = settings.credProtect;
        if (settings.enforceCredProtect) {
            publicKey.extensions.enforceCredentialProtectionPolicy = true;
        }
    }

    if (settings.largeBlob) {
        publicKey.extensions.largeBlob = { support: settings.largeBlob };
    }

    if (settings.prf && settings.prfFirst) {
        publicKey.extensions.prf = {
            eval: {
                first: jsonBytes(settings.prfFirst),
            },
        };
        if (settings.prfSecond) {
            publicKey.extensions.prf.eval.second = jsonBytes(settings.prfSecond);
        }
    }

    if (settings.hints.length > 0) {
        publicKey.hints = settings.hints;
    }

    return { publicKey };
}

/** A byte value the request holds, as hex: {"$hex"}, {"$base64url"}, {"$base64"} or base64url text. */
export function decodeJsonBinaryToHex(value) {
    if (!value) {
        return '';
    }

    if (value.$base64) {
        return base64UrlToHex(value.$base64);
    }
    if (value.$base64url) {
        return base64UrlToHex(value.$base64url);
    }
    if (value.$hex) {
        return value.$hex;
    }
    if (typeof value === 'string') {
        return base64UrlToHex(value);
    }

    return '';
}

/**
 * The settings a request says, over the ones the form has (`previous`): what it
 * gives replaces them, what it leaves out stays. Also the IDs its
 * excludeCredentials holds that are not saved credentials' (context:
 * storedCredentials), as the fake IDs, as they are spelled there.
 * @param {Record<string, any>} publicKey
 * @param {RegistrationSettings} previous
 * @param {{ storedCredentials?: Array<Record<string, any>> }} [context]
 * @returns {{ settings: RegistrationSettings, fakeExcludeCredentials: string[] }}
 */
export function readCreationOptions(publicKey, previous, context = {}) {
    const settings = { ...previous };

    if (publicKey.user) {
        if (publicKey.user.id) {
            const userIdValue = decodeJsonBinaryToHex(publicKey.user.id);
            if (userIdValue) {
                settings.userId = userIdValue;
            }
        }
        if (publicKey.user.name) {
            settings.userName = publicKey.user.name;
        }
        if (publicKey.user.displayName) {
            settings.displayName = publicKey.user.displayName;
        }
    }

    if (publicKey.challenge) {
        const challengeValue = decodeJsonBinaryToHex(publicKey.challenge);
        if (challengeValue) {
            settings.challenge = challengeValue;
        }
    }

    if (publicKey.timeout || publicKey.timeout === 0) {
        settings.timeout = publicKey.timeout.toString();
    }

    if (Object.hasOwn(publicKey, 'attestation')) {
        settings.attestation = publicKey.attestation || 'direct';
    }

    if (Array.isArray(publicKey.pubKeyCredParams)) {
        const chosen = new Set();
        publicKey.pubKeyCredParams.forEach(param => {
            if (param && Object.hasOwn(param, 'alg')) {
                const alg = typeof param.alg === 'string' ? Number.parseInt(param.alg, 10) : param.alg;
                chosen.add(alg);
            }
        });
        settings.algorithms = ALGORITHM_OPTIONS.filter(option => chosen.has(option.alg)).map(option => option.alg);
    }

    // No attachment is what Unspecified builds; one the form does not name reads as Cross-Platform.
    const selection = publicKey.authenticatorSelection;
    const attachmentValue = selection?.authenticatorAttachment;
    settings.attachment = attachmentValue === undefined
        ? 'unspecified'
        : ['platform', 'cross-platform', 'unspecified'].includes(attachmentValue) ? attachmentValue : 'cross-platform';
    if (selection) {
        settings.residentKey = selection.requireResidentKey === true
            ? 'required'
            : selection.residentKey || 'discouraged';
        if (Object.hasOwn(selection, 'userVerification')) {
            settings.userVerification = selection.userVerification || 'preferred';
        }
    }

    // An empty list is what excluding builds with nothing to exclude: it says nothing of the switch.
    const excludeArray = Array.isArray(publicKey.excludeCredentials) ? publicKey.excludeCredentials : [];
    if (excludeArray.length > 0) {
        settings.excludeCredentials = true;
    } else if (!Array.isArray(publicKey.excludeCredentials)) {
        settings.excludeCredentials = false;
    }
    const storedIds = new Set(
        (context.storedCredentials || [])
            .map(cred => (cred.credentialIdHex || getCredentialIdHex(cred) || '').toLowerCase())
            .filter(Boolean),
    );
    const fakeExcludeCredentials = [];
    excludeArray.forEach(entry => {
        if (!entry || typeof entry !== 'object') {
            return;
        }
        const hexValue = extractHexFromJsonFormat(entry.id);
        if (hexValue && !storedIds.has(hexValue.toLowerCase())) {
            fakeExcludeCredentials.push(hexValue);
        }
    });

    const extensions = publicKey.extensions || {};
    settings.credProps = !!extensions.credProps;
    settings.minPinLength = !!extensions.minPinLength;
    settings.credProtect = extensions.credentialProtectionPolicy || '';
    settings.enforceCredProtect = settings.credProtect ? !!extensions.enforceCredentialProtectionPolicy : true;
    settings.largeBlob = ['preferred', 'required'].includes(extensions.largeBlob?.support) ? extensions.largeBlob.support : '';

    // The evaluations the request asks for turn prf on; a request without them
    // turns it off, unless it was on with no first evaluation yet (which builds none).
    const prfFirstValue = decodeJsonBinaryToHex(extensions.prf?.eval?.first);
    if (prfFirstValue) {
        settings.prf = true;
        settings.prfFirst = prfFirstValue;
        settings.prfSecond = decodeJsonBinaryToHex(extensions.prf.eval.second);
    } else {
        settings.prf = previous.prf && !previous.prfFirst;
    }

    settings.hints = Array.isArray(publicKey.hints) ? publicKey.hints : [];

    return { settings, fakeExcludeCredentials };
}

/**
 * The settings after one of them changes, with the rules the form applies:
 * the user name is also the display name; a credProtect of Unspecified
 * enforces it; a resident key that is not required cannot ask for largeBlob;
 * an empty first prf evaluation empties the second.
 * @template {RegistrationField} F
 * @param {RegistrationSettings} settings
 * @param {F} field
 * @param {RegistrationSettings[F]} value
 * @returns {RegistrationSettings}
 */
export function changeRegistration(settings, field, value) {
    /** @type {RegistrationSettings} */
    const next = { ...settings, [field]: value };
    if (field === 'userName') {
        next.displayName = next.userName;
    }
    if (field === 'credProtect' && !value) {
        next.enforceCredProtect = true;
    }
    if (field === 'residentKey' && value !== 'required' && ['preferred', 'required'].includes(next.largeBlob)) {
        next.largeBlob = '';
    }
    if (field === 'prfFirst' && !value) {
        next.prfSecond = '';
    }
    return next;
}

/**
 * Which of the settings' fields the form cannot change as they stand.
 * @param {RegistrationSettings} settings
 * @returns {{ enforceCredProtect: boolean, prfSecond: boolean }}
 */
export function registrationControls(settings) {
    return {
        enforceCredProtect: !settings.credProtect,
        prfSecond: !settings.prfFirst,
    };
}
