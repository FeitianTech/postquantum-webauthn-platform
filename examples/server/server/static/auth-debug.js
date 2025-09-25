import {
    arrayBufferToHex,
    base64UrlToHex,
    bufferSourceToUint8Array,
    bytesToHex,
    hexToBase64Url,
} from './binary-utils.js';
import { COSE_ALGORITHM_LABELS, COSE_KEY_TYPE_LABELS } from './constants.js';
import { extractHexFromJsonFormat } from './credential-utils.js';
import { state } from './state.js';

function startConsoleGroup(label, collapsed = false) {
    if (collapsed && typeof console.groupCollapsed === 'function') {
        console.groupCollapsed(label);
        return true;
    }
    if (typeof console.group === 'function') {
        console.group(label);
        return true;
    }
    console.log(label);
    return false;
}

function endConsoleGroup(started) {
    if (started && typeof console.groupEnd === 'function') {
        console.groupEnd();
    }
}

function shouldLogVerbose(options = {}) {
    if (options && typeof options === 'object' && options.force) {
        return true;
    }
    if (state?.verboseConsoleLogging) {
        return true;
    }
    if (typeof window !== 'undefined' && window.__webauthnVerboseLogging === true) {
        return true;
    }
    return false;
}

export function logDebugGroup(label, callback, options = {}) {
    if (!shouldLogVerbose(options)) {
        return;
    }

    const started = startConsoleGroup(label, options?.collapsed);
    try {
        callback();
    } catch (error) {
        console.error('Error while logging debug group:', error);
    } finally {
        endConsoleGroup(started);
    }
}

function describeAlgorithmLabel(alg) {
    if (alg === undefined || alg === null) {
        return null;
    }
    const key = String(alg);
    return COSE_ALGORITHM_LABELS[key] || `COSE ${alg}`;
}

function describeKeyTypeLabel(kty) {
    if (kty === undefined || kty === null) {
        return null;
    }
    const key = String(kty);
    return COSE_KEY_TYPE_LABELS[key] || `kty ${kty}`;
}

function convertForLogging(value) {
    if (value == null) {
        return value;
    }
    if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
        const hex = arrayBufferToHex(value);
        return {
            $hex: hex,
            $base64url: hexToBase64Url(hex),
            $byteLength: bufferSourceToUint8Array(value)?.length || 0,
        };
    }
    if (Array.isArray(value)) {
        return value.map((item) => convertForLogging(item));
    }
    if (typeof value === 'object' && value.constructor === Object) {
        const normalized = {};
        for (const [key, val] of Object.entries(value)) {
            normalized[key] = convertForLogging(val);
        }
        return normalized;
    }
    return value;
}

function collectRegistrationRequestDetails(createOptions) {
    const publicKey = (createOptions && createOptions.publicKey) || {};

    const challengeBytes = bufferSourceToUint8Array(publicKey.challenge);
    const challengeHex = challengeBytes ? bytesToHex(challengeBytes) : '';

    const userEntity = publicKey.user || {};
    const userIdBytes = bufferSourceToUint8Array(userEntity.id);
    const userIdHex = userIdBytes ? bytesToHex(userIdBytes) : '';

    const excludeCredentialsRaw = Array.isArray(publicKey.excludeCredentials)
        ? publicKey.excludeCredentials
        : [];
    const excludeCredentials = excludeCredentialsRaw.map((descriptor) => {
        const idBytes = bufferSourceToUint8Array(descriptor && descriptor.id);
        const idHex = idBytes ? bytesToHex(idBytes) : '';
        return {
            type: descriptor?.type || 'public-key',
            transports: descriptor?.transports || null,
            idHex: idHex || null,
            idBase64Url: idHex ? hexToBase64Url(idHex) : null,
            idLength: idBytes ? idBytes.length : 0,
        };
    });

    const pubKeyCredParamsRaw = Array.isArray(publicKey.pubKeyCredParams)
        ? publicKey.pubKeyCredParams
        : [];
    const pubKeyCredParams = pubKeyCredParamsRaw.map((param) => {
        const alg = param?.alg ?? param;
        const type = param?.type ?? 'public-key';
        return {
            type,
            alg,
            label: describeAlgorithmLabel(alg),
        };
    });

    const authenticatorSelection = publicKey.authenticatorSelection || {};
    const extensions = publicKey.extensions ? convertForLogging(publicKey.extensions) : null;
    const hints = Array.isArray(publicKey.hints) ? publicKey.hints : [];

    const timeout = publicKey.timeout ?? createOptions?.timeout ?? null;
    const attestation = publicKey.attestation ?? createOptions?.attestation ?? 'none';

    let createOptionsForLogging = null;
    try {
        createOptionsForLogging = convertForLogging(createOptions);
    } catch (error) {
        if (shouldLogVerbose()) {
            console.warn('Unable to normalise create() options for logging:', error);
        }
    }

    return {
        rp: publicKey.rp || null,
        user: {
            name: userEntity?.name || null,
            displayName: userEntity?.displayName || null,
            idHex: userIdHex || null,
            idBase64Url: userIdHex ? hexToBase64Url(userIdHex) : null,
            idLength: userIdBytes ? userIdBytes.length : 0,
        },
        challengeHex: challengeHex || null,
        challengeBase64Url: challengeHex ? hexToBase64Url(challengeHex) : null,
        timeout,
        attestation,
        pubKeyCredParams,
        authenticatorSelection,
        hints,
        extensions,
        excludeCredentials,
        rawCreateOptions: createOptions,
        rawCreateOptionsForLogging: createOptionsForLogging,
    };
}

function logRegistrationRequestDetails(details) {
    if (!shouldLogVerbose()) {
        return;
    }

    const started = startConsoleGroup('WebAuthn registration request (browser → authenticator)');
    if (details?.rp) {
        console.log('RP ID:', details.rp.id || null);
        console.log('RP name:', details.rp.name || null);
    }
    if (details?.user) {
        console.log('User name:', details.user.name || null);
        console.log('User displayName:', details.user.displayName || null);
        console.log('User ID length (bytes):', details.user.idLength || 0);
        console.log('User ID (hex):', details.user.idHex || '');
        console.log('User ID (base64url):', details.user.idBase64Url || '');
    }
    console.log('Requested challenge (hex):', details?.challengeHex || '');
    console.log('Requested challenge (base64url):', details?.challengeBase64Url || '');
    console.log('Requested timeout (ms):', details?.timeout ?? null);
    console.log('Requested attestation:', details?.attestation || 'none');
    if (details?.authenticatorSelection) {
        console.log('Requested authenticatorSelection:', details.authenticatorSelection);
    }
    console.log('Requested hints:', details?.hints || []);
    console.log('Requested pubKeyCredParams:', details?.pubKeyCredParams || []);
    console.log('Requested excludeCredentials:', details?.excludeCredentials || []);
    if (details?.extensions) {
        console.log('Requested extensions:', details.extensions);
    }
    console.log('fake credential id length:', window.lastFakeCredLength || 0);
    if (details?.rawCreateOptionsForLogging) {
        console.log('navigator.credentials.create options (sanitized):', details.rawCreateOptionsForLogging);
    }
    if (details?.rawCreateOptions) {
        console.log('navigator.credentials.create options (raw reference):', details.rawCreateOptions);
    }
    endConsoleGroup(started);
}

export function printRegistrationRequestDebug(createOptions) {
    const details = collectRegistrationRequestDetails(createOptions);
    if (shouldLogVerbose()) {
        logRegistrationRequestDetails(details);
    }
    if (typeof window !== 'undefined') {
        window.__webauthnDebug = window.__webauthnDebug || {};
        const summary = { ...details };
        if (Object.prototype.hasOwnProperty.call(summary, 'rawCreateOptions')) {
            delete summary.rawCreateOptions;
        }
        window.__webauthnDebug.lastRegistrationRequest = {
            timestamp: new Date().toISOString(),
            summary,
            rawCreateOptions: details.rawCreateOptions,
            rawCreateOptionsForLogging: details.rawCreateOptionsForLogging,
        };
    }
    return details;
}

function decodeClientData(credential) {
    const buffer = credential?.response?.clientDataJSON
        ? bufferSourceToUint8Array(credential.response.clientDataJSON)
        : null;
    if (!buffer || !buffer.length) {
        return { buffer: null, hex: '', base64url: '', text: '', parsed: null };
    }
    const hex = bytesToHex(buffer);
    let text = '';
    if (state.utf8Decoder) {
        try {
            text = state.utf8Decoder.decode(buffer);
        } catch (err) {
            console.warn('Unable to decode clientDataJSON bytes with shared decoder:', err);
        }
    }
    if (!text && typeof TextDecoder !== 'undefined') {
        try {
            const decoder = new TextDecoder('utf-8', { fatal: false });
            text = decoder.decode(buffer);
        } catch (err) {
            console.warn('Unable to decode clientDataJSON bytes with TextDecoder:', err);
        }
    }
    let parsed = null;
    if (text) {
        try {
            parsed = JSON.parse(text);
        } catch (parseError) {
            console.warn('Unable to parse clientDataJSON text:', parseError);
        }
    }
    return {
        buffer,
        hex,
        base64url: hexToBase64Url(hex),
        text,
        parsed,
    };
}


function hasContent(value) {
    if (value === null || value === undefined) {
        return false;
    }
    if (typeof value === 'string') {
        return value.length > 0;
    }
    if (Array.isArray(value)) {
        return value.length > 0;
    }
    if (typeof value === 'object') {
        return Object.keys(value).length > 0;
    }
    return true;
}

function normaliseAttestationObjectRaw(credential, serverData) {
    const fromServer = serverData?.attestationObject;
    if (typeof fromServer === 'string' && fromServer.length) {
        const normalized = { base64url: fromServer };
        try {
            normalized.hex = base64UrlToHex(fromServer);
        } catch (error) {
            // ignore decode errors for malformed inputs
        }
        return normalized;
    }

    const attestationBuffer = credential?.response?.attestationObject;
    if (attestationBuffer) {
        const hex = arrayBufferToHex(attestationBuffer);
        return {
            base64url: hexToBase64Url(hex),
            hex,
        };
    }

    return null;
}

function buildAuthenticatorDataSummary(serverData) {
    const breakdown = serverData?.authenticatorDataBreakdown;
    if (!breakdown || typeof breakdown !== 'object') {
        return null;
    }

    const summary = {};
    if (typeof breakdown.rawHex === 'string' && breakdown.rawHex.length) {
        summary.rawHex = breakdown.rawHex;
    }

    if (breakdown.rpIdHashHex || breakdown.rpIdHashBase64Url) {
        summary.rpIdHash = {};
        if (typeof breakdown.rpIdHashHex === 'string' && breakdown.rpIdHashHex.length) {
            summary.rpIdHash.hex = breakdown.rpIdHashHex;
        }
        if (typeof breakdown.rpIdHashBase64Url === 'string' && breakdown.rpIdHashBase64Url.length) {
            summary.rpIdHash.base64url = breakdown.rpIdHashBase64Url;
        }
    }

    if (breakdown.flags !== undefined && breakdown.flags !== null) {
        summary.flags = breakdown.flags;
    }

    if (breakdown.signCount !== undefined && breakdown.signCount !== null) {
        summary.signCount = breakdown.signCount;
    }

    if (breakdown.attestedCredentialData && typeof breakdown.attestedCredentialData === 'object') {
        const attestedSource = breakdown.attestedCredentialData;
        const attested = {};

        if (attestedSource.aaguidHex) {
            attested.aaguidHex = attestedSource.aaguidHex;
        }
        if (attestedSource.aaguidGuid) {
            attested.aaguidGuid = attestedSource.aaguidGuid;
        }
        if (attestedSource.aaguidBase64Url) {
            attested.aaguidBase64Url = attestedSource.aaguidBase64Url;
        }
        if (attestedSource.credentialIdHex) {
            attested.credentialIdHex = attestedSource.credentialIdHex;
        }
        if (attestedSource.credentialIdBase64Url) {
            attested.credentialIdBase64Url = attestedSource.credentialIdBase64Url;
        }
        if (attestedSource.credentialIdLength !== undefined && attestedSource.credentialIdLength !== null) {
            attested.credentialIdLength = attestedSource.credentialIdLength;
        }
        if (attestedSource.credentialPublicKeyCose) {
            attested.credentialPublicKeyCose = attestedSource.credentialPublicKeyCose;
        }
        if (attestedSource.credentialPublicKeyBytes) {
            attested.credentialPublicKeyBytes = attestedSource.credentialPublicKeyBytes;
        }
        if (attestedSource.credentialPublicKeyAlgorithm !== undefined && attestedSource.credentialPublicKeyAlgorithm !== null) {
            attested.credentialPublicKeyAlgorithm = attestedSource.credentialPublicKeyAlgorithm;
        }
        if (attestedSource.credentialPublicKeyAlgorithmLabel) {
            attested.credentialPublicKeyAlgorithmLabel = attestedSource.credentialPublicKeyAlgorithmLabel;
        }
        if (attestedSource.credentialPublicKeyType !== undefined && attestedSource.credentialPublicKeyType !== null) {
            attested.credentialPublicKeyType = attestedSource.credentialPublicKeyType;
        }
        if (attestedSource.extensions) {
            attested.extensions = attestedSource.extensions;
        }

        if (hasContent(attested)) {
            summary.attestedCredentialData = attested;
        }
    }

    if (breakdown.extensions) {
        summary.extensions = breakdown.extensions;
    }

    return hasContent(summary) ? summary : null;
}

function buildAttestationObjectSummary(credential, serverData, authenticatorDataSummary) {
    const summary = {};
    const fmt = serverData?.attestationFormat;
    if (fmt !== undefined && fmt !== null && fmt !== '') {
        summary.fmt = fmt;
    }

    const authDataHex = authenticatorDataSummary?.rawHex
        || (typeof serverData?.authenticatorDataBreakdown?.rawHex === 'string' ? serverData.authenticatorDataBreakdown.rawHex : null);
    if (typeof authDataHex === 'string' && authDataHex.length) {
        summary.authData = {
            hex: authDataHex,
            base64url: hexToBase64Url(authDataHex),
        };
    }

    const raw = normaliseAttestationObjectRaw(credential, serverData);
    if (raw) {
        summary.raw = raw;
    }

    return hasContent(summary) ? summary : null;
}

function buildAttestationStatementSummary(serverData) {
    const attStmt = serverData?.attestationStatement;
    if (attStmt && typeof attStmt === 'object') {
        return Object.keys(attStmt).length ? attStmt : null;
    }
    if (attStmt !== undefined && attStmt !== null) {
        return attStmt;
    }

    const attestationObjectDecoded = serverData?.attestationObjectDecoded;
    if (attestationObjectDecoded && typeof attestationObjectDecoded === 'object' && attestationObjectDecoded.attStmt) {
        return attestationObjectDecoded.attStmt;
    }

    return null;
}

function buildCredentialPublicKeySummary(serverData, authenticatorDataSummary) {
    const attested = authenticatorDataSummary?.attestedCredentialData;
    const summary = {};

    const cose = serverData?.credentialPublicKeyCose || attested?.credentialPublicKeyCose;
    if (cose) {
        summary.cose = cose;
    }

    const bytes = serverData?.credentialPublicKeyBytes || attested?.credentialPublicKeyBytes;
    if (bytes) {
        summary.bytes = bytes;
    }

    const algorithm = serverData?.credentialPublicKeyAlgorithm ?? attested?.credentialPublicKeyAlgorithm;
    if (algorithm !== undefined && algorithm !== null) {
        summary.algorithm = algorithm;
    }

    const algorithmLabel = serverData?.credentialPublicKeyAlgorithmLabel
        ?? attested?.credentialPublicKeyAlgorithmLabel
        ?? serverData?.postQuantum?.credentialAlgorithmLabel;
    if (algorithmLabel) {
        summary.algorithmLabel = algorithmLabel;
    }

    const keyType = serverData?.credentialPublicKeyType ?? attested?.credentialPublicKeyType;
    if (keyType !== undefined && keyType !== null) {
        summary.keyType = keyType;
    }

    return hasContent(summary) ? summary : null;
}

function logRegistrationValue(label, value) {
    if (value === undefined || value === null) {
        return;
    }
    if (typeof value === 'object' && Object.keys(value).length === 0) {
        return;
    }
    console.log(label, value);
}

function extractCredentialDetails(credential) {
    if (!credential || typeof credential !== 'object') {
        return { summary: null, extensions: null };
    }

    let summary = null;
    if (typeof credential.toJSON === 'function') {
        try {
            summary = credential.toJSON();
        } catch (error) {
            summary = null;
        }
    }

    const clientExtensions = typeof credential.getClientExtensionResults === 'function'
        ? credential.getClientExtensionResults()
        : (credential.clientExtensionResults || {});

    let extensionsSummary = null;
    try {
        extensionsSummary = convertForLogging(clientExtensions);
    } catch (error) {
        extensionsSummary = clientExtensions;
    }

    const rawIdBytes = bufferSourceToUint8Array(credential.rawId);
    if (rawIdBytes && rawIdBytes.length) {
        const rawIdHex = bytesToHex(rawIdBytes);
        const baseSummary = summary && typeof summary === 'object' ? { ...summary } : {};
        baseSummary.rawIdHex = rawIdHex;
        baseSummary.rawIdBase64Url = hexToBase64Url(rawIdHex);
        baseSummary.rawIdLength = rawIdBytes.length;
        summary = baseSummary;
    }

    return {
        summary: summary && Object.keys(summary).length ? summary : null,
        extensions: extensionsSummary && hasContent(extensionsSummary) ? extensionsSummary : null,
    };
}

function logAuthenticatorDataDetails(authenticatorDataSummary) {
    if (!authenticatorDataSummary || typeof authenticatorDataSummary !== 'object') {
        return;
    }

    logRegistrationValue('Authenticator data (hex)', authenticatorDataSummary.rawHex);

    if (authenticatorDataSummary.rpIdHash) {
        const rpHash = authenticatorDataSummary.rpIdHash;
        const displayValue = rpHash.base64url || rpHash.hex || rpHash;
        logRegistrationValue('Authenticator data rpIdHash', displayValue);
    }

    if (authenticatorDataSummary.flags && typeof authenticatorDataSummary.flags === 'object') {
        const { value, ...rest } = authenticatorDataSummary.flags;
        logRegistrationValue('Authenticator data flags', rest);
        if (value !== undefined) {
            logRegistrationValue('Authenticator data flags (value)', value);
        }
    }

    if (authenticatorDataSummary.signCount !== undefined) {
        logRegistrationValue('Authenticator data signCount', authenticatorDataSummary.signCount);
    }

    const attested = authenticatorDataSummary.attestedCredentialData;
    if (attested && typeof attested === 'object') {
        logRegistrationValue('Credential AAGUID (hex)', attested.aaguidHex || attested.aaguidGuid || attested.aaguidBase64Url);
        logRegistrationValue('Credential ID (hex)', attested.credentialIdHex);
        logRegistrationValue('Credential ID (base64url)', attested.credentialIdBase64Url);
        if (attested.credentialIdLength !== undefined) {
            logRegistrationValue('Credential ID length', attested.credentialIdLength);
        }
    }
}

function logAttestationObjectDetails(attestationObjectSummary) {
    if (!attestationObjectSummary || typeof attestationObjectSummary !== 'object') {
        return;
    }
    logRegistrationValue('Attestation format', attestationObjectSummary.fmt);
    if (attestationObjectSummary.raw && typeof attestationObjectSummary.raw === 'object') {
        logRegistrationValue('Attestation object (base64url)', attestationObjectSummary.raw.base64url);
        logRegistrationValue('Attestation object (hex)', attestationObjectSummary.raw.hex);
    }
    if (attestationObjectSummary.authData && typeof attestationObjectSummary.authData === 'object') {
        logRegistrationValue('Authenticator data (base64url)', attestationObjectSummary.authData.base64url);
        logRegistrationValue('Authenticator data (hex copy)', attestationObjectSummary.authData.hex);
    }
}

function logAttestationStatementDetails(attestationStatementSummary) {
    if (!attestationStatementSummary) {
        return;
    }
    logRegistrationValue('Attestation statement', attestationStatementSummary);
}

function logCredentialPublicKeyDetails(credentialPublicKeySummary) {
    if (!credentialPublicKeySummary || typeof credentialPublicKeySummary !== 'object') {
        return;
    }

    if (credentialPublicKeySummary.cose) {
        logRegistrationValue('Credential public key (COSE)', credentialPublicKeySummary.cose);
    }
    if (credentialPublicKeySummary.bytes) {
        logRegistrationValue('Credential public key (bytes)', credentialPublicKeySummary.bytes);
    }
    if (credentialPublicKeySummary.algorithm !== undefined) {
        const label = credentialPublicKeySummary.algorithmLabel
            ? `${credentialPublicKeySummary.algorithm} (${credentialPublicKeySummary.algorithmLabel})`
            : credentialPublicKeySummary.algorithm;
        logRegistrationValue('Credential public key algorithm', label);
    } else if (credentialPublicKeySummary.algorithmLabel) {
        logRegistrationValue('Credential public key algorithm', credentialPublicKeySummary.algorithmLabel);
    }
    if (credentialPublicKeySummary.keyType !== undefined) {
        logRegistrationValue('Credential public key type', credentialPublicKeySummary.keyType);
    }
}

export function printRegistrationDebug(credential, createOptions, serverResponse, requestDetails) {
    const serverData = serverResponse || {};
    const authenticatorDataSummary = buildAuthenticatorDataSummary(serverData);
    const attestationObjectSummary = buildAttestationObjectSummary(credential, serverData, authenticatorDataSummary);
    const attestationStatementSummary = buildAttestationStatementSummary(serverData);
    const credentialPublicKeySummary = buildCredentialPublicKeySummary(serverData, authenticatorDataSummary);

    logAttestationObjectDetails(attestationObjectSummary);
    logAuthenticatorDataDetails(authenticatorDataSummary);
    logAttestationStatementDetails(attestationStatementSummary);
    logCredentialPublicKeyDetails(credentialPublicKeySummary);

    const requestInfo = requestDetails && typeof requestDetails === 'object'
        ? requestDetails
        : (createOptions ? collectRegistrationRequestDetails(createOptions) : null);

    const { summary: credentialSummary, extensions: clientExtensionsSummary } = extractCredentialDetails(credential);

    if (typeof window !== 'undefined') {
        window.__webauthnDebug = window.__webauthnDebug || {};
        window.__webauthnDebug.lastRegistrationDebug = {
            timestamp: new Date().toISOString(),
            request: requestInfo || null,
            credential: credentialSummary,
            clientExtensions: clientExtensionsSummary,
            server: serverData,
            attestationObject: attestationObjectSummary,
            authenticatorData: authenticatorDataSummary,
            attestationStatement: attestationStatementSummary,
            credentialPublicKey: credentialPublicKeySummary,
        };
    }
}

export function printAuthenticationDebug(assertion, requestOptions, serverResponse) {
    const clientExtensions = assertion.getClientExtensionResults
        ? assertion.getClientExtensionResults()
        : (assertion.clientExtensionResults || {});
    const serverData = serverResponse || {};

    const fakeCredLength = window.lastFakeCredLength || 0;
    console.log('Fake credential ID length:', fakeCredLength);

    let challengeHex = '';
    if (assertion.response && assertion.response.clientDataJSON) {
        try {
            const clientData = JSON.parse(atob(assertion.response.clientDataJSON));
            challengeHex = base64UrlToHex(clientData.challenge);
        } catch (e) {
            // ignore
        }
    }
    console.log('challenge hex code:', challengeHex);

    const hints = serverData.hintsUsed || [];
    console.log('hints:', hints);

    const largeBlobRead = clientExtensions.largeBlob?.blob !== undefined;
    const largeBlobWrite = clientExtensions.largeBlob?.written !== undefined;
    const largeBlobType = largeBlobWrite ? 'write' : (largeBlobRead ? 'read' : 'none');
    console.log('largeblob:', largeBlobType);

    const largeBlobWriteHex = clientExtensions.largeBlob?.blob !== undefined
        ? extractHexFromJsonFormat(clientExtensions.largeBlob.blob)
        : '';
    console.log('largeblob write hex code:', largeBlobWriteHex);

    const prfFirstHex = clientExtensions.prf?.results?.first !== undefined
        ? extractHexFromJsonFormat(clientExtensions.prf.results.first)
        : '';
    console.log('prf eval first hex code:', prfFirstHex);

    const prfSecondHex = clientExtensions.prf?.results?.second !== undefined
        ? extractHexFromJsonFormat(clientExtensions.prf.results.second)
        : '';
    console.log('prf eval second hex code:', prfSecondHex);
}

export { convertForLogging };
