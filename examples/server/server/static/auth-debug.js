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

export function logDebugGroup(label, callback, options = {}) {
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
        console.warn('Unable to normalise create() options for logging:', error);
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
        _logged: false,
    };
}

function logRegistrationRequestDetails(details) {
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
    logRegistrationRequestDetails(details);
    details._logged = true;
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

export function printRegistrationDebug(credential, createOptions, serverResponse, requestDetails) {
    const clientExtensions = credential.getClientExtensionResults
        ? credential.getClientExtensionResults()
        : (credential.clientExtensionResults || {});
    const serverData = serverResponse || {};
    const requestInfo = requestDetails && typeof requestDetails === 'object'
        ? requestDetails
        : collectRegistrationRequestDetails(createOptions);

    const started = startConsoleGroup('WebAuthn registration debug');
    console.log('Server response (full payload):', serverData);
    if (!requestInfo._logged) {
        logRegistrationRequestDetails(requestInfo);
        requestInfo._logged = true;
    }

    const clientGroup = startConsoleGroup('Authenticator response (client observations)');

    let credentialJson = null;
    if (credential) {
        console.log('Credential type:', credential.type || null);
        if (typeof credential.toJSON === 'function') {
            try {
                credentialJson = credential.toJSON();
                console.log('Credential (toJSON):', credentialJson);
            } catch (jsonError) {
                console.warn('Unable to serialize credential with toJSON():', jsonError);
            }
        }
    }

    const rawIdBytes = bufferSourceToUint8Array(credential?.rawId);
    const rawIdHex = rawIdBytes ? bytesToHex(rawIdBytes) : '';
    if (rawIdHex) {
        console.log('credential.rawId (hex):', rawIdHex);
        console.log('credential.rawId (base64url):', hexToBase64Url(rawIdHex));
        console.log('credential.rawId length (bytes):', rawIdBytes.length);
    }

    const clientDataDecoded = decodeClientData(credential);

    const residentKey = clientExtensions.credProps?.rk || serverData.actualResidentKey || false;
    console.log('Resident key:', residentKey);

    const attestationFormat = serverData.attestationFormat || 'direct';
    const attestationRetrieved = attestationFormat !== 'none';
    console.log('Attestation (retrieve or not, plus the format):', `${attestationRetrieved}, ${attestationFormat}`);

    const excludeCredentials = serverData.excludeCredentialsUsed || false;
    console.log('exclude credentials:', excludeCredentials);

    const fakeCredLength = window.lastFakeCredLength || 0;
    console.log('fake credential id length:', fakeCredLength);

    let challengeHex = '';
    if (clientDataDecoded.parsed?.challenge) {
        challengeHex = base64UrlToHex(clientDataDecoded.parsed.challenge);
    }
    console.log('challenge hex code:', challengeHex);

    const pubKeyCredParams = serverData.algorithmsUsed || [];
    console.log('pubkeycredparam used:', pubKeyCredParams);

    const hints = serverData.hintsUsed || [];
    console.log('hints:', hints);

    const credPropsRequested = clientExtensions.credProps !== undefined;
    console.log('credprops (requested or not):', credPropsRequested);

    const minPinLengthRequested = clientExtensions.minPinLength !== undefined;
    console.log('minpinlength (requested or not):', minPinLengthRequested);

    const credProtectSetting = serverData.credProtectUsed ?? 'none';
    const credProtectLabelMap = {
        1: 'userVerificationOptional',
        2: 'userVerificationOptionalWithCredentialIDList',
        3: 'userVerificationRequired',
        userVerificationOptionalWithCredentialIDList: 'userVerificationOptionalWithCredentialIDList',
        userVerificationOptionalWithCredentialIdList: 'userVerificationOptionalWithCredentialIDList',
    };
    const credProtectDisplay = credProtectLabelMap[credProtectSetting] || credProtectSetting || 'none';
    console.log('credprotect setting:', credProtectDisplay);

    const enforceCredProtect = serverData.enforceCredProtectUsed || false;
    console.log('enforce credprotect:', enforceCredProtect);

    const largeBlob = clientExtensions.largeBlob?.supported ?? 'none';
    console.log('largeblob:', largeBlob);

    const prfEnabled = clientExtensions.prf !== undefined;
    console.log('prf:', prfEnabled);

    const prfFirstHex = clientExtensions.prf?.results?.first !== undefined
        ? extractHexFromJsonFormat(clientExtensions.prf.results.first)
        : '';
    console.log('prf eval first hex code:', prfFirstHex);

    const prfSecondHex = clientExtensions.prf?.results?.second !== undefined
        ? extractHexFromJsonFormat(clientExtensions.prf.results.second)
        : '';
    console.log('prf eval second hex code:', prfSecondHex);

    const attestationObjectBuffer = credential?.response?.attestationObject;
    if (attestationObjectBuffer) {
        const attestationObjectHex = arrayBufferToHex(attestationObjectBuffer);
        if (attestationObjectHex) {
            console.log('attestation object (hex):', attestationObjectHex);
            console.log('attestation object (base64url):', hexToBase64Url(attestationObjectHex));
        }
    }

    if (clientDataDecoded.hex) {
        console.log('clientDataJSON (hex):', clientDataDecoded.hex);
        console.log('clientDataJSON (base64url):', clientDataDecoded.base64url);
    }
    if (clientDataDecoded.text) {
        console.log('clientDataJSON (text):', clientDataDecoded.text);
    }
    if (clientDataDecoded.parsed) {
        console.log('clientDataJSON (parsed):', clientDataDecoded.parsed);
    }

    if (credentialJson?.clientExtensionResults) {
        console.log('client extension results (submitted payload):', credentialJson.clientExtensionResults);
    }
    console.log('client extension results (client raw):', clientExtensions);
    if (credential?.authenticatorAttachment !== undefined) {
        console.log('authenticator attachment (client):', credential.authenticatorAttachment);
    }
    if (credential?.response) {
        console.log('credential.response (raw object):', credential.response);
        const responseSnapshot = convertForLogging({
            attestationObject: credential.response.attestationObject,
            clientDataJSON: credential.response.clientDataJSON,
            transports: typeof credential.response.getTransports === 'function'
                ? (() => {
                    try {
                        return credential.response.getTransports();
                    } catch (err) {
                        console.warn('Unable to read transports from credential response:', err);
                        return undefined;
                    }
                })()
                : undefined,
        });
        console.log('credential.response (sanitized):', responseSnapshot);
    }
    endConsoleGroup(clientGroup);

    const serverGroup = startConsoleGroup('Server registration analysis');

    if (serverData.clientDataJSON) {
        console.log('clientDataJSON (from server):', serverData.clientDataJSON);
    }
    if (serverData.clientDataJSONDecoded) {
        console.log('clientDataJSON (decoded from server):', serverData.clientDataJSONDecoded);
    }

    if (serverData.attestationFormat) {
        console.log('attestation format:', serverData.attestationFormat);
    }
    if (serverData.attestationObject) {
        console.log('attestation object (from server):', serverData.attestationObject);
    }
    if (serverData.attestationObjectDecoded) {
        console.log('attestation object (decoded from server):', serverData.attestationObjectDecoded);
    }
    if (serverData.attestationStatement) {
        console.log('attestation statement:', serverData.attestationStatement);
    }
    if (serverData.attestationSummary) {
        console.log('attestation summary (server):', serverData.attestationSummary);
    }
    if (serverData.attestationChecks) {
        console.log('attestation checks (server):', serverData.attestationChecks);
    }

    if (serverData.clientExtensionResults) {
        console.log('client extension results (server normalized):', serverData.clientExtensionResults);
    }

    if (Array.isArray(serverData.algorithmsUsed)) {
        console.log('algorithms advertised to authenticator:', serverData.algorithmsUsed);
    }

    if (serverData.actualResidentKey !== undefined) {
        console.log('resident key (flags from server):', serverData.actualResidentKey);
    }

    if (serverData.attestationSignatureValid !== undefined) {
        console.log('attestation signature valid (server):', serverData.attestationSignatureValid);
    }
    if (serverData.attestationRootValid !== undefined) {
        console.log('attestation root valid (server):', serverData.attestationRootValid);
    }
    if (serverData.attestationRpIdHashValid !== undefined) {
        console.log('attestation RP ID hash valid (server):', serverData.attestationRpIdHashValid);
    }
    if (serverData.attestationAaguidMatch !== undefined) {
        console.log('attestation AAGUID match (server):', serverData.attestationAaguidMatch);
    }

    if (serverData.credentialIdHex) {
        console.log('credential ID (hex):', serverData.credentialIdHex);
    }
    if (serverData.credentialIdBase64Url) {
        console.log('credential ID (base64url):', serverData.credentialIdBase64Url);
    }

    if (serverData.credentialPublicKeyCose) {
        console.log('credential public key (COSE):', serverData.credentialPublicKeyCose);
    }
    if (serverData.credentialPublicKeyBytes) {
        console.log('credential public key (raw base64url):', serverData.credentialPublicKeyBytes);
    }
    if (serverData.credentialPublicKeyAlgorithm !== undefined) {
        console.log('credential public key algorithm (COSE):', serverData.credentialPublicKeyAlgorithm);
    }
    if (serverData.credentialPublicKeyAlgorithmLabel) {
        console.log('credential public key algorithm (label):', serverData.credentialPublicKeyAlgorithmLabel);
    }
    if (serverData.credentialPublicKeyType !== undefined) {
        console.log('credential public key type (COSE kty):', serverData.credentialPublicKeyType);
        const keyTypeLabel = describeKeyTypeLabel(serverData.credentialPublicKeyType);
        if (keyTypeLabel) {
            console.log('credential public key type (label):', keyTypeLabel);
        }
    }

    if (serverData.authenticatorDataBreakdown) {
        const breakdown = serverData.authenticatorDataBreakdown;
        if (breakdown.rawHex) {
            console.log('authenticator data (hex):', breakdown.rawHex);
        }
        console.log('authenticator data breakdown:', breakdown);
        if (breakdown.attestedCredentialData?.credentialPublicKeyCose && !serverData.credentialPublicKeyCose) {
            console.log('credential public key (COSE from breakdown):', breakdown.attestedCredentialData.credentialPublicKeyCose);
        }
    } else if (serverData?.relyingParty?.registrationData?.authenticatorData) {
        console.log('authenticator data (hex from relying party):', serverData.relyingParty.registrationData.authenticatorData);
    }

    if (serverData.relyingParty) {
        console.log('relying party summary:', serverData.relyingParty);
    }

    if (serverData.status) {
        console.log('server status:', serverData.status);
    }

    if (serverData.registration_response) {
        console.log('registration response (server echo):', serverData.registration_response);
    }

    if (serverData.originalEditorPayload) {
        console.log('original JSON editor payload (server view):', serverData.originalEditorPayload);
    }
    if (serverData.originalPublicKeyOptions) {
        console.log('original publicKey options (server view):', serverData.originalPublicKeyOptions);
    }
    if (serverData.credentialResponseEcho) {
        console.log('credential response echo (server view):', serverData.credentialResponseEcho);
    }
    if (serverData.beginDebugContext) {
        console.log('server begin() debug context:', serverData.beginDebugContext);
    }
    if (serverData.authenticatorAttachmentValidation) {
        console.log('authenticator attachment validation:', serverData.authenticatorAttachmentValidation);
    }
    if (serverData.postQuantum) {
        console.log('post-quantum diagnostics:', serverData.postQuantum);
    }

    endConsoleGroup(serverGroup);
    endConsoleGroup(started);

    if (typeof window !== 'undefined') {
        window.__webauthnDebug = window.__webauthnDebug || {};
        const credentialSummary = credentialJson ? { ...credentialJson } : {};
        if (credential) {
            credentialSummary.rawIdHex = rawIdHex || null;
            credentialSummary.rawIdBase64Url = rawIdHex ? hexToBase64Url(rawIdHex) : null;
            credentialSummary.response = credential?.response
                ? convertForLogging({
                    attestationObject: credential.response.attestationObject,
                    clientDataJSON: credential.response.clientDataJSON,
                    transports: typeof credential.response.getTransports === 'function'
                        ? (() => {
                            try {
                                return credential.response.getTransports();
                            } catch (err) {
                                return undefined;
                            }
                        })()
                        : undefined,
                })
                : null;
        }
        window.__webauthnDebug.lastRegistrationDebug = {
            timestamp: new Date().toISOString(),
            request: requestInfo,
            credential: credentialSummary,
            clientExtensions: convertForLogging(clientExtensions),
            server: serverData,
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
