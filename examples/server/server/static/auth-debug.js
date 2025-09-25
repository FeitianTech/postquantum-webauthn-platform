import {
    arrayBufferToHex,
    base64UrlToHex,
    bufferSourceToUint8Array,
    bytesToHex,
    hexToBase64Url,
} from './binary-utils.js';
import { extractHexFromJsonFormat } from './credential-utils.js';
import { state } from './state.js';

export function printRegistrationDebug(credential, createOptions, serverResponse) {
    const clientExtensions = credential.getClientExtensionResults
        ? credential.getClientExtensionResults()
        : (credential.clientExtensionResults || {});
    const serverData = serverResponse || {};

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
    if (credential.response && credential.response.clientDataJSON) {
        try {
            const clientData = JSON.parse(atob(credential.response.clientDataJSON));
            challengeHex = base64UrlToHex(clientData.challenge);
        } catch (e) {
            // ignore
        }
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

    const clientDataBuffer = credential?.response?.clientDataJSON
        ? bufferSourceToUint8Array(credential.response.clientDataJSON)
        : null;
    if (clientDataBuffer && clientDataBuffer.length) {
        const clientDataHex = bytesToHex(clientDataBuffer);
        console.log('clientDataJSON (hex):', clientDataHex);
        console.log('clientDataJSON (base64url):', hexToBase64Url(clientDataHex));
        if (state.utf8Decoder) {
            try {
                const clientDataText = state.utf8Decoder.decode(clientDataBuffer);
                if (clientDataText) {
                    console.log('clientDataJSON (text):', clientDataText);
                    try {
                        console.log('clientDataJSON (parsed):', JSON.parse(clientDataText));
                    } catch (parseError) {
                        console.warn('Unable to parse clientDataJSON text:', parseError);
                    }
                }
            } catch (decodeError) {
                console.warn('Unable to decode clientDataJSON bytes:', decodeError);
            }
        }
    }

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

    console.log('client extension results (client raw):', clientExtensions);
    if (serverData.clientExtensionResults) {
        console.log('client extension results (server normalized):', serverData.clientExtensionResults);
    }

    if (Array.isArray(serverData.algorithmsUsed)) {
        console.log('algorithms advertised to authenticator:', serverData.algorithmsUsed);
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
