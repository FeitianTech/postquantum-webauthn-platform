import { base64UrlToBytes } from '../utils/base64.js';
import { state } from '../state.js';
import { extractHexFromJsonFormat } from '../../advanced/credentials/utils.js';

function bytesOf(value) {
    if (value instanceof ArrayBuffer) {
        return new Uint8Array(value);
    }
    if (ArrayBuffer.isView(value)) {
        return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    return base64UrlToBytes(value);
}

// The challenge the authenticator signed, in hex, from the credential's
// clientDataJSON: an ArrayBuffer on the browser's own credential, base64url in
// its JSON form. '' when it cannot be read.
function challengeHexOf(response) {
    try {
        const clientData = JSON.parse(new TextDecoder().decode(bytesOf(response.clientDataJSON)));
        return Array.from(base64UrlToBytes(clientData.challenge), byte => byte.toString(16).padStart(2, '0')).join('');
    } catch (error) {
        return '';
    }
}

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

    const fakeCredLength = state.lastFakeCredLength || 0;
    console.log('fake credential id length:', fakeCredLength);

    console.log('challenge hex code:', credential.response ? challengeHexOf(credential.response) : '');

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
}

export function printAuthenticationDebug(assertion, requestOptions, serverResponse) {
    const clientExtensions = assertion.getClientExtensionResults
        ? assertion.getClientExtensionResults()
        : (assertion.clientExtensionResults || {});
    const serverData = serverResponse || {};

    const fakeCredLength = state.lastFakeCredLength || 0;
    console.log('Fake credential ID length:', fakeCredLength);

    console.log('challenge hex code:', assertion.response ? challengeHexOf(assertion.response) : '');

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
