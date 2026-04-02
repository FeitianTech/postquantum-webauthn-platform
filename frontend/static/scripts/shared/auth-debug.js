import { base64UrlToHex } from './binary-utils.js';
import { extractHexFromJsonFormat } from '../advanced/credential-utils.js';

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
