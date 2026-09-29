// The one registration state the sanitisers and the saved snapshot's context
// read when no state of its own is passed in.
export const registrationDetailState = {
    attestationObject: null,
    attestationCertificates: [],
    visibleAttestationCertificateIndices: [],
    authenticatorData: null,
    authenticatorDataHash: '',
    authenticatorDataHex: '',
};
