export const state = {
    currentSubTab: 'registration',
    storedCredentials: [],
    currentJsonMode: null,
    currentJsonData: null,
    lastFakeCredLength: 0,
    generatedExcludeCredentials: [],
    generatedAllowCredentials: [],
    utf8Decoder: typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8') : null,
    lastRegisteredCredentialId: null, // Track most recently registered credential
    lastAssertedCredentialId: null, // Track most recently asserted credential for animation
};
