export const state = {
    currentSubTab: 'registration',
    storedCredentials: [],
    currentJsonMode: null,
    currentJsonData: null,
    lastFakeCredLength: 0,
    generatedExcludeCredentials: [],
    utf8Decoder: typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8') : null,
};
