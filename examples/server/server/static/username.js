import { updateJsonEditor } from './json-editor.js';
import { randomizeUserId } from './forms.js';

export function generateRandom10DigitUsername() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < 10; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

export function randomizeUsername() {
    const randomUsername = generateRandom10DigitUsername();
    const userName = document.getElementById('user-name');
    const displayName = document.getElementById('user-display-name');
    if (userName) {
        userName.value = randomUsername;
    }
    if (displayName) {
        displayName.value = randomUsername;
    }
    updateJsonEditor();
}

export function randomizeUserIdentity() {
    randomizeUserId();
    randomizeUsername();
}

let hasInitializedSimpleUsername = false;

function setSimpleUsernameValue() {
    const simpleInput = document.getElementById('simple-email');
    if (simpleInput) {
        simpleInput.value = generateRandom10DigitUsername();
    }
}

export function initializeSimpleUsername() {
    if (hasInitializedSimpleUsername) {
        return;
    }

    hasInitializedSimpleUsername = true;
    setSimpleUsernameValue();
}

export function randomizeSimpleUsername() {
    setSimpleUsernameValue();
}
