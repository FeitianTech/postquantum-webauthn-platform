import { updateJsonEditor } from '../../advanced/editor/index.js';
import { randomizeUserId } from '../../advanced/auth/forms.js';
import { bindActions, callWith } from '../ui/actions.js';

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

export const usernameActions = {
    'randomize-simple-username': callWith(randomizeSimpleUsername),
};

// On the document: the simple and the advanced tab each have a username control.
export function bindUsernameActions() {
    return bindActions(document, usernameActions);
}
