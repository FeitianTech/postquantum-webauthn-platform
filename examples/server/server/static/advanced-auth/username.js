import { updateJsonEditor } from './json-editor.js';

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
