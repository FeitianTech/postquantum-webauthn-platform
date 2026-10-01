// A random username: ten characters from A–Z, a–z and 0–9, as the Simple tab
// fills its field with when the page loads and on "Generate random username".

const USERNAME_CHARACTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

export function generateRandom10DigitUsername() {
    let result = '';
    for (let i = 0; i < 10; i++) {
        result += USERNAME_CHARACTERS.charAt(Math.floor(Math.random() * USERNAME_CHARACTERS.length));
    }
    return result;
}
