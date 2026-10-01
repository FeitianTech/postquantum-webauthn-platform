// Text written to the clipboard, and why it could not be. DOM-free: the
// navigator is given (the page's by default).
import { attempt, describeError } from './probe.js';

const NO_CLIPBOARD = 'the clipboard is not available on this page';

// Why the text could not be written, or null when it was.
export async function writeToClipboard(text, nav = globalThis.navigator) {
    const clipboard = attempt(() => nav.clipboard).value;
    if (typeof clipboard?.writeText !== 'function') {
        return NO_CLIPBOARD;
    }
    try {
        await clipboard.writeText(text);
        return null;
    } catch (error) {
        return describeError(error);
    }
}
