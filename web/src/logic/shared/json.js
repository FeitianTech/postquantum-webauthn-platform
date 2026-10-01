// A copy of a JSON value that shares nothing with it. DOM-free.

/** A copy of a map or a list at every level; null for any other value. */
export function cloneJson(value) {
    if (!value || typeof value !== 'object') {
        return null;
    }
    return structuredClone(value);
}
