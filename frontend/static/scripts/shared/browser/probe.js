// Reading a browser API that may be missing, or may throw when it is read.

export function describeError(error) {
    if (error && typeof error === 'object' && typeof error.message === 'string') {
        const name = typeof error.name === 'string' && error.name !== '' ? error.name : 'Error';
        return error.message === '' ? name : `${name}: ${error.message}`;
    }
    return String(error);
}

export function describeValue(value) {
    if (value === undefined) {
        return 'undefined';
    }
    try {
        return JSON.stringify(value) ?? String(value);
    } catch {
        return String(value);
    }
}

// { value } when the read succeeds, { error } (a description) when it throws.
export function attempt(read) {
    try {
        return { value: read() };
    } catch (error) {
        return { error: describeError(error) };
    }
}
