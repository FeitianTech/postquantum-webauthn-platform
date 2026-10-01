export function extractByteArray(value) {
    if (!value) {
        return null;
    }
    if (Array.isArray(value)) {
        return value.every(item => Number.isInteger(item)) ? value : null;
    }
    if (value instanceof Uint8Array) {
        return Array.from(value);
    }
    if (ArrayBuffer.isView(value)) {
        return Array.from(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
    }
    if (value instanceof ArrayBuffer) {
        return Array.from(new Uint8Array(value));
    }
    return null;
}

export function extractList(value) {
    if (!value) {
        return [];
    }
    if (Array.isArray(value)) {
        return value.filter(Boolean);
    }
    return [value];
}