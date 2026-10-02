// The raw view's text: JSON indented by four spaces, with what JSON cannot write
// written out (big integers, maps, sets, bytes, cycles), and a line per key when
// JSON cannot write the value at all. No DOM.
const RAW_TEXT_INDENT = '    ';

function isPlainObject(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function formatRawPrimitive(value) {
    if (value === undefined) {
        return 'undefined';
    }
    if (value === null) {
        return 'null';
    }
    if (typeof value === 'string') {
        return JSON.stringify(value);
    }
    if (typeof value === 'number' || typeof value === 'bigint') {
        return String(value);
    }
    if (typeof value === 'boolean') {
        return value ? 'true' : 'false';
    }
    try {
        return JSON.stringify(value);
    } catch (error) {
        try {
            return String(value);
        } catch (stringError) {
            return '';
        }
    }
}

function buildAuthenticatorRawLines(value, depth = 0, label) {
    const indent = RAW_TEXT_INDENT.repeat(depth);
    const lines = [];

    if (label !== undefined) {
        if (Array.isArray(value)) {
            lines.push(`${indent}${label}:`);
            if (!value.length) {
                lines.push(`${indent}${RAW_TEXT_INDENT}[]`);
                return lines;
            }
            value.forEach(item => {
                if (Array.isArray(item) || isPlainObject(item)) {
                    lines.push(...buildAuthenticatorRawLines(item, depth + 1));
                } else {
                    lines.push(`${indent}${RAW_TEXT_INDENT}${formatRawPrimitive(item)}`);
                }
            });
            return lines;
        }

        if (isPlainObject(value)) {
            lines.push(`${indent}${label}:`);
            const keys = Object.keys(value);
            if (!keys.length) {
                lines.push(`${indent}${RAW_TEXT_INDENT}{}`);
                return lines;
            }
            keys.forEach(key => {
                lines.push(...buildAuthenticatorRawLines(value[key], depth + 1, key));
            });
            return lines;
        }

        lines.push(`${indent}${label}: ${formatRawPrimitive(value)}`);
        return lines;
    }

    if (Array.isArray(value)) {
        if (!value.length) {
            lines.push(`${indent}[]`);
            return lines;
        }
        value.forEach(item => {
            if (Array.isArray(item) || isPlainObject(item)) {
                lines.push(...buildAuthenticatorRawLines(item, depth + 1));
            } else {
                lines.push(`${indent}${RAW_TEXT_INDENT}${formatRawPrimitive(item)}`);
            }
        });
        return lines;
    }

    if (isPlainObject(value)) {
        const keys = Object.keys(value);
        if (!keys.length) {
            lines.push(`${indent}{}`);
            return lines;
        }
        keys.forEach(key => {
            lines.push(...buildAuthenticatorRawLines(value[key], depth, key));
        });
        return lines;
    }

    lines.push(`${indent}${formatRawPrimitive(value)}`);
    return lines;
}

/**
 * @param {unknown} value
 * @returns {string}
 */
export function stringifyAuthenticatorRawData(value) {
    const seen = new WeakSet();
    const replacer = (key, currentValue) => {
        if (typeof currentValue === 'bigint') {
            return currentValue.toString();
        }
        if (currentValue instanceof Map) {
            return Object.fromEntries(currentValue);
        }
        if (currentValue instanceof Set) {
            return Array.from(currentValue);
        }
        if (currentValue instanceof ArrayBuffer) {
            return Array.from(new Uint8Array(currentValue));
        }
        if (ArrayBuffer.isView(currentValue)) {
            return Array.from(new Uint8Array(currentValue.buffer, currentValue.byteOffset, currentValue.byteLength));
        }
        if (currentValue && typeof currentValue === 'object') {
            if (seen.has(currentValue)) {
                return '[Circular]';
            }
            seen.add(currentValue);
        }
        return currentValue;
    };

    try {
        return JSON.stringify(value, replacer, 4);
    } catch (error) {
        return buildAuthenticatorRawLines(value).join('\n');
    }
}
