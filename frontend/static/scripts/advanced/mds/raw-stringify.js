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
        try {
            return JSON.stringify(value);
        } catch (error) {
            return `"${value.replace(/"/g, '\\"')}"`;
        }
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

    const addLine = text => {
        if (text !== undefined && text !== null) {
            lines.push(text);
        }
    };

    if (label !== undefined) {
        if (Array.isArray(value)) {
            addLine(`${indent}${label}:`);
            if (!value.length) {
                addLine(`${indent}${RAW_TEXT_INDENT}[]`);
                return lines;
            }
            value.forEach(item => {
                if (Array.isArray(item) || isPlainObject(item)) {
                    const childLines = buildAuthenticatorRawLines(item, depth + 1);
                    lines.push(...childLines);
                } else {
                    addLine(`${indent}${RAW_TEXT_INDENT}${formatRawPrimitive(item)}`);
                }
            });
            return lines;
        }

        if (isPlainObject(value)) {
            addLine(`${indent}${label}:`);
            const keys = Object.keys(value);
            if (!keys.length) {
                addLine(`${indent}${RAW_TEXT_INDENT}{}`);
                return lines;
            }
            keys.forEach(key => {
                const childLines = buildAuthenticatorRawLines(value[key], depth + 1, key);
                lines.push(...childLines);
            });
            return lines;
        }

        addLine(`${indent}${label}: ${formatRawPrimitive(value)}`);
        return lines;
    }

    if (Array.isArray(value)) {
        if (!value.length) {
            addLine(`${indent}[]`);
            return lines;
        }
        value.forEach(item => {
            if (Array.isArray(item) || isPlainObject(item)) {
                const childLines = buildAuthenticatorRawLines(item, depth + 1);
                lines.push(...childLines);
            } else {
                addLine(`${indent}${RAW_TEXT_INDENT}${formatRawPrimitive(item)}`);
            }
        });
        return lines;
    }

    if (isPlainObject(value)) {
        const keys = Object.keys(value);
        if (!keys.length) {
            addLine(`${indent}{}`);
            return lines;
        }
        keys.forEach(key => {
            const childLines = buildAuthenticatorRawLines(value[key], depth, key);
            lines.push(...childLines);
        });
        return lines;
    }

    addLine(`${indent}${formatRawPrimitive(value)}`);
    return lines;
}

export function stringifyAuthenticatorRawData(value) {
    const seen = typeof WeakSet === 'function' ? new WeakSet() : null;
    const replacer = (key, currentValue) => {
        if (typeof currentValue === 'bigint') {
            return currentValue.toString();
        }
        if (typeof Map !== 'undefined' && currentValue instanceof Map) {
            return Object.fromEntries(currentValue);
        }
        if (typeof Set !== 'undefined' && currentValue instanceof Set) {
            return Array.from(currentValue);
        }
        if (typeof ArrayBuffer !== 'undefined') {
            if (currentValue instanceof ArrayBuffer) {
                return Array.from(new Uint8Array(currentValue));
            }
            if (typeof ArrayBuffer.isView === 'function' && ArrayBuffer.isView(currentValue)) {
                const view = new Uint8Array(
                    currentValue.buffer,
                    currentValue.byteOffset || 0,
                    currentValue.byteLength || currentValue.length || 0,
                );
                return Array.from(view);
            }
        }
        if (currentValue && typeof currentValue === 'object' && seen) {
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
        const lines = buildAuthenticatorRawLines(value);
        return lines.join('\n');
    }
}
