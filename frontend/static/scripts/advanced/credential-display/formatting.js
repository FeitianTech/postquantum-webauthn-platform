function appendKeyValueLines(output, value, indentLevel = 0) {
    if (value === null || value === undefined) {
        return;
    }

    const indent = '    '.repeat(indentLevel);

    if (typeof value === 'string' || typeof value === 'number') {
        if (String(value).trim() !== '') {
            output.push(`${indent}${value}`);
        }
        return;
    }

    if (typeof value === 'boolean') {
        output.push(`${indent}${value}`);
        return;
    }

    if (Array.isArray(value)) {
        if (value.length === 0) {
            return;
        }

        const filtered = value.filter(item => item !== null && item !== undefined);
        if (filtered.length === 0) {
            return;
        }

        const allScalars = filtered.every(item => {
            return (
                typeof item === 'string' ||
                typeof item === 'number' ||
                typeof item === 'boolean'
            );
        });

        if (allScalars) {
            filtered.forEach(item => {
                output.push(`${indent}${item}`);
            });
        } else {
            filtered.forEach(item => {
                if (item === null || item === undefined) {
                    return;
                }

                if (typeof item === 'object') {
                    output.push(`${indent}-`);
                    appendKeyValueLines(output, item, indentLevel + 1);
                } else {
                    output.push(`${indent}- ${item}`);
                }
            });
        }
        return;
    }

    if (typeof value === 'object') {
        const entries = Object.entries(value).filter(([key, val]) => {
            if (val === null || val === undefined || val === '') {
                return false;
            }
            if (typeof key === 'string' && key.toLowerCase().includes('base64')) {
                return false;
            }
            return true;
        });

        if (entries.length === 0) {
            return;
        }

        entries.forEach(([key, val]) => {
            if (typeof val === 'object') {
                if (Array.isArray(val)) {
                    if (val.length === 0) {
                        return;
                    }
                    output.push(`${indent}${key}:`);
                    appendKeyValueLines(output, val, indentLevel + 1);
                } else {
                    const nestedEntries = Object.entries(val).filter(([, nestedVal]) => nestedVal !== null && nestedVal !== undefined && nestedVal !== '');
                    if (nestedEntries.length === 0) {
                        return;
                    }
                    output.push(`${indent}${key}:`);
                    appendKeyValueLines(output, val, indentLevel + 1);
                }
            } else {
                output.push(`${indent}${key}: ${val}`);
            }
        });
        return;
    }

    output.push(`${indent}${String(value)}`);
}

function hexToColonLines(hexString, bytesPerLine = 16) {
    if (typeof hexString !== 'string') {
        return [];
    }
    let clean = hexString.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
    if (!clean) {
        return [];
    }
    if (clean.length % 2 !== 0) {
        clean = `0${clean}`;
    }
    const pairs = [];
    for (let i = 0; i < clean.length; i += 2) {
        pairs.push(clean.slice(i, i + 2));
    }
    const output = [];
    for (let i = 0; i < pairs.length; i += bytesPerLine) {
        output.push(pairs.slice(i, i + bytesPerLine).join(':'));
    }
    return output;
}

export function formatCertificateDetails(details) {
    if (!details || typeof details !== 'object') {
        return '';
    }

    if (typeof details.summary === 'string' && details.summary.trim() !== '') {
        return details.summary.trim();
    }

    const lines = [];
    const addLine = line => lines.push(line);
    const addBlankLine = () => {
        if (lines.length && lines[lines.length - 1] !== '') {
            lines.push('');
        }
    };

    const { version } = details;
    if (version) {
        if (typeof version === 'object') {
            const parts = [];
            if (typeof version.display === 'string' && version.display.trim() !== '') {
                parts.push(version.display.trim());
            }
            if (typeof version.hex === 'string' && version.hex.trim() !== '') {
                if (!parts.length || parts[parts.length - 1] !== version.hex.trim()) {
                    parts.push(version.hex.trim());
                }
            }
            if (parts.length > 0) {
                addLine(`Version: ${parts.join(' ')}`);
            }
        } else if (String(version).trim() !== '') {
            addLine(`Version: ${version}`);
        }
    }

    const serialNumber = details.serialNumber;
    if (serialNumber) {
        if (typeof serialNumber === 'object') {
            const parts = [];
            if (typeof serialNumber.decimal === 'string' && serialNumber.decimal.trim() !== '') {
                parts.push(serialNumber.decimal.trim());
            }
            if (typeof serialNumber.hex === 'string' && serialNumber.hex.trim() !== '') {
                parts.push(serialNumber.hex.trim());
            }
            if (parts.length > 0) {
                addLine(`Certificate Serial Number: ${parts.join(' / ')}`);
            }
        } else if (String(serialNumber).trim() !== '') {
            addLine(`Certificate Serial Number: ${serialNumber}`);
        }
    }

    if (typeof details.signatureAlgorithm === 'string' && details.signatureAlgorithm.trim() !== '') {
        addLine(`Signature Algorithm: ${details.signatureAlgorithm.trim()}`);
    }

    if (typeof details.issuer === 'string' && details.issuer.trim() !== '') {
        addLine(`Issuer: ${details.issuer.trim()}`);
    }

    const validity = details.validity;
    if (validity && (validity.notBefore || validity.notAfter)) {
        addBlankLine();
        addLine('Validity:');
        if (validity.notBefore) {
            addLine(`    Not Before: ${validity.notBefore}`);
        }
        if (validity.notAfter) {
            addLine(`    Not After: ${validity.notAfter}`);
        }
    }

    if (typeof details.subject === 'string' && details.subject.trim() !== '') {
        addBlankLine();
        addLine(`Subject: ${details.subject.trim()}`);
    }

    if (details.publicKeyInfo && typeof details.publicKeyInfo === 'object') {
        addBlankLine();
        addLine('Subject Public Key Info:');
        appendKeyValueLines(lines, details.publicKeyInfo, 1);
    }

    if (Array.isArray(details.extensions) && details.extensions.length) {
        addBlankLine();
        addLine('X509v3 extensions:');
        details.extensions.forEach(ext => {
            if (!ext || typeof ext !== 'object') {
                return;
            }

            const includeOid = ext.includeOidInHeader === undefined
                ? true
                : Boolean(ext.includeOidInHeader);
            const headerOverride = typeof ext.displayHeader === 'string'
                ? ext.displayHeader.trim()
                : '';
            const oid = typeof ext.oid === 'string' ? ext.oid.trim() : '';
            const friendlyName = typeof ext.friendlyName === 'string'
                ? ext.friendlyName.trim()
                : '';
            const extName = typeof ext.name === 'string' ? ext.name.trim() : '';

            let header = headerOverride;
            if (!header) {
                const headerParts = [];
                if (includeOid && oid) {
                    headerParts.push(oid);
                }

                let displayName = friendlyName;
                if (!displayName && extName && extName !== oid) {
                    displayName = extName;
                }

                if (displayName) {
                    if (includeOid && headerParts.length) {
                        headerParts.push(`(${displayName})`);
                    } else {
                        headerParts.push(displayName);
                    }
                }

                if (!headerParts.length) {
                    if (extName) {
                        headerParts.push(extName);
                    } else if (oid) {
                        headerParts.push(oid);
                    } else {
                        headerParts.push('Extension');
                    }
                }

                header = headerParts.join(' ');
            }

            if (ext.critical) {
                header = `${header} [critical]`;
            }

            addLine(`    ${header}:`);
            if ('value' in ext) {
                appendKeyValueLines(lines, ext.value, 2);
            }
        });
    }

    if (details.signature && typeof details.signature === 'object') {
        const algorithm = typeof details.signature.algorithm === 'string'
            ? details.signature.algorithm.trim()
            : '';
        const signatureLines = Array.isArray(details.signature.lines)
            ? details.signature.lines.filter(line => typeof line === 'string' && line.trim() !== '')
            : [];
        const signatureColon = typeof details.signature.colon === 'string'
            ? details.signature.colon.trim()
            : '';

        if (algorithm || signatureLines.length || signatureColon) {
            addBlankLine();
            const algorithmLabel = algorithm || (typeof details.signatureAlgorithm === 'string' ? details.signatureAlgorithm.trim() : 'Signature');
            addLine(`Signature Algorithm: ${algorithmLabel}`);
            if (signatureLines.length) {
                signatureLines.forEach(line => addLine(`    ${line}`));
            } else if (signatureColon) {
                addLine(`    ${signatureColon}`);
            }
        }
    }

    if (details.fingerprints && typeof details.fingerprints === 'object') {
        const fingerprintEntries = Object.entries(details.fingerprints)
            .filter(([, value]) => typeof value === 'string' && value.trim() !== '');

        if (fingerprintEntries.length) {
            addBlankLine();
            addLine('Fingerprint:');
            fingerprintEntries.forEach(([algorithm, value]) => {
                const label = typeof algorithm === 'string' && algorithm.trim() !== ''
                    ? algorithm.trim().toUpperCase()
                    : 'VALUE';
                const colonLines = hexToColonLines(value);
                addLine(`    ${label}:`);
                if (colonLines.length) {
                    colonLines.forEach(line => addLine(`        ${line}`));
                } else {
                    addLine(`        ${value}`);
                }
            });
        }
    }

    const formatted = lines.join('\n').trim();
    return formatted;
}

export function autoResizeCertificateTextareas(context) {
    const scope = context && typeof context.querySelectorAll === 'function'
        ? context
        : document;
    const textareas = scope.querySelectorAll('.certificate-textarea');
    textareas.forEach(textarea => {
        if (!(textarea instanceof HTMLTextAreaElement)) {
            return;
        }

        const resizeOnce = () => {
            textarea.style.height = 'auto';
            textarea.style.overflowY = 'hidden';
            textarea.style.overflowX = 'hidden';
            const measuredHeight = textarea.scrollHeight;
            if (Number.isFinite(measuredHeight) && measuredHeight > 0) {
                textarea.style.height = `${measuredHeight}px`;
            } else {
                textarea.style.height = '';
            }
        };

        resizeOnce();

        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(resizeOnce);
        }

        setTimeout(resizeOnce, 150);
    });
}
