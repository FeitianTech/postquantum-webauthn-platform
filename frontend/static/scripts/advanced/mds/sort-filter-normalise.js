export function normaliseSortValueInput(value) {
    if (value === undefined || value === null) {
        return '';
    }
    if (typeof value === 'number') {
        return value;
    }
    if (value instanceof Date) {
        return value.getTime();
    }

    const text = String(value).trim();
    if (!text || text === '—') {
        return '';
    }

    const numeric = Number(text);
    if (!Number.isNaN(numeric) && text !== '') {
        return numeric;
    }
    return text.toLowerCase();
}
