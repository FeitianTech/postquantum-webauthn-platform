// How the Codec shows one decoded value, without the page: which kind of view
// it gets, the label of each key, and the badges an interpreted value carries.
// The current panel (render-values.js) and the new UI in web/ both use it.
import { formatKey } from './labels.js';

// A string longer than this, or holding a newline, is shown as a block.
const INLINE_LIMIT = 80;

// What the server says about an interpreted value, shown before it: an
// identifier nothing defines, something shown but not verified, a format the
// spec deprecates. Each badge is [kind, text].
export function badgesFor(value) {
    const badges = [];
    if (value.known === false) {
        badges.push(['unknown', 'Unknown']);
    }
    if (typeof value.verification === 'string' && /not verified/i.test(value.verification)) {
        badges.push(['not-verified', 'Not verified']);
    }
    if (value.deprecated === true || typeof value.deprecated === 'string') {
        badges.push(['deprecated', 'Deprecated']);
    }
    return badges;
}

/**
 * The view a value gets: `empty` (null, undefined, [] or {}, muted), `inline` or
 * `block` (a string), `primitive` (a number, boolean or anything else, as text),
 * `list` (its items, each shown by these rules) or `map` (its entries with their
 * labels, and the badges shown before them).
 */
export function classifyCodecValue(value) {
    if (value === null || value === undefined) {
        return { kind: 'empty', text: String(value) };
    }
    if (typeof value === 'string') {
        const isMultiline = value.includes('\n') || value.length > INLINE_LIMIT;
        return { kind: isMultiline ? 'block' : 'inline', text: value };
    }
    if (typeof value === 'number' || typeof value === 'boolean') {
        return { kind: 'primitive', text: String(value) };
    }
    if (Array.isArray(value)) {
        return value.length === 0
            ? { kind: 'empty', text: '[]' }
            : { kind: 'list', items: value };
    }
    if (typeof value === 'object') {
        const entries = Object.entries(value);
        if (entries.length === 0) {
            return { kind: 'empty', text: '{}' };
        }
        return {
            kind: 'map',
            badges: badgesFor(value),
            entries: entries.map(([key, child]) => ({ key, label: formatKey(key), value: child })),
        };
    }
    return { kind: 'primitive', text: String(value) };
}

// A top-level expandedJson, as the text the panel shows.
export function codecExpandedJson(value) {
    const payload = { 'decoded json': value === undefined ? null : value };
    try {
        return JSON.stringify(payload, null, 2);
    } catch (error) {
        return 'Unable to render expanded JSON';
    }
}

// The EDN view's text: the notation as the decoder wrote it.
export function codecEdnText(value) {
    return typeof value === 'string' ? value : JSON.stringify(value);
}
