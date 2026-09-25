// The Analyze Browser's findings as data: what is gathered, how the client
// capabilities are grouped, and the report a person copies. Nothing here touches
// the DOM, so the panel (analyze.js) and the new UI (web/) build their views from
// the same answers and say the same words.

import { determineIdentity, readIdentityInputs } from './identity.js';
import { attempt, describeError } from './probe.js';
import { CLIENT_CAPABILITY_LABELS, gatherWebAuthnFacts } from './webauthn-facts.js';

export const IDENTITY_FIELDS = ['name', 'version', 'engine', 'system'];
export const NOT_REPORTED = 'Not reported';

export const CAPABILITY_GROUPS = [
    { kind: 'defined', title: 'Defined by WebAuthn Level 3' },
    { kind: 'extension', title: 'Extensions' },
    { kind: 'unrecognised', title: 'Not recognised by this page, as the browser wrote them' },
];

export const NO_CAPABILITIES = 'The browser returned no capabilities.';
export const COPIED = 'Report copied to the clipboard.';
const NO_CLIPBOARD = 'the clipboard is not available on this page';

const DEFINED_ORDER = Object.keys(CLIENT_CAPABILITY_LABELS);

export async function gatherAnalysis(scope = globalThis) {
    const [inputs, webauthn] = await Promise.all([readIdentityInputs(scope.navigator), gatherWebAuthnFacts(scope)]);
    return {
        generatedAt: new Date().toISOString(),
        page: scope.location.origin,
        inputs,
        identity: determineIdentity(inputs),
        webauthn,
    };
}

// The groups that have entries, in CAPABILITY_GROUPS order. Defined keys follow
// the spec's order whatever order the browser used; the others stay as written.
export function groupCapabilities(capabilities) {
    return CAPABILITY_GROUPS.map(group => {
        const entries = capabilities.filter(entry => entry.kind === group.kind);
        if (group.kind === 'defined') {
            entries.sort((a, b) => DEFINED_ORDER.indexOf(a.key) - DEFINED_ORDER.indexOf(b.key));
        }
        return { ...group, entries };
    }).filter(group => group.entries.length > 0);
}

export function omittedNote(omitted) {
    return omitted.length > 0 ? `Left out by the browser, so not known: ${omitted.join(', ')}.` : null;
}

// The raw findings, for a bug report: what was read, and every answer and state.
export function buildReport(analysis) {
    const { identity, inputs, webauthn } = analysis;
    const { state, note, returned, omitted } = webauthn.clientCapabilities;
    return {
        report: 'Analyze Browser',
        generatedAt: analysis.generatedAt,
        page: analysis.page,
        identity: {
            name: identity.name,
            version: identity.version,
            engine: identity.engine,
            system: identity.system,
            sources: identity.sources,
            inputs,
        },
        webauthn: {
            facts: webauthn.facts,
            clientCapabilities: { state, ...(note ? { note } : {}), returned, omitted },
        },
    };
}

export function reportText(analysis) {
    return JSON.stringify(buildReport(analysis), null, 2);
}

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

export function copyFailedMessage(failure) {
    const reason = /[.!?]$/.test(failure) ? failure : `${failure}.`;
    return `Could not copy the report: ${reason} The report is below, selected, to copy by hand.`;
}

// Copies the report and says how it went: { copied, message, text }. When the copy
// failed the view shows `text` for copying by hand.
export async function copyReport(analysis, nav = globalThis.navigator) {
    const text = reportText(analysis);
    const failure = await writeToClipboard(text, nav);
    if (failure === null) {
        return { copied: true, message: COPIED, text };
    }
    return { copied: false, message: copyFailedMessage(failure), text };
}
