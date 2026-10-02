// What the server made of the last ceremony, as the panel under each tab's
// buttons says it: the signature counter and its check, and in the advanced tab
// where the challenge came from. DOM-free: the result panel shows this model.

// server/app/webauthn/sign_count.py
const SIGN_COUNT_SENTENCES = {
    ok: 'Higher than the last counter the server saw for this credential, as it should be.',
    'not-supported': 'This authenticator keeps no counter: it reported 0, as synced passkeys do, so the counter cannot show whether it was cloned.',
    regressed: 'Not higher than the counter the server stored: the authenticator may have been cloned.',
};

// server/app/routes/advanced/constants.py and server/app/challenge_registry.py
const CHALLENGE_SOURCES = {
    'server-session': 'Issued by this server for this ceremony.',
};

const CHALLENGE_STATUSES = {
    fresh: 'First use.',
    replayed: 'Used before: this is a replay.',
    expired: 'Expired before it was used.',
};

function reported(value) {
    return `The server reported "${value}".`;
}

function known(table, value) {
    return Object.hasOwn(table, value) ? table[value] : reported(value);
}

// A row: its label, the value the server gave (shown as a figure), the sentence,
// and what follows the sentence (the tab's consequence, the challenge's status).
/** @param {CeremonyResultInput} result */
function counterRow({ signCount, signCountStatus, consequence }) {
    const hasCount = typeof signCount === 'number' && Number.isFinite(signCount);
    if (!hasCount && !signCountStatus) {
        return [];
    }
    return [{
        label: 'Signature counter',
        value: hasCount ? String(signCount) : null,
        text: signCountStatus
            ? known(SIGN_COUNT_SENTENCES, signCountStatus)
            : 'The server did not say how this counter compares with the stored one.',
        after: signCountStatus === 'regressed' && consequence ? consequence : null,
    }];
}

/** @param {CeremonyResultInput} result */
function challengeRow({ challengeSource, challengeStatus }) {
    if (!challengeSource && !challengeStatus) {
        return [{ label: 'Challenge', value: null, text: 'Not reported by the server.', after: null }];
    }
    return [{
        label: 'Challenge',
        value: challengeSource || null,
        text: challengeSource ? known(CHALLENGE_SOURCES, challengeSource) : 'Its source was not reported.',
        after: challengeStatus ? known(CHALLENGE_STATUSES, challengeStatus) : null,
    }];
}

/**
 * What a tab hands the result panel: the server's verdicts and the tab's consequence.
 * @typedef {{
 *   title?: string,
 *   signCount?: number,
 *   signCountStatus?: string | null,
 *   consequence?: string,
 *   showChallenge?: boolean,
 *   challengeSource?: string | null,
 *   challengeStatus?: string | null,
 * }} CeremonyResultInput
 */

/** @typedef {{ label: string, value: string | null, text: string, after: string | null }} CeremonyResultRow */
/** @typedef {{ title: string, rows: CeremonyResultRow[], warning: boolean }} CeremonyResultView */

/**
 * What the panel shows for a ceremony's result, or null when it has nothing to
 * say. result: title ("Last authentication"), signCount, signCountStatus,
 * consequence (appended to a regressed verdict: what the tab did about it), and
 * with showChallenge, challengeSource and challengeStatus. A regressed counter or
 * a replayed challenge is a warning.
 * @param {CeremonyResultInput} [result]
 * @returns {CeremonyResultView | null}
 */
export function describeCeremonyResult(result = {}) {
    const rows = [
        ...counterRow(result),
        ...(result.showChallenge ? challengeRow(result) : []),
    ];
    if (!rows.length) {
        return null;
    }
    return {
        title: result.title || 'Last ceremony',
        rows,
        warning: result.signCountStatus === 'regressed' || result.challengeStatus === 'replayed',
    };
}
