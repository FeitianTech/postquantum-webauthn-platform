// The panel under each tab's buttons that says what the server made of the last
// ceremony: the signature counter and its check, and in the advanced tab where
// the challenge came from. It stays until the next ceremony starts, unlike the
// status toast, so a warning that an authenticator may have been cloned does not
// vanish after five seconds.

import { el } from './dom.js';

// server/app/webauthn/sign_count.py
const SIGN_COUNT_SENTENCES = {
    ok: 'Higher than the last counter the server saw for this credential, as it should be.',
    'not-supported': 'This authenticator keeps no counter: it reported 0, as synced passkeys do, so the counter cannot show whether it was cloned.',
    regressed: 'Not higher than the counter the server stored: the authenticator may have been cloned.',
};

// server/app/routes/advanced/constants.py and server/app/challenge_registry.py
const CHALLENGE_SOURCES = {
    'server-session': 'Issued by this server for this ceremony.',
    'client-supplied': 'Taken from the request, not issued by this server.',
};

const CHALLENGE_STATUSES = {
    fresh: 'First use.',
    replayed: 'Used before: this is a replay.',
    expired: 'Expired before it was used.',
    'not-tracked': 'Not tracked for reuse.',
};

function panelFor(tab) {
    return document.getElementById(`${tab}-ceremony-result`);
}

function row(label, ...value) {
    return [el('dt', { text: label }), el('dd', {}, ...value)];
}

function counterRow({ signCount, signCountStatus, consequence }) {
    const hasCount = typeof signCount === 'number' && Number.isFinite(signCount);
    if (!hasCount && !signCountStatus) {
        return [];
    }
    const sentence = signCountStatus
        ? SIGN_COUNT_SENTENCES[signCountStatus] || `The server reported "${signCountStatus}".`
        : 'The server did not say how this counter compares with the stored one.';
    return row('Signature counter',
        el('span', { className: 'ceremony-result__value', text: hasCount ? String(signCount) : 'not reported' }),
        ' ',
        sentence,
        signCountStatus === 'regressed' && consequence ? ` ${consequence}` : null,
    );
}

function challengeRow({ challengeSource, challengeStatus }) {
    if (!challengeSource && !challengeStatus) {
        return row('Challenge', 'Not reported by the server.');
    }
    const source = challengeSource
        ? CHALLENGE_SOURCES[challengeSource] || `The server reported "${challengeSource}".`
        : 'Its source was not reported.';
    const status = challengeStatus
        ? CHALLENGE_STATUSES[challengeStatus] || `The server reported "${challengeStatus}".`
        : null;
    return row('Challenge',
        challengeSource ? el('span', { className: 'ceremony-result__value', text: challengeSource }) : null,
        challengeSource ? ' ' : null,
        source,
        status ? ` ${status}` : null,
    );
}

/**
 * Show what the server said about the last ceremony.
 *
 * result: title ("Last authentication"), signCount, signCountStatus, consequence
 * (appended to a regressed verdict: what the tab did about it), and with
 * showChallenge, challengeSource and challengeStatus.
 */
export function showCeremonyResult(tab, result = {}) {
    const panel = panelFor(tab);
    if (!panel) {
        return;
    }
    const rows = [
        ...counterRow(result),
        ...(result.showChallenge ? challengeRow(result) : []),
    ];
    if (!rows.length) {
        clearCeremonyResult(tab);
        return;
    }
    panel.replaceChildren(
        el('p', { className: 'ceremony-result__title', text: result.title || 'Last ceremony' }),
        el('dl', { className: 'ceremony-result__rows' }, rows),
    );
    if (result.signCountStatus === 'regressed' || result.challengeStatus === 'replayed') {
        panel.dataset.verdict = 'warning';
    } else {
        delete panel.dataset.verdict;
    }
    panel.hidden = false;
}

export function clearCeremonyResult(tab) {
    const panel = panelFor(tab);
    if (!panel) {
        return;
    }
    panel.replaceChildren();
    delete panel.dataset.verdict;
    panel.hidden = true;
}
