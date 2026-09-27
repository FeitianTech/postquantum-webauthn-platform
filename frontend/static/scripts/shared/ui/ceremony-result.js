// The panel under each tab's buttons that says what the server made of the last
// ceremony: the signature counter and its check, and in the advanced tab where
// the challenge came from. It stays until the next ceremony starts, unlike the
// status toast, so a warning that an authenticator may have been cloned does not
// vanish after five seconds. What it says is shared/ceremony/result.js's.

import { describeCeremonyResult } from '../ceremony/result.js';
import { el } from './dom.js';

function panelFor(tab) {
    return document.getElementById(`${tab}-ceremony-result`);
}

function row({ label, value, text, after }) {
    return [
        el('dt', { text: label }),
        el('dd', {},
            value !== null ? el('span', { className: 'ceremony-result__value', text: value }) : null,
            value !== null ? ' ' : null,
            text,
            after ? ` ${after}` : null,
        ),
    ];
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
    const described = describeCeremonyResult(result);
    if (!described) {
        clearCeremonyResult(tab);
        return;
    }
    panel.replaceChildren(
        el('p', { className: 'ceremony-result__title', text: described.title }),
        el('dl', { className: 'ceremony-result__rows' }, described.rows.flatMap(row)),
    );
    if (described.warning) {
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
