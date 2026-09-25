// The Analyze Browser panel: what the browser says about itself and about
// WebAuthn, each answer shown with where it came from, or why there is none.

import { updateGlobalScrollLock } from '../ui/core.js';
import { el } from '../ui/dom.js';
import { SOURCE_TEXT } from './identity.js';
import {
    IDENTITY_FIELDS,
    NOT_REPORTED,
    NO_CAPABILITIES,
    copyReport as copyAnalysisReport,
    gatherAnalysis,
    groupCapabilities,
    omittedNote,
} from './report.js';
import { AUTHENTICATOR_FACTS, STATE_TEXT, WEBAUTHN_FACTS } from './webauthn-facts.js';

const FOCUSABLE = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

function element(tag, className, text) {
    return el(tag, { className, text });
}

function stateBadge(state) {
    const badge = element('span', 'analyze-browser-panel__feature-value', STATE_TEXT[state]);
    badge.dataset.state = state;
    return badge;
}

function factItem(id, label, api, fact) {
    const item = element('li', 'analyze-browser-panel__feature');
    item.dataset.fact = id;
    const text = element('div', 'analyze-browser-panel__feature-text');
    text.append(element('span', 'analyze-browser-panel__feature-label', label));
    if (api) {
        text.append(element('code', 'analyze-browser-panel__feature-api', api));
    }
    if (fact.note) {
        text.append(element('span', 'analyze-browser-panel__feature-note', fact.note));
    }
    item.append(text, stateBadge(fact.state));
    return item;
}

function renderIdentity(panel, identity) {
    for (const field of IDENTITY_FIELDS) {
        const item = panel.querySelector(`[data-identity="${field}"]`);
        item.querySelector('[data-role="value"]').textContent = identity[field] ?? NOT_REPORTED;
        item.querySelector('[data-role="source"]').textContent = SOURCE_TEXT[identity.sources[field]];
    }
    panel.querySelector('[data-role="apple-webkit-note"]').hidden = !identity.onAppleWebKit;
}

function renderFacts(list, definitions, facts) {
    list.replaceChildren(...definitions.map(({ id, label, api }) => factItem(id, label, api, facts[id])));
}

function capabilityGroup(group) {
    const block = element('div', 'analyze-browser-panel__capability-group');
    block.dataset.group = group.kind;
    const list = element('ul', `analyze-browser-panel__feature-list analyze-browser-panel__feature-list--${group.kind}`);
    list.append(
        ...group.entries.map(entry => factItem(entry.key, entry.label, entry.kind === 'defined' ? entry.key : null, entry)),
    );
    block.append(element('h4', 'analyze-browser-panel__group-title', group.title), list);
    return block;
}

function renderClientCapabilities(container, clientCapabilities) {
    if (clientCapabilities.state !== 'yes') {
        const status = element('p', 'analyze-browser-panel__capabilities-status');
        status.append(
            stateBadge(clientCapabilities.state),
            element('span', 'analyze-browser-panel__feature-note', clientCapabilities.note),
        );
        container.replaceChildren(status);
        return;
    }

    const { capabilities, omitted } = clientCapabilities;
    const blocks = [];
    if (capabilities.length === 0) {
        blocks.push(element('p', 'analyze-browser-panel__section-note', NO_CAPABILITIES));
    }
    for (const group of groupCapabilities(capabilities)) {
        blocks.push(capabilityGroup(group));
    }
    const note = omittedNote(omitted);
    if (note) {
        blocks.push(element('p', 'analyze-browser-panel__section-note', note));
    }
    container.replaceChildren(...blocks);
}

function renderAnalysis(panel, analysis) {
    renderIdentity(panel, analysis.identity);
    const { facts, clientCapabilities } = analysis.webauthn;
    renderFacts(panel.querySelector('[data-role="webauthn-facts"]'), WEBAUTHN_FACTS, facts);
    renderClientCapabilities(panel.querySelector('[data-role="client-capabilities"]'), clientCapabilities);
    renderFacts(panel.querySelector('[data-role="authenticator-facts"]'), AUTHENTICATOR_FACTS, facts);
}

async function copyReport(panel, analysis) {
    const status = panel.querySelector('[data-role="copy-status"]');
    const fallback = panel.querySelector('[data-role="report-text"]');
    const { copied, message, text } = await copyAnalysisReport(analysis);

    status.dataset.outcome = copied ? 'copied' : 'failed';
    status.textContent = message;
    if (copied) {
        fallback.hidden = true;
        return;
    }
    fallback.value = text;
    fallback.hidden = false;
    fallback.focus();
    fallback.select();
}

function openPanel(panel) {
    const content = panel.querySelector('.analyze-browser-panel__content');
    content.scrollTop = 0;

    panel.hidden = false;
    panel.setAttribute('aria-hidden', 'false');
    requestAnimationFrame(() => {
        panel.classList.add('is-open');
        updateGlobalScrollLock();
        panel.querySelector('[data-role="dialog"]').focus({ preventScroll: true });
    });
}

// Tab and Shift+Tab go round the dialog's controls and never leave it.
function keepFocusInside(event, dialog) {
    const focusable = Array.from(dialog.querySelectorAll(FOCUSABLE)).filter(
        node => !node.disabled && !node.closest('[hidden]'),
    );
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const active = document.activeElement;
    const inside = active !== dialog && dialog.contains(active);

    if (event.shiftKey && (!inside || active === first)) {
        event.preventDefault();
        last.focus();
    } else if (!event.shiftKey && (!inside || active === last)) {
        event.preventDefault();
        first.focus();
    }
}

function closePanel(panel) {
    if (!panel.classList.contains('is-open')) {
        return false;
    }
    panel.querySelector('.analyze-browser-panel__content').scrollTop = 0;
    panel.classList.remove('is-open');
    panel.setAttribute('aria-hidden', 'true');
    panel.hidden = true;
    updateGlobalScrollLock();
    return true;
}

export function initializeAnalyzeBrowser() {
    const trigger = document.querySelector('[data-analyze-browser-trigger]');
    const panel = document.getElementById('analyze-browser-panel');

    if (!trigger || !panel) {
        return;
    }

    let running = false;
    let analysis = null;

    const handleClose = () => {
        if (closePanel(panel)) {
            trigger.focus({ preventScroll: true });
        }
    };

    panel.addEventListener('click', event => {
        const target = event.target;
        if (!(target instanceof Element)) {
            return;
        }
        if (target.closest('[data-action="close"]')) {
            event.preventDefault();
            handleClose();
        } else if (target.closest('[data-action="copy-report"]')) {
            copyReport(panel, analysis);
        }
    });

    document.addEventListener('keydown', event => {
        if (!panel.classList.contains('is-open')) {
            return;
        }
        if (event.key === 'Escape') {
            handleClose();
        } else if (event.key === 'Tab') {
            keepFocusInside(event, panel.querySelector('[data-role="dialog"]'));
        }
    });

    trigger.addEventListener('click', async () => {
        if (running) {
            return;
        }
        if (!analysis) {
            running = true;
            trigger.disabled = true;
            try {
                analysis = await gatherAnalysis();
                renderAnalysis(panel, analysis);
            } finally {
                trigger.disabled = false;
                running = false;
            }
        }
        openPanel(panel);
    });
}
