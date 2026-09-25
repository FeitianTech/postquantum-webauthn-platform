import { el } from '../../shared/ui/dom.js';

// The popup is an about:blank document, so it shares this page's
// Content-Security-Policy: its rules come from a stylesheet (no <style>, no style
// attribute), and its document is built with DOM calls, never parsed from markup.
const RAW_WINDOW_STYLESHEET = new URL('../../../styles/advanced/mds-raw-window.css', import.meta.url).href;

function buildRawWindowDocument(doc, { titleText, subtitleText }) {
    const subtitle = el('p', { attrs: { id: 'mds-raw-subtitle' }, text: subtitleText || '' });
    subtitle.style.display = subtitleText ? '' : 'none';

    // A document takes one root element, and replaceChildren checks that before it
    // removes the old one, so the old root goes first.
    doc.documentElement?.remove();
    doc.append(
        el('html', { attrs: { lang: 'en' } },
            el('head', {},
                el('title', { text: titleText }),
                el('link', { attrs: { rel: 'stylesheet', href: RAW_WINDOW_STYLESHEET } }),
            ),
            el('body', {},
                el('div', { className: 'raw-window' },
                    el('header', {},
                        el('h1', { attrs: { id: 'mds-raw-title' }, text: titleText }),
                        subtitle,
                    ),
                    el('textarea', {
                        attrs: {
                            id: 'mds-raw-textarea',
                            readonly: true,
                            spellcheck: 'false',
                            wrap: 'off',
                            'aria-label': 'Raw authenticator metadata',
                        },
                    }),
                ),
            ),
        ),
    );
}

export function openAuthenticatorRawWindow({
    state,
    formatDetailSubtitle,
    getAuthenticatorRawData,
    stringifyAuthenticatorRawData,
}) {
    if (!state) {
        return;
    }

    const entry = state.activeDetailEntry;
    const rawData = getAuthenticatorRawData(entry);
    if (!rawData) {
        return;
    }

    const rawText = stringifyAuthenticatorRawData(rawData);
    if (!rawText || typeof window === 'undefined') {
        return;
    }

    const viewportWidth = Number.isFinite(window.innerWidth) && window.innerWidth > 0
        ? window.innerWidth
        : (window.screen && Number.isFinite(window.screen.availWidth) ? window.screen.availWidth : 1280);
    const viewportHeight = Number.isFinite(window.innerHeight) && window.innerHeight > 0
        ? window.innerHeight
        : (window.screen && Number.isFinite(window.screen.availHeight) ? window.screen.availHeight : 720);

    const width = Math.max(Math.round(viewportWidth * 0.8), 640);
    const height = Math.max(Math.round(viewportHeight * 0.8), 480);
    const features = `popup=yes,width=${width},height=${height},resizable=yes,scrollbars=yes`;
    const viewerName = 'mdsAuthenticatorRawViewer';

    let viewer = state.authenticatorRawWindow;
    if (!viewer || viewer.closed) {
        viewer = window.open('', viewerName, features);
    } else {
        viewer.focus();
        try {
            viewer.resizeTo(width, height);
        } catch (error) {
            // Ignore resize errors caused by browser restrictions.
        }
    }

    if (!viewer) {
        return;
    }

    state.authenticatorRawWindow = viewer;

    let doc;
    try {
        doc = viewer.document;
    } catch (error) {
        return;
    }

    if (!doc) {
        return;
    }

    const titleParts = [];
    if (entry?.name && typeof entry.name === 'string' && entry.name.trim()) {
        titleParts.push(entry.name.trim());
    }
    titleParts.push('Authenticator Raw Data');
    const titleText = titleParts.join(' – ');
    const subtitleText = formatDetailSubtitle(entry);

    // Discards what the popup held, as before; neither call parses markup.
    doc.open();
    doc.close();
    buildRawWindowDocument(doc, { titleText, subtitleText });

    const textarea = doc.getElementById('mds-raw-textarea');
    if (textarea) {
        textarea.value = rawText;
        textarea.scrollTop = 0;
        textarea.scrollLeft = 0;
        if (typeof textarea.setSelectionRange === 'function') {
            try {
                textarea.setSelectionRange(0, 0);
            } catch (error) {
                // Ignore selection errors in unsupported browsers.
            }
        }
        if (typeof textarea.focus === 'function') {
            textarea.focus();
        }
    }

    try {
        viewer.focus();
    } catch (error) {
        // Some browsers may block programmatic focus; ignore.
    }

    try {
        viewer.onbeforeunload = () => {
            if (state && state.authenticatorRawWindow === viewer) {
                state.authenticatorRawWindow = null;
            }
        };
    } catch (error) {
        // Ignore if the viewer does not permit assigning event handlers.
    }
}
