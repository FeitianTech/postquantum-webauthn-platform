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

    const template = `<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Authenticator Raw Data</title>
    <style>
        :root { color-scheme: light; }
        body {
            margin: 0;
            font-family: 'SFMono-Regular', 'JetBrains Mono', 'Fira Code', monospace;
            background: #f4f7fb;
            color: #0f2740;
        }
        .raw-window {
            display: flex;
            flex-direction: column;
            height: 100vh;
        }
        header {
            padding: 1rem 1.5rem;
            background: #ffffff;
            border-bottom: 1px solid rgba(15, 39, 64, 0.12);
        }
        h1 {
            margin: 0;
            font-size: 1.1rem;
            font-weight: 700;
        }
        p {
            margin: 0.35rem 0 0;
            font-size: 0.85rem;
            color: #48607a;
        }
        textarea {
            flex: 1;
            width: 100%;
            border: none;
            resize: none;
            padding: 1.25rem;
            background: #ffffff;
            font-family: 'SFMono-Regular', 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.85rem;
            line-height: 1.5;
            color: inherit;
            box-sizing: border-box;
            outline: none;
        }
        textarea:focus {
            outline: none;
        }
    </style>
</head>
<body>
    <div class="raw-window">
        <header>
            <h1 id="mds-raw-title">Authenticator Raw Data</h1>
            <p id="mds-raw-subtitle" style="display: none;"></p>
        </header>
        <textarea id="mds-raw-textarea" readonly spellcheck="false" wrap="off" aria-label="Raw authenticator metadata"></textarea>
    </div>
</body>
</html>`;

    doc.open();
    doc.write(template);
    doc.close();

    doc.title = titleText;

    const titleEl = doc.getElementById('mds-raw-title');
    if (titleEl) {
        titleEl.textContent = titleText;
    }

    const subtitleEl = doc.getElementById('mds-raw-subtitle');
    if (subtitleEl) {
        if (subtitleText) {
            subtitleEl.textContent = subtitleText;
            subtitleEl.style.display = '';
        } else {
            subtitleEl.textContent = '';
            subtitleEl.style.display = 'none';
        }
    }

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
