import { updateGlobalScrollLock } from './ui.js';

const MIN_LOADER_DURATION_MS = 600;
const COSE_SUPPORT_ROWS = [
    {
        id: -7,
        label: 'ES256 (-7)',
        support: {
            chromeEdge: { status: 'yes', note: null },
            safari: { status: 'yes', note: '≥ 17' },
            firefox: { status: 'yes', note: '≥ 125' },
            androidChrome: { status: 'yes', note: null },
        },
    },
    {
        id: -257,
        label: 'RS256 (-257)',
        support: {
            chromeEdge: { status: 'yes', note: null },
            safari: { status: 'yes', note: '≥ 17' },
            firefox: { status: 'yes', note: '≥ 113' },
            androidChrome: { status: 'yes', note: null },
        },
    },
    {
        id: -8,
        label: 'EdDSA (-8)',
        support: {
            chromeEdge: { status: 'yes', note: null },
            safari: { status: 'partial', note: '≥ 17' },
            firefox: { status: 'yes', note: '≥ 125' },
            androidChrome: { status: 'yes', note: null },
        },
    },
    {
        id: -38,
        label: 'ES384 (-38)',
        support: {
            chromeEdge: { status: 'partial', note: null },
            safari: { status: 'partial', note: null },
            firefox: { status: 'yes', note: '≥ 125' },
            androidChrome: { status: 'partial', note: null },
        },
    },
    {
        id: -39,
        label: 'ES512 (-39)',
        support: {
            chromeEdge: { status: 'partial', note: null },
            safari: { status: 'no', note: null },
            firefox: { status: 'partial', note: null },
            androidChrome: { status: 'partial', note: null },
        },
    },
    {
        id: -65535,
        label: 'RS1 (-65535)',
        note: 'Deprecated Algorithm',
        support: {
            chromeEdge: { status: 'no', note: null },
            safari: { status: 'no', note: null },
            firefox: { status: 'no', note: null },
            androidChrome: { status: 'no', note: null },
        },
    },
    {
        id: -47,
        label: 'ES256K (-47)',
        support: {
            chromeEdge: { status: 'yes', note: '≥ 115' },
            safari: { status: 'yes', note: '≥ 123' },
            firefox: { status: 'partial', note: null },
            androidChrome: { status: 'partial', note: null },
        },
    },
    {
        id: -258,
        label: 'RS384 (-258)',
        support: {
            chromeEdge: { status: 'partial', note: null },
            safari: { status: 'partial', note: null },
            firefox: { status: 'partial', note: null },
            androidChrome: { status: 'partial', note: null },
        },
    },
    {
        id: -259,
        label: 'RS512 (-259)',
        support: {
            chromeEdge: { status: 'partial', note: null },
            safari: { status: 'partial', note: null },
            firefox: { status: 'partial', note: null },
            androidChrome: { status: 'partial', note: null },
        },
    },
];

const SUPPORT_COLUMN_KEYS = ['chromeEdge', 'safari', 'firefox', 'androidChrome'];
const TRANSPORT_CANDIDATES = [
    { key: 'internal', label: 'Internal', test: data => data.platformAuthenticator === true },
    { key: 'usb', label: 'USB', test: () => 'usb' in navigator },
    { key: 'hid', label: 'HID', test: () => 'hid' in navigator },
    { key: 'nfc', label: 'NFC', test: () => 'nfc' in navigator },
    { key: 'ble', label: 'BLE', test: () => 'bluetooth' in navigator },
    { key: 'cable', label: 'Cable / Serial', test: () => 'serial' in navigator },
];

function normalizeBrandName(brand) {
    if (!brand) {
        return 'Unknown Browser';
    }

    if (/Chromium/i.test(brand)) {
        return 'Chromium';
    }

    if (/Edg/i.test(brand)) {
        return 'Microsoft Edge';
    }

    if (/Chrome/i.test(brand)) {
        return 'Google Chrome';
    }

    if (/Safari/i.test(brand) && !/Chrome/i.test(brand)) {
        return 'Safari';
    }

    if (/Firefox/i.test(brand)) {
        return 'Mozilla Firefox';
    }

    return brand;
}

function selectBrandEntry(brandList) {
    if (!Array.isArray(brandList) || brandList.length === 0) {
        return null;
    }

    const filtered = brandList.filter(brand => {
        const label = (brand?.brand || '').trim();
        return label !== '' && !/Not.?A.?Brand/i.test(label);
    });

    const candidates = filtered.length > 0 ? filtered : brandList;

    return (
        candidates.find(brand => /Chrom(e|ium)/i.test(brand.brand)) ||
        candidates.find(brand => /Edg/i.test(brand.brand)) ||
        candidates.find(brand => /Firefox/i.test(brand.brand)) ||
        candidates.find(brand => /Safari/i.test(brand.brand)) ||
        candidates[0]
    );
}

function parseFromUserAgentString(uaString, defaultPlatform) {
    const platform = defaultPlatform || 'Unknown System';
    const browsers = [
        { regex: /(Edg|EdgiOS|EdgA)\/([\d.]+)/, name: 'Microsoft Edge' },
        { regex: /(OPR|OPiOS)\/([\d.]+)/, name: 'Opera' },
        { regex: /(FxiOS)\/([\d.]+)/, name: 'Firefox (iOS)' },
        { regex: /(Firefox)\/([\d.]+)/, name: 'Mozilla Firefox' },
        { regex: /(Chrome|CriOS)\/([\d.]+)/, name: 'Google Chrome' },
        { regex: /(Version)\/([\d.]+).*Safari\//, name: 'Safari' },
    ];

    for (const browser of browsers) {
        const match = browser.regex.exec(uaString);
        if (match) {
            return {
                name: browser.name,
                version: match[2],
                platform,
            };
        }
    }

    return {
        name: 'Unknown Browser',
        version: null,
        platform,
    };
}

async function detectBrowser() {
    const navigatorUA = typeof navigator !== 'undefined' ? navigator : null;
    const uaString = navigatorUA?.userAgent || '';
    const fallbackPlatform = navigatorUA?.platform || 'Unknown System';

    const uaFallback = parseFromUserAgentString(uaString, fallbackPlatform);

    let name = uaFallback.name;
    let version = uaFallback.version;
    let platform = uaFallback.platform;

    const uaData = navigatorUA?.userAgentData;

    const maybeUpdateFromBrand = brandEntry => {
        if (!brandEntry) {
            return;
        }

        const brandName = (brandEntry.brand || '').trim();
        if (brandName && !/Not.?A.?Brand/i.test(brandName) && name === 'Unknown Browser') {
            name = normalizeBrandName(brandName);
        }

        if (
            brandName &&
            !/Not.?A.?Brand/i.test(brandName) &&
            typeof brandEntry.version === 'string' &&
            brandEntry.version.trim() !== ''
        ) {
            const candidateSegments = brandEntry.version.split('.');
            const currentSegments = typeof version === 'string' ? version.split('.') : [];
            const fallbackIsGeneric =
                currentSegments.length > 1 && currentSegments.slice(1).every(segment => /^0+$/.test(segment));
            const candidateIsGeneric =
                candidateSegments.length > 1 && candidateSegments.slice(1).every(segment => /^0+$/.test(segment));

            if (
                !version ||
                candidateSegments.length > currentSegments.length ||
                (fallbackIsGeneric && !candidateIsGeneric)
            ) {
                version = brandEntry.version;
            }
        }
    };

    if (uaData) {
        const brandList = Array.isArray(uaData.brands) ? uaData.brands : null;

        if (typeof uaData.platform === 'string' && uaData.platform.trim() !== '') {
            platform = uaData.platform;
        }

        if (typeof uaData.getHighEntropyValues === 'function') {
            try {
                const highEntropy = await uaData.getHighEntropyValues(['platform', 'platformVersion', 'fullVersionList']);
                if (typeof highEntropy?.platform === 'string' && highEntropy.platform.trim() !== '') {
                    platform = highEntropy.platform;
                }

                const fullVersionList =
                    Array.isArray(highEntropy?.fullVersionList) && highEntropy.fullVersionList.length > 0
                        ? highEntropy.fullVersionList
                        : brandList;

                const brandEntry = selectBrandEntry(fullVersionList);
                maybeUpdateFromBrand(brandEntry);
            } catch (error) {
                console.warn('Unable to retrieve high-entropy UA data', error);
                const fallbackBrand = selectBrandEntry(brandList);
                maybeUpdateFromBrand(fallbackBrand);
            }
        } else {
            const fallbackBrand = selectBrandEntry(brandList);
            maybeUpdateFromBrand(fallbackBrand);
        }
    }

    return {
        name: name || 'Unknown Browser',
        version: version || null,
        platform: platform || 'Unknown System',
    };
}

async function detectPlatformAuthenticator() {
    if (!('PublicKeyCredential' in window)) {
        return null;
    }

    try {
        if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
            return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        }
    } catch (error) {
        console.warn('Failed to query platform authenticator availability', error);
    }

    return null;
}

async function detectCrossPlatformAuthenticator(hasWebAuthn) {
    if (!hasWebAuthn) {
        return false;
    }

    if (typeof PublicKeyCredential?.isConditionalMediationAvailable === 'function') {
        try {
            return await PublicKeyCredential.isConditionalMediationAvailable();
        } catch (error) {
            console.warn('Failed to query conditional mediation availability', error);
        }
    }

    if ('hid' in navigator || 'usb' in navigator || 'nfc' in navigator || 'bluetooth' in navigator) {
        return true;
    }

    return null;
}

function detectTransports(data) {
    const transports = [];

    TRANSPORT_CANDIDATES.forEach(candidate => {
        try {
            if (candidate.test(data)) {
                transports.push(candidate.label);
            }
        } catch (error) {
            console.warn('Transport detection failed for', candidate.key, error);
        }
    });

    const unique = Array.from(new Set(transports));
    return unique;
}

function setFeatureValue(container, value) {
    if (!container) {
        return;
    }

    const valueElement = container.querySelector('.analyze-browser-panel__feature-value');
    if (!valueElement) {
        return;
    }

    let status = 'unknown';
    let text = 'Unknown';

    if (value === true) {
        status = 'true';
        text = 'Yes';
    } else if (value === false) {
        status = 'false';
        text = 'No';
    }

    valueElement.dataset.status = status;
    valueElement.textContent = text;
}

function renderTransports(listElement, transports) {
    if (!listElement) {
        return;
    }

    listElement.innerHTML = '';

    const values = transports.length > 0 ? transports : ['No supported transports detected'];

    values.forEach((transport, index) => {
        const item = document.createElement('li');
        item.className = 'analyze-browser-panel__transport-item';
        item.textContent = transport;

        if (transports.length === 0 && index === 0) {
            item.classList.add('analyze-browser-panel__transport-item--empty');
        }

        listElement.appendChild(item);
    });
}

function createSupportCell(row, columnKey) {
    const cell = document.createElement('td');
    const support = row.support[columnKey];
    const status = support?.status || 'no';
    const note = support?.note;

    const statusClass = `analyze-browser__support--${status}`;
    const wrapper = document.createElement('span');
    wrapper.className = `analyze-browser__support ${statusClass}`;
    wrapper.textContent = status === 'yes' ? 'Yes' : status === 'partial' ? 'Partial' : 'No';

    if (note) {
        const noteElement = document.createElement('span');
        noteElement.className = 'analyze-browser__support-note';
        noteElement.textContent = note;
        wrapper.appendChild(noteElement);
    }

    cell.appendChild(wrapper);
    return cell;
}

function renderCoseTable(tableBody) {
    if (!tableBody) {
        return;
    }

    tableBody.innerHTML = '';

    COSE_SUPPORT_ROWS.forEach(row => {
        const tr = document.createElement('tr');

        const algorithmCell = document.createElement('th');
        algorithmCell.scope = 'row';
        const noteHtml = row.note ? `<br><span class="analyze-browser-panel__alg-note">${row.note}</span>` : '';
        algorithmCell.innerHTML = `<span class="analyze-browser-panel__alg-name">${row.label}</span>${noteHtml}`;

        tr.appendChild(algorithmCell);

        SUPPORT_COLUMN_KEYS.forEach(columnKey => {
            tr.appendChild(createSupportCell(row, columnKey));
        });

        tableBody.appendChild(tr);
    });
}

function applyAnalysisResults(results) {
    const panel = document.getElementById('analyze-browser-panel');
    if (!panel) {
        return;
    }

    const browserNameEl = document.getElementById('analyze-browser-name');
    const browserVersionEl = document.getElementById('analyze-browser-version');
    const systemEl = document.getElementById('analyze-browser-system');

    if (browserNameEl) {
        browserNameEl.textContent = results.browser.name || 'Unknown Browser';
    }

    if (browserVersionEl) {
        browserVersionEl.textContent = results.browser.version || '—';
    }

    if (systemEl) {
        systemEl.textContent = results.browser.platform || '—';
    }

    const featureList = panel.querySelector('[data-role="feature-list"]');
    if (featureList) {
        setFeatureValue(featureList.querySelector('[data-feature="webauthn"]'), results.features.webauthn);
        setFeatureValue(featureList.querySelector('[data-feature="platform"]'), results.features.platformAuthenticator);
        setFeatureValue(featureList.querySelector('[data-feature="cross-platform"]'), results.features.crossPlatform);
    }

    const transportList = panel.querySelector('[data-role="transport-list"]');
    renderTransports(transportList, results.features.transports);

    const tableBody = panel.querySelector('[data-role="cose-table-body"]');
    if (tableBody && !tableBody.hasChildNodes()) {
        renderCoseTable(tableBody);
    }
}

function showLoader(loader) {
    if (!loader) {
        return;
    }

    loader.hidden = false;
    loader.setAttribute('aria-hidden', 'false');
    requestAnimationFrame(() => {
        loader.classList.add('is-open');
        updateGlobalScrollLock();
    });
}

function hideLoader(loader) {
    if (!loader) {
        return;
    }

    loader.classList.remove('is-open');
    loader.setAttribute('aria-hidden', 'true');
    setTimeout(() => {
        loader.hidden = true;
        updateGlobalScrollLock();
    }, 260);
}

function openPanel(panel) {
    if (!panel) {
        return;
    }

    panel.hidden = false;
    panel.setAttribute('aria-hidden', 'false');
    requestAnimationFrame(() => {
        panel.classList.add('is-open');
        updateGlobalScrollLock();

        const focusTarget = panel.querySelector('[data-action="close"]');
        if (focusTarget && typeof focusTarget.focus === 'function') {
            focusTarget.focus({ preventScroll: true });
        }
    });
}

function closePanel(panel) {
    if (!panel || !panel.classList.contains('is-open')) {
        return;
    }

    panel.classList.add('is-closing');
    panel.classList.remove('is-open');
    panel.setAttribute('aria-hidden', 'true');

    setTimeout(() => {
        panel.classList.remove('is-closing');
        panel.hidden = true;
        updateGlobalScrollLock();
    }, 260);
}

async function gatherAnalysis() {
    const hasWebAuthn = 'PublicKeyCredential' in window;
    const [browser, platformAuthenticator, crossPlatform] = await Promise.all([
        detectBrowser(),
        detectPlatformAuthenticator(),
        detectCrossPlatformAuthenticator(hasWebAuthn),
    ]);

    const transports = detectTransports({ platformAuthenticator });

    return {
        browser,
        features: {
            webauthn: hasWebAuthn,
            platformAuthenticator,
            crossPlatform,
            transports,
        },
    };
}

export function initializeAnalyzeBrowser() {
    const trigger = document.querySelector('[data-analyze-browser-trigger]');
    const loader = document.getElementById('analyze-browser-loader');
    const panel = document.getElementById('analyze-browser-panel');

    if (!trigger || !loader || !panel) {
        return;
    }

    let isRunning = false;

    const handleClose = () => {
        closePanel(panel);
        if (typeof trigger.focus === 'function') {
            trigger.focus({ preventScroll: true });
        }
    };

    panel.addEventListener('click', event => {
        const target = event.target;
        if (!(target instanceof HTMLElement)) {
            return;
        }

        if (target.dataset.action === 'close') {
            event.preventDefault();
            handleClose();
        }
    });

    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && panel.classList.contains('is-open')) {
            handleClose();
        }
    });

    trigger.addEventListener('click', async () => {
        if (isRunning) {
            return;
        }

        isRunning = true;
        trigger.disabled = true;
        showLoader(loader);

        const start = performance.now();
        let results = null;
        try {
            results = await gatherAnalysis();
        } catch (error) {
            console.error('Browser analysis failed', error);
        }

        if (!results) {
            const fallbackBrowser = await detectBrowser().catch(() => ({
                name: 'Unknown Browser',
                version: null,
                platform: 'Unknown System',
            }));

            results = {
                browser: fallbackBrowser,
                features: {
                    webauthn: 'PublicKeyCredential' in window,
                    platformAuthenticator: null,
                    crossPlatform: null,
                    transports: [],
                },
            };
        }

        const elapsed = performance.now() - start;
        const remaining = Math.max(0, MIN_LOADER_DURATION_MS - elapsed);

        await new Promise(resolve => setTimeout(resolve, remaining));

        hideLoader(loader);

        applyAnalysisResults(results);
        openPanel(panel);

        trigger.disabled = false;
        isRunning = false;
    });
}
