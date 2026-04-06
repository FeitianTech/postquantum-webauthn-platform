import { updateGlobalScrollLock } from './ui.js';

const TRANSPORT_CANDIDATES = [
    { key: 'internal', label: 'Internal', test: data => data.platformAuthenticator === true },
    { key: 'hybrid', label: 'Hybrid', test: data => data.clientCapabilities?.hybridTransport === true },
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

function normalizeSystemName(rawPlatform, uaString, maxTouchPoints) {
    const rawValue = typeof rawPlatform === 'string' ? rawPlatform.trim() : '';
    const normalizedPlatform = rawValue.toLowerCase();
    const normalizedUa = typeof uaString === 'string' ? uaString.toLowerCase() : '';

    const uaLooksAppleMobile = /\b(iphone|ipad|ipod)\b/.test(normalizedUa);
    const uaLooksAndroid = /\bandroid\b/.test(normalizedUa);
    const uaLooksWindows = /\bwindows nt\b/.test(normalizedUa);
    const uaLooksMac = /\b(macintosh|mac os x|macos)\b/.test(normalizedUa);
    const uaLooksChromeOs = /\bcros\b/.test(normalizedUa);
    const isLikelyIpadDesktopMode =
        (normalizedPlatform === 'macintel' || normalizedPlatform === 'mac') &&
        Number(maxTouchPoints || 0) > 1 &&
        (uaLooksAppleMobile || /\bmobile\b/.test(normalizedUa));

    if (isLikelyIpadDesktopMode || /\bipad\b/.test(normalizedUa) || /^ipad/.test(normalizedPlatform)) {
        return 'iPadOS';
    }

    if (uaLooksAppleMobile || /^iphone/.test(normalizedPlatform) || /^ipod/.test(normalizedPlatform) || normalizedPlatform === 'ios') {
        return 'iOS';
    }

    if (uaLooksAndroid || /^android/.test(normalizedPlatform)) {
        return 'Android';
    }

    if (
        normalizedPlatform === 'macintel' ||
        /^mac/.test(normalizedPlatform) ||
        normalizedPlatform === 'darwin' ||
        uaLooksMac
    ) {
        return 'macOS';
    }

    if (/^win/.test(normalizedPlatform) || uaLooksWindows) {
        return 'Windows';
    }

    if (/\bcros\b/.test(normalizedPlatform) || /chrome\s?os/.test(normalizedPlatform) || uaLooksChromeOs) {
        return 'ChromeOS';
    }

    if (/\blinux\b/.test(normalizedPlatform) || /\blinux\b/.test(normalizedUa)) {
        return 'Linux';
    }

    if (/\b(freebsd|openbsd|netbsd|bsd)\b/.test(normalizedPlatform) || /\b(freebsd|openbsd|netbsd)\b/.test(normalizedUa)) {
        return 'BSD';
    }

    return 'Unknown System';
}

function parseFromUserAgentString(uaString, defaultPlatform, maxTouchPoints) {
    const platform = normalizeSystemName(defaultPlatform, uaString, maxTouchPoints);
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

function safeReadUserAgentDataBrands(uaData) {
    try {
        const brands = uaData?.brands;
        return Array.isArray(brands) ? brands : null;
    } catch (error) {
        console.warn('Unable to read UA brand list', error);
        return null;
    }
}

function safeReadUserAgentDataPlatform(uaData) {
    try {
        const platform = uaData?.platform;
        return typeof platform === 'string' ? platform : null;
    } catch (error) {
        console.warn('Unable to read UA platform', error);
        return null;
    }
}

async function detectBrowser() {
    const navigatorUA = typeof navigator !== 'undefined' ? navigator : null;
    const uaString = navigatorUA?.userAgent || '';
    const fallbackPlatform = navigatorUA?.platform || 'Unknown System';
    const maxTouchPoints = Number(navigatorUA?.maxTouchPoints || 0);

    const uaFallback = parseFromUserAgentString(uaString, fallbackPlatform, maxTouchPoints);

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
        const brandList = safeReadUserAgentDataBrands(uaData);

        const uaPlatform = safeReadUserAgentDataPlatform(uaData);
        if (typeof uaPlatform === 'string' && uaPlatform.trim() !== '') {
            platform = uaPlatform;
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
        platform: normalizeSystemName(platform, uaString, maxTouchPoints),
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

async function detectClientCapabilities(hasWebAuthn) {
    if (!hasWebAuthn || !('PublicKeyCredential' in window)) {
        return null;
    }

    if (typeof PublicKeyCredential.getClientCapabilities !== 'function') {
        return null;
    }

    try {
        const raw = await PublicKeyCredential.getClientCapabilities();
        if (!raw || typeof raw !== 'object') {
            return null;
        }

        const entries = raw instanceof Map ? Array.from(raw.entries()) : Object.entries(raw);
        const normalized = {};
        entries.forEach(([key, value]) => {
            if (typeof key === 'string' && typeof value === 'boolean') {
                normalized[key] = value;
            }
        });

        return Object.keys(normalized).length > 0 ? normalized : null;
    } catch (error) {
        console.warn('Failed to query WebAuthn client capabilities', error);
    }

    return null;
}

async function detectCrossPlatformAuthenticator(hasWebAuthn, clientCapabilities) {
    if (!hasWebAuthn) {
        return false;
    }

    if (typeof PublicKeyCredential?.isExternalCTAP2SecurityKeySupported === 'function') {
        try {
            return await PublicKeyCredential.isExternalCTAP2SecurityKeySupported();
        } catch (error) {
            console.warn('Failed to query external CTAP2 authenticator support', error);
        }
    }

    if (typeof clientCapabilities?.hybridTransport === 'boolean') {
        return clientCapabilities.hybridTransport;
    }

    const hasExternalTransportApi =
        'hid' in navigator || 'usb' in navigator || 'nfc' in navigator || 'bluetooth' in navigator || 'serial' in navigator;
    if (hasExternalTransportApi) {
        return true;
    }

    if (typeof PublicKeyCredential?.isConditionalMediationAvailable === 'function') {
        try {
            const conditionalMediation = await PublicKeyCredential.isConditionalMediationAvailable();
            if (conditionalMediation === false) {
                return null;
            }
        } catch (error) {
            console.warn('Failed to query conditional mediation availability', error);
        }
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
}

function openPanel(panel) {
    if (!panel) {
        return;
    }

    const content = panel.querySelector('.analyze-browser-panel__content');
    if (content) {
        content.scrollTop = 0;
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

    const content = panel.querySelector('.analyze-browser-panel__content');
    if (content) {
        content.scrollTop = 0;
    }

    panel.classList.remove('is-open');
    panel.classList.remove('is-closing');
    panel.setAttribute('aria-hidden', 'true');
    panel.hidden = true;
    updateGlobalScrollLock();
}

async function gatherAnalysis() {
    const hasWebAuthn = 'PublicKeyCredential' in window;
    const [browser, platformAuthenticator, clientCapabilities] = await Promise.all([
        detectBrowser(),
        detectPlatformAuthenticator(),
        detectClientCapabilities(hasWebAuthn),
    ]);

    const crossPlatform = await detectCrossPlatformAuthenticator(hasWebAuthn, clientCapabilities);

    const transports = detectTransports({ platformAuthenticator, clientCapabilities });

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
    const panel = document.getElementById('analyze-browser-panel');

    if (!trigger || !panel) {
        return;
    }

    let isRunning = false;
    let hasCompletedInitialAnalysis = false;
    let analysisResultsCache = null;

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

        if (hasCompletedInitialAnalysis && analysisResultsCache) {
            applyAnalysisResults(analysisResultsCache);
            openPanel(panel);
            return;
        }

        isRunning = true;
        trigger.disabled = true;

        try {
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

            analysisResultsCache = results;
            hasCompletedInitialAnalysis = true;

            applyAnalysisResults(results);
            openPanel(panel);
        } finally {
            trigger.disabled = false;
            isRunning = false;
        }
    });
}
