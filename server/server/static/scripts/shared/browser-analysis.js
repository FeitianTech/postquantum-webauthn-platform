import { openModal, closeModal, updateGlobalScrollLock } from './ui.js';

const ANALYSIS_MODAL_ID = 'browserAnalysisModal';
const MIN_LOADING_DURATION_MS = 1000;
const CLOSE_ANIMATION_DURATION_MS = 260;

const BROWSER_IDS = {
    CHROME: 'chrome',
    EDGE: 'edge',
    SAFARI: 'safari',
    FIREFOX: 'firefox'
};

const OS_IDS = {
    WINDOWS: 'windows',
    MACOS: 'macos',
    IOS: 'ios',
    ANDROID: 'android',
    LINUX: 'linux',
    CHROMEOS: 'chromeos',
    UNKNOWN: 'unknown'
};

const BROWSER_LABELS = {
    [BROWSER_IDS.CHROME]: 'Google Chrome',
    [BROWSER_IDS.EDGE]: 'Microsoft Edge',
    [BROWSER_IDS.SAFARI]: 'Apple Safari',
    [BROWSER_IDS.FIREFOX]: 'Mozilla Firefox'
};

const OS_LABELS = {
    [OS_IDS.WINDOWS]: 'Windows',
    [OS_IDS.MACOS]: 'macOS',
    [OS_IDS.IOS]: 'iOS / iPadOS',
    [OS_IDS.ANDROID]: 'Android',
    [OS_IDS.LINUX]: 'Linux',
    [OS_IDS.CHROMEOS]: 'ChromeOS',
    [OS_IDS.UNKNOWN]: 'Unknown OS'
};

// Capability data references:
// - passkeys.dev device support matrix: https://raw.githubusercontent.com/passkeydeveloper/passkeys.dev/main/content/en/device-support/index.md
// - passkeys.dev platform docs: Android https://raw.githubusercontent.com/passkeydeveloper/passkeys.dev/main/content/en/docs/reference/android.md,
//   iOS https://raw.githubusercontent.com/passkeydeveloper/passkeys.dev/main/content/en/docs/reference/ios.md,
//   macOS https://raw.githubusercontent.com/passkeydeveloper/passkeys.dev/main/content/en/docs/reference/macos.md,
//   Windows https://raw.githubusercontent.com/passkeydeveloper/passkeys.dev/main/content/en/docs/reference/windows.md
// - MDN Browser Compatibility Data for PublicKeyCredential: https://raw.githubusercontent.com/mdn/browser-compat-data/main/api/PublicKeyCredential.json
// - MDN guidance on COSE algorithms: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/pubKeyCredParams
// - WebAuthn Level 2 spec credProps extension: https://www.w3.org/TR/webauthn-2/#sctn-credProps-extension

const SUPPORT_MATRIX_DATA = {
    platform: {
        [BROWSER_IDS.CHROME]: {
            [OS_IDS.WINDOWS]: 'supported',
            [OS_IDS.MACOS]: 'supported',
            [OS_IDS.IOS]: 'supported',
            [OS_IDS.ANDROID]: 'supported'
        },
        [BROWSER_IDS.EDGE]: {
            [OS_IDS.WINDOWS]: 'supported',
            [OS_IDS.MACOS]: 'supported',
            [OS_IDS.IOS]: 'supported',
            [OS_IDS.ANDROID]: 'supported'
        },
        [BROWSER_IDS.SAFARI]: {
            [OS_IDS.WINDOWS]: 'na',
            [OS_IDS.MACOS]: 'supported',
            [OS_IDS.IOS]: 'supported',
            [OS_IDS.ANDROID]: 'na'
        },
        [BROWSER_IDS.FIREFOX]: {
            [OS_IDS.WINDOWS]: 'supported',
            [OS_IDS.MACOS]: 'supported',
            [OS_IDS.IOS]: 'supported',
            [OS_IDS.ANDROID]: 'unsupported'
        }
    },
    cross: {
        [BROWSER_IDS.CHROME]: {
            [OS_IDS.WINDOWS]: 'supported',
            [OS_IDS.MACOS]: 'supported',
            [OS_IDS.IOS]: 'supported',
            [OS_IDS.ANDROID]: 'supported'
        },
        [BROWSER_IDS.EDGE]: {
            [OS_IDS.WINDOWS]: 'supported',
            [OS_IDS.MACOS]: 'supported',
            [OS_IDS.IOS]: 'supported',
            [OS_IDS.ANDROID]: 'supported'
        },
        [BROWSER_IDS.SAFARI]: {
            [OS_IDS.WINDOWS]: 'na',
            [OS_IDS.MACOS]: 'supported',
            [OS_IDS.IOS]: 'supported',
            [OS_IDS.ANDROID]: 'na'
        },
        [BROWSER_IDS.FIREFOX]: {
            [OS_IDS.WINDOWS]: 'supported',
            [OS_IDS.MACOS]: 'supported',
            [OS_IDS.IOS]: 'supported',
            [OS_IDS.ANDROID]: 'unsupported'
        }
    },
    cose: {
        [BROWSER_IDS.CHROME]: {
            [OS_IDS.WINDOWS]: 'supported',
            [OS_IDS.MACOS]: 'supported',
            [OS_IDS.IOS]: 'supported',
            [OS_IDS.ANDROID]: 'supported'
        },
        [BROWSER_IDS.EDGE]: {
            [OS_IDS.WINDOWS]: 'supported',
            [OS_IDS.MACOS]: 'supported',
            [OS_IDS.IOS]: 'supported',
            [OS_IDS.ANDROID]: 'supported'
        },
        [BROWSER_IDS.SAFARI]: {
            [OS_IDS.WINDOWS]: 'na',
            [OS_IDS.MACOS]: 'supported',
            [OS_IDS.IOS]: 'supported',
            [OS_IDS.ANDROID]: 'na'
        },
        [BROWSER_IDS.FIREFOX]: {
            [OS_IDS.WINDOWS]: 'supported',
            [OS_IDS.MACOS]: 'supported',
            [OS_IDS.IOS]: 'supported',
            [OS_IDS.ANDROID]: 'unsupported'
        }
    }
};

const MATRIX_TITLES = {
    platform: 'Platform authenticator availability',
    cross: 'Cross-platform authenticator support',
    cose: 'COSE key support'
};

const STATUS_SYMBOL = {
    supported: '✓',
    unsupported: '✕',
    na: 'N/A'
};

const STATUS_CLASS = {
    supported: 'browser-analysis-table__status--supported',
    unsupported: 'browser-analysis-table__status--unsupported',
    na: 'browser-analysis-table__status--na'
};

const DEFAULT_UNKNOWN_MESSAGE = 'Not documented for this browser and OS combination.';

const STATIC_CAPABILITIES = {
    crossPlatform: {
        [BROWSER_IDS.CHROME]: {
            [OS_IDS.WINDOWS]: {
                supported: true,
                note: 'Windows Hello supports cross-device passkeys and external authenticators in Chrome.'
            },
            [OS_IDS.MACOS]: {
                supported: true,
                note: 'Chrome integrates with iCloud Keychain and supports external authenticators on macOS.'
            },
            [OS_IDS.IOS]: {
                supported: true,
                note: 'Chrome on iOS delegates to the system WebAuthn implementation with passkey and security key support.'
            },
            [OS_IDS.ANDROID]: {
                supported: true,
                note: 'Chrome on Android supports passkeys, Credential Manager, and FIDO security keys.'
            }
        },
        [BROWSER_IDS.EDGE]: {
            [OS_IDS.WINDOWS]: {
                supported: true,
                note: 'Edge supports Windows Hello, FIDO cross-device, and security keys on Windows.'
            },
            [OS_IDS.MACOS]: {
                supported: true,
                note: 'Edge relies on macOS passkey APIs and supports external authenticators.'
            },
            [OS_IDS.IOS]: {
                supported: true,
                note: 'Edge on iOS uses Apple’s passkey stack including external authenticators.'
            },
            [OS_IDS.ANDROID]: {
                supported: true,
                note: 'Edge on Android shares Chromium’s passkey and security key support.'
            }
        },
        [BROWSER_IDS.SAFARI]: {
            [OS_IDS.MACOS]: {
                supported: true,
                note: 'Safari on macOS supports passkeys, cross-device authentication, and FIDO2 security keys.'
            },
            [OS_IDS.IOS]: {
                supported: true,
                note: 'Safari on iOS/iPadOS supports local passkeys, security keys, and cross-device flows.'
            }
        },
        [BROWSER_IDS.FIREFOX]: {
            [OS_IDS.WINDOWS]: {
                supported: true,
                note: 'Firefox enables platform and cross-platform authenticators on Windows.'
            },
            [OS_IDS.MACOS]: {
                supported: true,
                note: 'Firefox uses macOS passkey APIs and security keys.'
            },
            [OS_IDS.IOS]: {
                supported: true,
                note: 'Firefox on iOS inherits WebKit’s passkey and security key support.'
            }
        }
    },
    algorithms: {
        [BROWSER_IDS.CHROME]: {
            [OS_IDS.WINDOWS]: ['ES256', 'RS256'],
            [OS_IDS.MACOS]: ['ES256', 'RS256'],
            [OS_IDS.IOS]: ['ES256'],
            [OS_IDS.ANDROID]: ['ES256', 'RS256']
        },
        [BROWSER_IDS.EDGE]: {
            [OS_IDS.WINDOWS]: ['ES256', 'RS256'],
            [OS_IDS.MACOS]: ['ES256', 'RS256'],
            [OS_IDS.IOS]: ['ES256'],
            [OS_IDS.ANDROID]: ['ES256', 'RS256']
        },
        [BROWSER_IDS.SAFARI]: {
            [OS_IDS.MACOS]: ['ES256'],
            [OS_IDS.IOS]: ['ES256']
        },
        [BROWSER_IDS.FIREFOX]: {
            [OS_IDS.WINDOWS]: ['ES256', 'RS256'],
            [OS_IDS.MACOS]: ['ES256', 'RS256'],
            [OS_IDS.IOS]: ['ES256']
        }
    },
    transports: {
        [BROWSER_IDS.CHROME]: {
            [OS_IDS.WINDOWS]: ['internal', 'hybrid', 'usb', 'nfc', 'ble'],
            [OS_IDS.MACOS]: ['internal', 'hybrid', 'usb', 'nfc', 'ble'],
            [OS_IDS.IOS]: ['internal', 'hybrid', 'usb', 'nfc', 'ble'],
            [OS_IDS.ANDROID]: ['internal', 'hybrid', 'usb', 'nfc', 'ble']
        },
        [BROWSER_IDS.EDGE]: {
            [OS_IDS.WINDOWS]: ['internal', 'hybrid', 'usb', 'nfc', 'ble'],
            [OS_IDS.MACOS]: ['internal', 'hybrid', 'usb', 'nfc', 'ble'],
            [OS_IDS.IOS]: ['internal', 'hybrid', 'usb', 'nfc', 'ble'],
            [OS_IDS.ANDROID]: ['internal', 'hybrid', 'usb', 'nfc', 'ble']
        },
        [BROWSER_IDS.SAFARI]: {
            [OS_IDS.MACOS]: ['internal', 'hybrid', 'usb', 'nfc', 'ble'],
            [OS_IDS.IOS]: ['internal', 'hybrid', 'usb', 'nfc', 'ble']
        },
        [BROWSER_IDS.FIREFOX]: {
            [OS_IDS.WINDOWS]: ['internal', 'usb', 'nfc', 'ble'],
            [OS_IDS.MACOS]: ['internal', 'usb', 'nfc', 'ble'],
            [OS_IDS.IOS]: ['internal', 'hybrid']
        }
    },
    extensions: {
        [BROWSER_IDS.CHROME]: {
            [OS_IDS.WINDOWS]: ['credProps', 'appidExclude'],
            [OS_IDS.MACOS]: ['credProps', 'appidExclude'],
            [OS_IDS.IOS]: ['credProps'],
            [OS_IDS.ANDROID]: ['credProps', 'appidExclude']
        },
        [BROWSER_IDS.EDGE]: {
            [OS_IDS.WINDOWS]: ['credProps', 'appidExclude'],
            [OS_IDS.MACOS]: ['credProps', 'appidExclude'],
            [OS_IDS.IOS]: ['credProps'],
            [OS_IDS.ANDROID]: ['credProps', 'appidExclude']
        },
        [BROWSER_IDS.SAFARI]: {
            [OS_IDS.MACOS]: ['credProps'],
            [OS_IDS.IOS]: ['credProps']
        },
        [BROWSER_IDS.FIREFOX]: {
            [OS_IDS.WINDOWS]: ['credProps'],
            [OS_IDS.MACOS]: ['credProps'],
            [OS_IDS.IOS]: ['credProps']
        }
    }
};

let cachedAnalysis = null;
let matrixRendered = false;
let loadingPromise = null;

function detectBrowserEnvironment() {
    const environment = {
        browserId: null,
        browserName: 'Unknown browser',
        version: 'Unknown version',
        osId: OS_IDS.UNKNOWN,
        osName: OS_LABELS[OS_IDS.UNKNOWN],
        userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : '',
        canIdentify: false
    };

    try {
        const nav = typeof navigator !== 'undefined' ? navigator : null;
        const uaData = nav && nav.userAgentData ? nav.userAgentData : null;
        const platformSource = uaData?.platform || nav?.platform || '';
        const ua = (nav?.userAgent || '').toLowerCase();
        const vendor = (nav?.vendor || '').toLowerCase();

        if (/windows/i.test(platformSource) || /win(dows)?/i.test(ua)) {
            environment.osId = OS_IDS.WINDOWS;
        } else if (/mac/i.test(platformSource) || (/mac os x/i.test(ua) && !/iphone|ipad|ipod/i.test(ua))) {
            environment.osId = OS_IDS.MACOS;
        } else if (/iphone|ipad|ipod/i.test(ua)) {
            environment.osId = OS_IDS.IOS;
        } else if (/android/i.test(platformSource) || /android/i.test(ua)) {
            environment.osId = OS_IDS.ANDROID;
        } else if (/cros/i.test(ua)) {
            environment.osId = OS_IDS.CHROMEOS;
        } else if (/linux/i.test(platformSource) || /linux/i.test(ua)) {
            environment.osId = OS_IDS.LINUX;
        }

        const browserChecks = [
            {
                id: BROWSER_IDS.EDGE,
                match: /edg(e|ios|a)?\//i,
                versionRegex: /(edg|edgios|edga)\/([\d._]+)/i
            },
            {
                id: BROWSER_IDS.FIREFOX,
                match: /firefox|fxios/i,
                versionRegex: /(firefox|fxios)\/([\d._]+)/i
            },
            {
                id: BROWSER_IDS.CHROME,
                match: /chrome|crios/i,
                versionRegex: /(chrome|crios)\/([\d._]+)/i,
                exclude: /edg(e|ios|a)?\//i
            },
            {
                id: BROWSER_IDS.SAFARI,
                match: /safari/i,
                versionRegex: /version\/([\d._]+)/i,
                vendorCheck: /apple/i
            }
        ];

        for (const candidate of browserChecks) {
            if (candidate.exclude && candidate.exclude.test(ua)) {
                continue;
            }

            if (!candidate.match.test(ua)) {
                continue;
            }

            if (candidate.vendorCheck && !candidate.vendorCheck.test(vendor)) {
                continue;
            }

            const versionMatch = candidate.versionRegex.exec(nav?.userAgent || '')
                || candidate.versionRegex.exec(nav?.appVersion || '');
            const rawVersion = versionMatch ? versionMatch[versionMatch.length - 1] : '';
            const normalizedVersion = rawVersion ? rawVersion.replace(/_/g, '.') : 'Unknown version';

            environment.browserId = candidate.id;
            environment.browserName = BROWSER_LABELS[candidate.id] || 'Unknown browser';
            environment.version = normalizedVersion;
            break;
        }

        environment.osName = OS_LABELS[environment.osId] || OS_LABELS[OS_IDS.UNKNOWN];
        environment.canIdentify = Boolean(environment.browserId && environment.osId !== OS_IDS.UNKNOWN);
    } catch (error) {
        console.error('Browser analysis failed to detect environment.', error);
    }

    return environment;
}

async function detectPlatformAuthenticatorAvailability() {
    if (typeof window === 'undefined' || typeof window.PublicKeyCredential === 'undefined') {
        return { supported: false, message: 'WebAuthn API unavailable.' };
    }

    if (typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== 'function') {
        return { supported: null, message: 'Browser does not expose platform authenticator detection.' };
    }

    try {
        const supported = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        return {
            supported,
            message: supported ? 'Available via PublicKeyCredential API.' : 'Platform authenticator not reported by the API.'
        };
    } catch (error) {
        return {
            supported: null,
            message: `Detection error: ${error instanceof Error ? error.message : 'Unknown issue.'}`
        };
    }
}

function getStaticCapability(browserId, osId, category) {
    const byBrowser = STATIC_CAPABILITIES[category]?.[browserId];
    if (!byBrowser) {
        return null;
    }

    return byBrowser[osId] ?? null;
}

function formatArray(values) {
    if (!Array.isArray(values) || values.length === 0) {
        return DEFAULT_UNKNOWN_MESSAGE;
    }

    return values.join(', ');
}

function getMatrixStatus(matrixType, browserId, osId) {
    const browserRow = SUPPORT_MATRIX_DATA[matrixType]?.[browserId];
    if (!browserRow) {
        return 'na';
    }

    return browserRow[osId] || 'na';
}

function renderMatrixTable(type, container) {
    const browserKeys = [BROWSER_IDS.CHROME, BROWSER_IDS.EDGE, BROWSER_IDS.SAFARI, BROWSER_IDS.FIREFOX];
    const osKeys = [OS_IDS.WINDOWS, OS_IDS.MACOS, OS_IDS.IOS, OS_IDS.ANDROID];

    const wrapper = document.createElement('div');
    wrapper.className = 'browser-analysis-table';

    const title = document.createElement('h4');
    title.className = 'browser-analysis-table__title';
    title.textContent = MATRIX_TITLES[type] || 'Support matrix';
    wrapper.appendChild(title);

    const table = document.createElement('table');
    table.className = 'browser-analysis-table__grid';
    table.setAttribute('role', 'table');

    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    const corner = document.createElement('th');
    corner.textContent = 'Browser';
    headerRow.appendChild(corner);

    osKeys.forEach(osId => {
        const th = document.createElement('th');
        th.scope = 'col';
        th.textContent = OS_LABELS[osId];
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');

    browserKeys.forEach(browserId => {
        const row = document.createElement('tr');
        const header = document.createElement('th');
        header.scope = 'row';
        header.textContent = BROWSER_LABELS[browserId];
        row.appendChild(header);

        osKeys.forEach(osId => {
            const td = document.createElement('td');
            const status = getMatrixStatus(type, browserId, osId);
            const span = document.createElement('span');
            span.className = `browser-analysis-table__status ${STATUS_CLASS[status] || STATUS_CLASS.na}`;
            span.textContent = STATUS_SYMBOL[status] || STATUS_SYMBOL.na;
            td.appendChild(span);
            row.appendChild(td);
        });

        tbody.appendChild(row);
    });

    table.appendChild(tbody);
    wrapper.appendChild(table);
    container.innerHTML = '';
    container.appendChild(wrapper);
}

function renderMatricesOnce(modalElement) {
    if (matrixRendered) {
        return;
    }

    const containers = modalElement.querySelectorAll('[data-browser-analysis-matrix]');
    containers.forEach(container => {
        const type = container.getAttribute('data-browser-analysis-matrix');
        if (type && SUPPORT_MATRIX_DATA[type]) {
            renderMatrixTable(type, container);
        }
    });

    matrixRendered = true;
}

function toggleLoadingState(modalElement, showLoading) {
    const loading = modalElement.querySelector('[data-browser-analysis-loading]');
    const results = modalElement.querySelector('[data-browser-analysis-results]');

    if (loading) {
        loading.hidden = !showLoading;
    }

    if (results) {
        results.hidden = Boolean(showLoading);
    }
}

function updateResultText(modalElement, selector, text) {
    const target = modalElement.querySelector(selector);
    if (target) {
        target.textContent = text;
    }
}

function renderAnalysisResults(modalElement, analysis) {
    const { environment, webauthnSupported, platformCheck, combinationData } = analysis;

    updateResultText(modalElement, '[data-browser-analysis-browser]', environment.browserName);
    updateResultText(modalElement, '[data-browser-analysis-version]', environment.version);
    updateResultText(modalElement, '[data-browser-analysis-os]', environment.osName);

    updateResultText(
        modalElement,
        '[data-browser-analysis-webauthn]',
        webauthnSupported ? 'Yes' : 'No'
    );

    let platformMessage = platformCheck.message;
    if (platformCheck.supported === true) {
        platformMessage = `${platformMessage} (detected)`;
    } else if (platformCheck.supported === false) {
        platformMessage = `${platformMessage} (not available)`;
    }

    const staticPlatform = getStaticCapability(environment.browserId, environment.osId, 'crossPlatform');
    if (staticPlatform && platformCheck.supported !== true) {
        if (staticPlatform.supported) {
            platformMessage = `${platformMessage} — platform support documented.`;
        } else {
            platformMessage = `${platformMessage} — platform authenticator support is not documented.`;
        }
    }

    updateResultText(modalElement, '[data-browser-analysis-platform]', platformMessage);

    const crossData = combinationData?.crossPlatform || staticPlatform;
    if (crossData) {
        const crossText = crossData.supported
            ? `Supported${crossData.note ? ` — ${crossData.note}` : ''}`
            : `Not supported${crossData?.note ? ` — ${crossData.note}` : ''}`;
        updateResultText(modalElement, '[data-browser-analysis-cross]', crossText);
    } else {
        updateResultText(modalElement, '[data-browser-analysis-cross]', DEFAULT_UNKNOWN_MESSAGE);
    }

    const algorithms = combinationData?.algorithms
        || getStaticCapability(environment.browserId, environment.osId, 'algorithms');
    updateResultText(modalElement, '[data-browser-analysis-algorithms]', formatArray(algorithms));

    const transports = combinationData?.transports
        || getStaticCapability(environment.browserId, environment.osId, 'transports');
    updateResultText(modalElement, '[data-browser-analysis-transports]', formatArray(transports));

    const extensions = combinationData?.extensions
        || getStaticCapability(environment.browserId, environment.osId, 'extensions');
    updateResultText(modalElement, '[data-browser-analysis-extensions]', formatArray(extensions));

    renderMatricesOnce(modalElement);
    toggleLoadingState(modalElement, false);
}

async function gatherAnalysis() {
    const environment = detectBrowserEnvironment();
    const webauthnSupported = typeof window !== 'undefined' && typeof window.PublicKeyCredential !== 'undefined';
    const platformCheck = await detectPlatformAuthenticatorAvailability();

    const combinationData = environment.browserId && environment.osId
        ? {
            crossPlatform: getStaticCapability(environment.browserId, environment.osId, 'crossPlatform'),
            algorithms: getStaticCapability(environment.browserId, environment.osId, 'algorithms'),
            transports: getStaticCapability(environment.browserId, environment.osId, 'transports'),
            extensions: getStaticCapability(environment.browserId, environment.osId, 'extensions')
        }
        : null;

    return {
        environment,
        webauthnSupported,
        platformCheck,
        combinationData
    };
}

async function performAnalysis(modalElement) {
    toggleLoadingState(modalElement, true);

    if (loadingPromise) {
        return loadingPromise;
    }

    const start = typeof performance !== 'undefined' ? performance.now() : Date.now();
    loadingPromise = gatherAnalysis()
        .then(async analysis => {
            const end = typeof performance !== 'undefined' ? performance.now() : Date.now();
            const elapsed = end - start;
            const remaining = MIN_LOADING_DURATION_MS - elapsed;

            if (remaining > 0) {
                await new Promise(resolve => window.setTimeout(resolve, remaining));
            }

            cachedAnalysis = analysis;
            renderAnalysisResults(modalElement, analysis);
            loadingPromise = null;
            return analysis;
        })
        .catch(error => {
            console.error('Browser analysis failed.', error);
            toggleLoadingState(modalElement, false);
            loadingPromise = null;
            return null;
        });

    return loadingPromise;
}

function openBrowserAnalysisModal(modalElement) {
    openModal(ANALYSIS_MODAL_ID);

    if (cachedAnalysis) {
        renderAnalysisResults(modalElement, cachedAnalysis);
        return;
    }

    toggleLoadingState(modalElement, true);
    performAnalysis(modalElement).catch(error => {
        console.error('Browser analysis run error.', error);
    });
}

function closeBrowserAnalysisModal(modalElement) {
    if (modalElement.dataset.browserAnalysisClosing === 'true') {
        return;
    }

    modalElement.dataset.browserAnalysisClosing = 'true';
    modalElement.classList.add('browser-analysis-modal--closing');
    modalElement.classList.remove('open');

    window.setTimeout(() => {
        modalElement.classList.remove('browser-analysis-modal--closing');
        delete modalElement.dataset.browserAnalysisClosing;
        closeModal(ANALYSIS_MODAL_ID);
        updateGlobalScrollLock();
    }, CLOSE_ANIMATION_DURATION_MS);
}

function handleBackdropClick(event, modalElement) {
    if (event.target === modalElement) {
        closeBrowserAnalysisModal(modalElement);
    }
}

export function initializeBrowserAnalysis() {
    if (typeof document === 'undefined') {
        return;
    }

    const modalElement = document.getElementById(ANALYSIS_MODAL_ID);
    if (!modalElement) {
        return;
    }

    const triggers = Array.from(document.querySelectorAll('[data-browser-analysis-trigger]'));
    triggers.forEach(trigger => {
        trigger.addEventListener('click', () => openBrowserAnalysisModal(modalElement));
    });

    const closeButton = modalElement.querySelector('[data-browser-analysis-close]');
    if (closeButton) {
        closeButton.addEventListener('click', () => closeBrowserAnalysisModal(modalElement));
    }

    modalElement.addEventListener('click', event => handleBackdropClick(event, modalElement));

    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && modalElement.classList.contains('open')) {
            closeBrowserAnalysisModal(modalElement);
        }
    });
}
