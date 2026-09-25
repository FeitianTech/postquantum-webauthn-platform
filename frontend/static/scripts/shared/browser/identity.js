// What the browser says it is, and where each answer came from.
//
// readIdentityInputs() copies what the browser exposes; determineIdentity() is a
// pure function of that copy, so the same inputs always give the same answer.

import { attempt, describeError } from './probe.js';

export const SOURCE_TEXT = {
    'client-hints': 'from User-Agent Client Hints',
    'user-agent': 'from the user-agent string, which browsers reduce and can be spoofed',
    'brave-api': 'from navigator.brave.isBrave()',
    'platform-touch': 'from navigator.platform "MacIntel" with a touch screen, which no Mac has',
    'apple-webkit': 'every browser on iOS and iPadOS uses WebKit',
    'not-reported': 'the browser does not report this',
};

const GREASE_BRAND = /Not.?A.?Brand/i;

// A browser that names itself in the user-agent string. Checked before the Chrome
// token, which all of these also carry.
const USER_AGENT_CLAIMS = [
    { pattern: /\bEdg(?:A|iOS)?\/(\d[\d.]*)/, name: 'Microsoft Edge' },
    { pattern: /\b(?:OPR|OPT|OPiOS)\/(\d[\d.]*)/, name: 'Opera' },
    { pattern: /\bSamsungBrowser\/(\d[\d.]*)/, name: 'Samsung Internet' },
    { pattern: /\bFxiOS\/(\d[\d.]*)/, name: 'Mozilla Firefox' },
    { pattern: /\bCriOS\/(\d[\d.]*)/, name: 'Google Chrome' },
];

// Product tokens every browser of these families sends. Any other name/version
// token is some other product claiming the user-agent string.
const COMMON_PRODUCT_TOKENS = new Set([
    'Mozilla', 'AppleWebKit', 'Chrome', 'Safari', 'Version', 'Mobile', 'Gecko', 'Firefox',
]);

const USER_AGENT_SYSTEMS = [
    { pattern: /\biPad\b/, name: 'iPadOS' },
    { pattern: /\b(?:iPhone|iPod)\b/, name: 'iOS' },
    { pattern: /\bAndroid\b/, name: 'Android' },
    { pattern: /\bCrOS\b/, name: 'ChromeOS' },
    { pattern: /\bWindows\b/, name: 'Windows' },
    { pattern: /\bMacintosh\b|\bMac OS X\b/, name: 'macOS' },
    { pattern: /\b(?:FreeBSD|OpenBSD|NetBSD)\b/, name: null },
    { pattern: /\bLinux\b|\bX11\b/, name: 'Linux' },
];

const CLIENT_HINT_SYSTEMS = { 'Chrome OS': 'ChromeOS', 'Chromium OS': 'ChromeOS' };

function readString(read) {
    const result = attempt(read);
    return typeof result.value === 'string' ? result.value : null;
}

function brandList(value) {
    if (!Array.isArray(value)) {
        return null;
    }
    return value.map(entry => ({
        brand: typeof entry?.brand === 'string' ? entry.brand : String(entry?.brand ?? ''),
        version: typeof entry?.version === 'string' ? entry.version : String(entry?.version ?? ''),
    }));
}

function readLowEntropyHints(uaData) {
    const brands = attempt(() => uaData.brands);
    const mobile = attempt(() => uaData.mobile);
    const platform = attempt(() => uaData.platform);
    const hints = {
        brands: brandList(brands.value),
        mobile: typeof mobile.value === 'boolean' ? mobile.value : null,
        platform: typeof platform.value === 'string' ? platform.value : null,
    };
    const errors = [
        ['brands', brands.error],
        ['mobile', mobile.error],
        ['platform', platform.error],
    ].filter(([, error]) => error);
    if (errors.length > 0) {
        hints.errors = Object.fromEntries(errors);
    }
    return hints;
}

async function readHighEntropyHints(uaData) {
    const method = attempt(() => uaData.getHighEntropyValues);
    if (method.error) {
        return { error: method.error };
    }
    if (typeof method.value !== 'function') {
        return null;
    }
    try {
        const values = await method.value.call(uaData, ['fullVersionList', 'platformVersion']);
        return {
            fullVersionList: brandList(values?.fullVersionList),
            platformVersion: typeof values?.platformVersion === 'string' ? values.platformVersion : null,
        };
    } catch (error) {
        return { error: describeError(error) };
    }
}

async function readBrave(nav) {
    const brave = attempt(() => nav.brave);
    if (brave.error) {
        return { error: brave.error };
    }
    if (!brave.value) {
        return null;
    }
    const method = attempt(() => brave.value.isBrave);
    if (typeof method.value !== 'function') {
        return method.error ? { error: method.error } : { isBrave: null };
    }
    try {
        return { isBrave: (await method.value.call(brave.value)) === true };
    } catch (error) {
        return { error: describeError(error) };
    }
}

export async function readIdentityInputs(nav = globalThis.navigator) {
    const touchPoints = attempt(() => nav?.maxTouchPoints);
    const inputs = {
        userAgent: readString(() => nav?.userAgent),
        platform: readString(() => nav?.platform),
        maxTouchPoints: typeof touchPoints.value === 'number' ? touchPoints.value : null,
        userAgentData: null,
        highEntropyValues: null,
        brave: null,
    };
    if (!nav) {
        return inputs;
    }

    const uaData = attempt(() => nav.userAgentData);
    if (uaData.error) {
        inputs.userAgentData = { error: uaData.error };
    } else if (uaData.value && typeof uaData.value === 'object') {
        inputs.userAgentData = readLowEntropyHints(uaData.value);
        inputs.highEntropyValues = await readHighEntropyHints(uaData.value);
    }
    inputs.brave = await readBrave(nav);
    return inputs;
}

function namedBrands(list) {
    if (!Array.isArray(list)) {
        return [];
    }
    return list.filter(entry => entry.brand.trim() !== '' && !GREASE_BRAND.test(entry.brand));
}

// The brand list names the browser; fullVersionList, when granted, gives the full
// version of the same brand. A brand's version is never taken from another brand.
function clientHintBrands(inputs) {
    const low = namedBrands(inputs.userAgentData?.brands);
    const full = namedBrands(inputs.highEntropyValues?.fullVersionList);
    const names = low.length > 0 ? low : full;
    return names.map(({ brand, version }) => ({
        brand: brand.trim(),
        version: full.find(entry => entry.brand === brand)?.version || version || null,
    }));
}

function productTokens(ua) {
    return Array.from(ua.matchAll(/([A-Za-z][\w-]*)\/(\d[\w.]*)/g), match => match[1]);
}

// A reduced user-agent string writes "<major>.0.0.0"; only the major is known.
function reducedVersion(version) {
    const reduced = /^(\d+)\.0\.0\.0$/.exec(version);
    return reduced ? reduced[1] : version;
}

function fromUserAgentToken(name, version) {
    return {
        name,
        version: reducedVersion(version),
        sources: { name: 'user-agent', version: 'user-agent' },
    };
}

function userAgentClaim(ua) {
    for (const claim of USER_AGENT_CLAIMS) {
        const match = claim.pattern.exec(ua);
        if (match) {
            return fromUserAgentToken(claim.name, match[1]);
        }
    }
    return null;
}

function notReported() {
    return { name: null, version: null, sources: { name: 'not-reported', version: 'not-reported' } };
}

function browserFromUserAgent(ua) {
    const claim = userAgentClaim(ua);
    if (claim) {
        return claim;
    }

    const otherProducts = productTokens(ua).filter(token => !COMMON_PRODUCT_TOKENS.has(token));
    const firefox = /\bFirefox\/(\d[\d.]*)/.exec(ua);
    if (firefox) {
        return fromUserAgentToken('Mozilla Firefox', firefox[1]);
    }

    const chrome = /Chrome\/(\d[\d.]*)/.exec(ua);
    if (chrome) {
        if (/;\s*wv\)/.test(ua)) {
            return fromUserAgentToken('Android WebView', chrome[1]);
        }
        const name = otherProducts.length === 0 ? 'Google Chrome' : 'Chromium-based browser';
        return fromUserAgentToken(name, chrome[1]);
    }

    const safari = /\bVersion\/(\d[\d.]*).*\bSafari\//.exec(ua);
    if (safari && otherProducts.length === 0) {
        return fromUserAgentToken('Safari', safari[1]);
    }
    return notReported();
}

function fromBrand(name, entry, nameSource = 'client-hints') {
    return {
        name,
        version: entry?.version ?? null,
        sources: { name: nameSource, version: entry?.version ? 'client-hints' : 'not-reported' },
    };
}

function determineBrowser(inputs, ua, brands) {
    if (inputs.brave?.isBrave === true) {
        return fromBrand('Brave', brands.find(entry => entry.brand === 'Brave'), 'brave-api');
    }
    if (brands.length === 0) {
        return browserFromUserAgent(ua);
    }

    const own = brands.find(entry => entry.brand !== 'Chromium' && entry.brand !== 'Google Chrome');
    if (own) {
        return fromBrand(own.brand, own);
    }
    const chrome = brands.find(entry => entry.brand === 'Google Chrome');
    if (chrome) {
        return fromBrand('Google Chrome', chrome);
    }
    // Only "Chromium": a browser built on it that does not name itself here.
    return userAgentClaim(ua) ?? fromBrand('Chromium-based browser', brands.find(entry => entry.brand === 'Chromium'));
}

function determineEngine(ua, brands, onAppleWebKit) {
    if (onAppleWebKit) {
        return { engine: 'WebKit', source: 'apple-webkit' };
    }
    if (brands.some(entry => entry.brand === 'Chromium')) {
        return { engine: 'Blink', source: 'client-hints' };
    }
    if (/\bFirefox\//.test(ua) && /\bGecko\/\d/.test(ua)) {
        return { engine: 'Gecko', source: 'user-agent' };
    }
    if (/Chrom(?:e|ium)\/\d/.test(ua)) {
        return { engine: 'Blink', source: 'user-agent' };
    }
    if (/\bAppleWebKit\/\d/.test(ua)) {
        return { engine: 'WebKit', source: 'user-agent' };
    }
    return { engine: null, source: 'not-reported' };
}

function determineSystem(inputs, ua) {
    const hinted = (inputs.userAgentData?.platform ?? '').trim();
    if (hinted !== '' && hinted !== 'Unknown') {
        return { system: CLIENT_HINT_SYSTEMS[hinted] ?? hinted, source: 'client-hints' };
    }
    // iPadOS Safari asks for desktop sites by default and then sends a Mac's
    // user-agent string, with no "iPad" or "Mobile" in it.
    if (inputs.platform === 'MacIntel' && (inputs.maxTouchPoints ?? 0) > 1) {
        return { system: 'iPadOS', source: 'platform-touch' };
    }
    for (const candidate of USER_AGENT_SYSTEMS) {
        const match = candidate.pattern.exec(ua);
        if (match) {
            return { system: candidate.name ?? match[0], source: 'user-agent' };
        }
    }
    return { system: null, source: 'not-reported' };
}

export function determineIdentity(inputs) {
    const ua = inputs.userAgent ?? '';
    const brands = clientHintBrands(inputs);
    const { system, source: systemSource } = determineSystem(inputs, ua);
    const onAppleWebKit = system === 'iOS' || system === 'iPadOS';
    const browser = determineBrowser(inputs, ua, brands);
    const { engine, source: engineSource } = determineEngine(ua, brands, onAppleWebKit);

    return {
        name: browser.name,
        version: browser.version,
        engine,
        system,
        sources: {
            name: browser.sources.name,
            version: browser.sources.version,
            engine: engineSource,
            system: systemSource,
        },
        onAppleWebKit,
    };
}
