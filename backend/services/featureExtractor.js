/**
 * Advanced Feature Extractor v2.0
 *
 * Extracts structural, lexical, and entropy-based signals from a URL.
 * All computation is synchronous and runs in < 1ms for any input.
 *
 * Signals extracted:
 *  - Entropy      : Shannon entropy of hostname (detects DGA/random domains)
 *  - Homoglyphs   : Substitution of digits/look-alikes for letters
 *  - Anatomy      : Deep subdomain nesting, long SLD, numeric SLD, redirect params
 *  - Phishing     : Sensitive keywords, brand impersonation, special TLDs
 *  - Structural   : IP usage, URL shorteners, double extensions, encoded chars
 */

'use strict';

// ─── Constants ────────────────────────────────────────────────────────────────

const SUSPICIOUS_TLDS = new Set([
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work',
    'click', 'link', 'loan', 'download', 'stream', 'online',
    'site', 'best', 'win', 'party', 'bid', 'icu', 'buzz',
    'live', 'fun', 'space', 'world', 'info', 'mobi'
]);

const SENSITIVE_KEYWORDS = [
    'login', 'verify', 'account', 'secure', 'update', 'bank', 'wallet',
    'signin', 'support', 'service', 'billing', 'confirm', 'validation',
    'auth', 'portal', 'ebayisapi', 'paypal', 'webscr', 'wp-admin',
    'password', 'credential', 'recover', 'suspend', 'locked', 'unusual'
];

const TRUSTED_BRANDS = [
    'google', 'microsoft', 'apple', 'icloud', 'amazon', 'facebook',
    'instagram', 'twitter', 'linkedin', 'netflix', 'paypal', 'binance',
    'coinbase', 'blockchain', 'adobe', 'steam', 'dropbox', 'yahoo',
    'outlook', 'office365', 'chase', 'wellsfargo', 'citibank'
];

/** Trusted official second-level domains that brand impersonation should not flag */
const OFFICIAL_BRAND_DOMAINS = new Set([
    'google.com', 'microsoft.com', 'apple.com', 'icloud.com',
    'amazon.com', 'facebook.com', 'instagram.com', 'twitter.com',
    'linkedin.com', 'netflix.com', 'paypal.com', 'binance.com',
    'coinbase.com', 'adobe.com', 'steampowered.com', 'dropbox.com',
    'yahoo.com', 'live.com', 'microsoftonline.com', 'office.com',
    'outlook.com', 'chase.com', 'wellsfargo.com', 'citibank.com',
    'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com',
    'youtube.com', 'bing.com', 'openai.com'
]);

const URL_SHORTENERS = new Set([
    'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd',
    'buff.ly', 'bit.do', 'ow.ly', 'rebrand.ly', 'short.link',
    'cutt.ly', 'rb.gy', 'tiny.cc', 'clck.ru'
]);

/** Homoglyph substitution map — maps lookalike chars → canonical letter */
const HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '6': 'g', '7': 't', '8': 'b', '9': 'q',
    '@': 'a', '$': 's', '!': 'i'
};

const REDIRECT_PARAMS = new Set([
    'redirect', 'url', 'next', 'return', 'goto', 'link',
    'target', 'dest', 'destination', 'redir', 'r', 'u', 'page'
]);

// ─── Utility: Shannon Entropy ─────────────────────────────────────────────────

/**
 * Compute Shannon entropy of a string.
 * Safe domains (e.g. "google") score ~2.5–3.0.
 * DGA / random domains score 3.5+.
 * @param {string} str
 * @returns {number}
 */
function shannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    let entropy = 0;
    const len = str.length;
    for (const ch in freq) {
        const p = freq[ch] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

/**
 * Compute the vowel-absence ratio of a string.
 * Human words contain vowels; DGA/random strings often don't.
 * Ratio = consonants / total alpha chars (higher = more DGA-like)
 * e.g. "xk9f2rp4mz" → ~1.0   "google" → ~0.5
 * @param {string} str  (hostname core, dots stripped)
 * @returns {number} 0–1
 */
function consonantRatio(str) {
    const alpha = str.match(/[a-z]/gi);
    if (!alpha || alpha.length < 3) return 0;
    const vowels = str.match(/[aeiou]/gi);
    const vowelCount = vowels ? vowels.length : 0;
    return 1 - (vowelCount / alpha.length);
}

// ─── Utility: Homoglyph Normalizer ───────────────────────────────────────────

/**
 * Replace common digit/symbol lookalikes with their letter equivalents.
 * e.g. "g00gle" → "google", "micrоsoft" (Cyrillic о) → "microsoft"
 * @param {string} str
 * @returns {string}
 */
function normalizeHomoglyphs(str) {
    // Replace ASCII lookalikes
    let result = '';
    for (const ch of str.toLowerCase()) {
        result += HOMOGLYPH_MAP[ch] || ch;
    }
    // Normalise Unicode confusables to ASCII via NFD + strip non-ASCII
    return result.normalize('NFD').replace(/[^\x00-\x7F]/g, '');
}

// ─── Utility: Subdomain / SLD / TLD decomposition ────────────────────────────

function decomposeHostname(hostname) {
    const parts  = hostname.split('.');
    const tld    = parts[parts.length - 1] || '';
    const sld    = parts[parts.length - 2] || '';
    const subdomains = parts.slice(0, -2);
    return { parts, tld, sld, subdomains };
}

// ─── Main Extractor ───────────────────────────────────────────────────────────

module.exports = function extractFeatures(url) {
    let hostname = '';
    let pathname = '/';
    let search   = '';
    let parsed   = null;

    try {
        parsed   = new URL(url.startsWith('http') ? url : 'https://' + url);
        hostname = parsed.hostname.toLowerCase();
        pathname = parsed.pathname.toLowerCase();
        search   = parsed.search.toLowerCase();
    } catch (_) {
        hostname = url.toLowerCase().split('/')[0];
    }

    const fullPath = hostname + pathname + search;
    const { tld, sld, subdomains } = decomposeHostname(hostname);

    // ── 1. Shannon Entropy + Consonant Ratio (DGA detection) ──────────────────
    const hostnameCore = hostname.replace(/\./g, '');       // strip dots
    const entropy      = shannonEntropy(hostnameCore);
    const consonants   = consonantRatio(hostnameCore);      // high = no vowels = DGA

    // ── 2. Homoglyph Brand Impersonation ──────────────────────────────────────
    const normalizedHostname = normalizeHomoglyphs(hostname);

    const isTrustedOfficial = (() => {
        // Exact SLD+TLD match against official domains
        const sldTld = `${sld}.${tld}`;
        if (OFFICIAL_BRAND_DOMAINS.has(sldTld)) return true;
        // Allow any subdomain of a known official (mail.google.com etc.)
        for (const official of OFFICIAL_BRAND_DOMAINS) {
            if (hostname === official || hostname.endsWith('.' + official)) return true;
        }
        return false;
    })();

    // Standard brand check on raw hostname
    const brandImpersonationRaw = !isTrustedOfficial && TRUSTED_BRANDS.some(brand =>
        hostname.includes(brand)
    );

    // Homoglyph check on normalised hostname (catches g00gle, micrоsoft etc.)
    const brandImpersonationHomoglyph = !isTrustedOfficial && !brandImpersonationRaw &&
        TRUSTED_BRANDS.some(brand => normalizeHomoglyphs(brand) !== brand
            ? false // brand itself doesn't change, so we just check normalized host
            : normalizedHostname.includes(brand) && !hostname.includes(brand)
        );

    const brandImpersonation = brandImpersonationRaw || brandImpersonationHomoglyph;
    const isHomoglyphAttack  = brandImpersonationHomoglyph;

    // ── 3. Suspicious TLD ─────────────────────────────────────────────────────
    const hasSuspiciousTLD = SUSPICIOUS_TLDS.has(tld);

    // ── 4. Sensitive Keywords ─────────────────────────────────────────────────
    const foundKeywords = SENSITIVE_KEYWORDS.filter(kw => fullPath.includes(kw));

    // ── 5. IP Address Usage ───────────────────────────────────────────────────
    const hasIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);

    // ── 6. URL Shortener ──────────────────────────────────────────────────────
    const hasUrlShortener = URL_SHORTENERS.has(hostname) ||
        URL_SHORTENERS.has(`${sld}.${tld}`);

    // ── 7. Obfuscation Signals ────────────────────────────────────────────────
    const hasEncodedChars   = /%[0-9A-Fa-f]{2}/.test(url);
    const hasSpecialChars   = /[@%]/.test(url);
    const hasDoubleExtension = /\.(exe|zip|rar|gz|bat|scr|msi|ps1|vbs|sh)\.(exe|zip|rar|gz|bat|scr|msi|ps1|vbs|sh)$/i.test(url);

    // ── 8. Structural Metrics ─────────────────────────────────────────────────
    const digitCount = (hostname.match(/\d/g) || []).length;
    const dashCount  = (hostname.match(/-/g)  || []).length;
    const dotCount   = (hostname.match(/\./g)  || []).length;
    const length     = url.length;

    // ── 9. URL Anatomy Signals ────────────────────────────────────────────────
    const subdomain_depth      = subdomains.length;
    const sld_length           = sld.length;
    const sld_is_numeric       = /^\d+$/.test(sld);

    // Path signals
    const pathSegments = pathname.split('/').filter(Boolean);
    const path_depth   = pathSegments.length;
    const has_long_path_segment = pathSegments.some(s => s.length > 40);

    // Redirect parameter
    let has_redirect_param = false;
    if (parsed) {
        for (const key of parsed.searchParams.keys()) {
            if (REDIRECT_PARAMS.has(key.toLowerCase())) {
                has_redirect_param = true;
                break;
            }
        }
    }
    const param_count = parsed ? [...parsed.searchParams].length : 0;

    return {
        url,
        hostname,
        hasHttps: url.startsWith('https'),

        // Entropy + DGA
        entropy,
        consonants,

        // Brand / Impersonation
        brandImpersonation,
        isHomoglyphAttack,

        // Structural
        hasIP,
        dashCount,
        dotCount,
        digitCount,
        length,
        hasSuspiciousTLD,

        // Lexical
        foundKeywords,
        hasSpecialChars,
        hasEncodedChars,
        hasDoubleExtension,
        hasUrlShortener,

        // Anatomy
        subdomain_depth,
        sld_length,
        sld_is_numeric,
        path_depth,
        has_long_path_segment,
        has_redirect_param,
        param_count,

        // Trusted flag (used by engine to short-circuit)
        isTrustedOfficial
    };
};
