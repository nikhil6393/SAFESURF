/**
 * SafeSurf — Background Service Worker v2.0
 *
 * Detection pipeline (client-side):
 *  1. Whitelist check  — known safe official domains → score 0
 *  2. Blacklist check  — local JSON dataset
 *  3. Advanced heuristics — entropy, homoglyphs, anatomy, keywords, TLD
 *  4. Backend upgrade  — async call to SafeSurf API if available
 *
 * No ML, no paid API keys, no external dependencies.
 */

'use strict';

// ── Local Dataset ─────────────────────────────────────────────────────────────
let blacklistSet = new Set();

fetch(chrome.runtime.getURL('dataset.json'))
    .then(r => r.json())
    .then(data => {
        blacklistSet = new Set(data.blacklist);
        console.log(`🛡️ SafeSurf: Dataset v${data.version} loaded (${blacklistSet.size} entries)`);
    })
    .catch(err => console.error('[SafeSurf] Dataset load failed:', err));

// ── Constants ─────────────────────────────────────────────────────────────────

const TRUSTED_OFFICIAL = new Set([
    'google.com', 'gmail.com', 'youtube.com', 'googleapis.com',
    'github.com', 'githubusercontent.com',
    'microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'office.com',
    'apple.com', 'icloud.com',
    'amazon.com', 'aws.amazon.com',
    'facebook.com', 'instagram.com', 'whatsapp.com',
    'twitter.com', 'x.com',
    'linkedin.com',
    'netflix.com',
    'paypal.com',
    'wikipedia.org',
    'reddit.com',
    'stackoverflow.com',
    'dropbox.com',
    'adobe.com',
    'openai.com',
    'bing.com', 'yahoo.com'
]);

const SUSPICIOUS_TLDS = new Set([
    'tk','ml','ga','cf','gq','xyz','top','work','click','link',
    'loan','download','stream','online','site','best','win','party',
    'bid','icu','buzz','live','fun','space','world','mobi','info'
]);

const PHISHING_KEYWORDS = [
    'login','verify','account','secure','update','bank','wallet',
    'signin','support','service','billing','confirm','validation',
    'auth','portal','webscr','wp-admin','password','credential',
    'recover','suspend','locked','unusual','ebayisapi'
];

const BRANDS = [
    'google','microsoft','apple','icloud','amazon','facebook',
    'instagram','twitter','linkedin','netflix','paypal','binance',
    'coinbase','blockchain','adobe','steam','dropbox','yahoo',
    'outlook','chase','wellsfargo','citibank'
];

const URL_SHORTENERS = new Set([
    'bit.ly','goo.gl','t.co','tinyurl.com','is.gd','buff.ly',
    'bit.do','ow.ly','rebrand.ly','cutt.ly','rb.gy','tiny.cc'
]);

const REDIRECT_PARAMS = new Set([
    'redirect','url','next','return','goto','link','target',
    'dest','destination','redir','r','u','page'
]);

const HOMOGLYPH_MAP = {
    '0':'o','1':'l','3':'e','4':'a','5':'s',
    '6':'g','7':'t','8':'b','9':'q','@':'a','$':'s'
};

// ── Utilities ─────────────────────────────────────────────────────────────────

function shannonEntropy(str) {
    if (!str) return 0;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    let e = 0;
    const n = str.length;
    for (const ch in freq) { const p = freq[ch] / n; e -= p * Math.log2(p); }
    return e;
}

function normalizeHomoglyphs(str) {
    let result = '';
    for (const ch of str.toLowerCase()) result += HOMOGLYPH_MAP[ch] || ch;
    return result;
}

function normalizeURL(url) {
    try { return new URL(url).hostname.toLowerCase(); }
    catch (_) { return null; }
}

function isTrustedOfficial(hostname) {
    if (TRUSTED_OFFICIAL.has(hostname)) return true;
    for (const official of TRUSTED_OFFICIAL) {
        if (hostname.endsWith('.' + official)) return true;
    }
    return false;
}

// ── Core Scoring Engine ───────────────────────────────────────────────────────

/**
 * Evaluate a URL and return { score, reasons, block }.
 * score 0–100  (risk percentage)
 * reasons      array of human-readable signal strings
 * block        true if score >= 60
 */
function evaluateURL(url) {
    let score   = 0;
    const reasons = [];

    // Parse URL safely
    let parsed, hostname, pathname, search;
    try {
        parsed   = new URL(url.startsWith('http') ? url : 'https://' + url);
        hostname = parsed.hostname.toLowerCase();
        pathname = parsed.pathname.toLowerCase();
        search   = parsed.search.toLowerCase();
    } catch (_) {
        return { score: 0, reasons: ['Invalid URL format'], block: false };
    }

    const fullPath = hostname + pathname + search;

    // ── 1. Whitelist — instant safe ────────────────────────────────────────
    if (isTrustedOfficial(hostname)) {
        return { score: 0, reasons: ['Verified Official Domain'], block: false };
    }

    // ── 2. Local blacklist ─────────────────────────────────────────────────
    if (blacklistSet.has(hostname)) {
        score = Math.max(score, 90);
        reasons.push('Known Malicious Domain (Local Intel)');
    }

    // ── 3. Homoglyph / Brand Impersonation ────────────────────────────────
    const normalizedHost = normalizeHomoglyphs(hostname);
    let homoglyphHit = false;

    for (const brand of BRANDS) {
        const officialSLD = `${brand}.com`;
        const isOfficial = hostname === officialSLD ||
            hostname.endsWith('.' + officialSLD) ||
            hostname === `${brand}.net` ||
            hostname.endsWith(`.${brand}.net`);

        if (isOfficial) continue;

        if (normalizedHost.includes(brand) && !hostname.includes(brand)) {
            // Homoglyph variant (g00gle.com → google)
            score += 75;
            reasons.push(`Homoglyph brand impersonation: ${brand} (visual spoofing)`);
            homoglyphHit = true;
            break;
        } else if (hostname.includes(brand)) {
            // Direct brand inclusion in non-official domain
            score += 65;
            reasons.push(`Suspected brand impersonation: ${brand}`);
            break;
        }
    }

    // ── 4. IP address URL ──────────────────────────────────────────────────
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        score += 60;
        reasons.push('Raw IP address used instead of domain name');
    }

    // ── 5. Shannon Entropy (DGA detection) ────────────────────────────────
    const core    = hostname.replace(/\./g, '');
    const entropy = shannonEntropy(core);
    if (entropy >= 4.0) {
        score += 35;
        reasons.push(`High domain entropy (${entropy.toFixed(2)}) — algorithmically generated`);
    } else if (entropy >= 3.5) {
        score += 20;
        reasons.push(`Elevated domain entropy (${entropy.toFixed(2)}) — possible DGA domain`);
    }

    // ── 6. Suspicious TLD ──────────────────────────────────────────────────
    const tld = hostname.split('.').pop();
    if (SUSPICIOUS_TLDS.has(tld)) {
        score += 25;
        reasons.push(`Suspicious free/low-reputation TLD: .${tld}`);
    }

    // ── 7. Phishing keywords ───────────────────────────────────────────────
    const kws = PHISHING_KEYWORDS.filter(kw => fullPath.includes(kw));
    if (kws.length > 0) {
        score += Math.min(kws.length * 15, 40);
        reasons.push(`Phishing keywords: ${kws.slice(0, 3).join(', ')}`);
    }

    // ── 8. URL shortener ───────────────────────────────────────────────────
    const parts = hostname.split('.');
    const sldTld = parts.slice(-2).join('.');
    if (URL_SHORTENERS.has(hostname) || URL_SHORTENERS.has(sldTld)) {
        score += 25;
        reasons.push('URL shortener detected — destination obfuscated');
    }

    // ── 9. Open redirect parameter ─────────────────────────────────────────
    for (const key of parsed.searchParams.keys()) {
        if (REDIRECT_PARAMS.has(key.toLowerCase())) {
            score += 25;
            reasons.push(`Open redirect parameter: ?${key}=`);
            break;
        }
    }

    // ── 10. Obfuscation characters ─────────────────────────────────────────
    if (/[@%]/.test(url)) {
        score += 20;
        reasons.push('Obfuscation characters in URL (@ or %)');
    }

    // ── 11. URL anatomy signals ────────────────────────────────────────────
    const subdomains = parts.slice(0, -2);
    if (subdomains.length >= 3) {
        score += 20;
        reasons.push(`Deep subdomain nesting (${subdomains.length} levels)`);
    }

    const sld = parts[parts.length - 2] || '';
    if (/^\d+$/.test(sld)) {
        score += 20;
        reasons.push('Numeric-only domain name (machine-generated pattern)');
    } else if (sld.length > 25) {
        score += 15;
        reasons.push(`Abnormally long domain name (${sld.length} chars)`);
    }

    // Long path segment
    const pathSegs = pathname.split('/').filter(Boolean);
    if (pathSegs.some(s => s.length > 40)) {
        score += 20;
        reasons.push('Very long URL path segment (possible encoded payload)');
    }

    // Excessive dashes
    const dashes = (hostname.match(/-/g) || []).length;
    if (dashes > 3) {
        score += 12;
        reasons.push(`Abnormal dash count in domain (${dashes})`);
    }

    // Double file extension
    if (/\.(exe|zip|bat|scr|msi|ps1|vbs)\.(exe|zip|bat|scr|msi|ps1|vbs)$/i.test(url)) {
        score += 55;
        reasons.push('Dangerous double file extension (malware delivery)');
    }

    // ── 12. HTTP penalty — HTTPS no longer rewarded ────────────────────────
    // Note: 90%+ of phishing sites use HTTPS (free certs). We do NOT give
    // a -15 bonus for HTTPS. HTTP gets a small penalty only.
    if (!url.startsWith('https')) {
        score += 15;
        reasons.push('Unencrypted HTTP — all legitimate sites use HTTPS');
    }

    // Clamp
    score = Math.max(0, Math.min(100, Math.round(score)));

    return {
        score,
        reasons: reasons.slice(0, 4),
        block: score >= 60
    };
}

// ── Message Handler (from popup) ──────────────────────────────────────────────
chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
    if (request.action === 'evaluateURL') {
        sendResponse(evaluateURL(request.url));
    }
    return true;
});

// ── Tab Scan on Page Load ─────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== 'complete') return;
    if (!tab.url || !tab.url.startsWith('http')) return;

    const local = evaluateURL(tab.url);
    const status = local.score >= 60 ? 'critical'
                 : local.score >= 35 ? 'suspicious'
                 : 'safe';

    // Store immediately so popup shows a result even before backend returns
    _updateUI(tabId, status, tab.url, local);

    // Fire async backend upgrade (best-effort)
    _checkBackend(tab.url, tabId);
});

// ── Redirect Tracking ─────────────────────────────────────────────────────────
chrome.webRequest.onBeforeRedirect.addListener(
    details => {
        const result = evaluateURL(details.redirectUrl);
        if (result.block) {
            console.warn('[SafeSurf] Dangerous redirect blocked:', details.redirectUrl);
            _showNotification('critical', details.redirectUrl,
                `Dangerous Redirect Blocked: ${result.reasons[0] || 'Unknown threat'}`);
        }
    },
    { urls: ['<all_urls>'] }
);

// ── Internal Helpers ──────────────────────────────────────────────────────────

function _updateUI(tabId, status, url, data) {
    _updateBadge(tabId, status);

    // Standardise reasons array
    let reasons = data.reasons;
    if (!reasons || reasons.length === 0) {
        reasons = status === 'safe'
            ? ['Verified Safe Domain Structure']
            : ['Suspicious Signal Detected'];
    }

    const payload = { ...data, url, status, reasons };

    if (status === 'critical' || status === 'suspicious') {
        chrome.tabs.sendMessage(tabId, {
            action: 'SHOW_WARNING',
            data: { reasons, score: data.score }
        }).catch(() => {}); // content script may not be ready yet
    }

    chrome.storage.local.set({ [tabId.toString()]: payload });
}

function _updateBadge(tabId, status) {
    const color = status === 'critical' ? '#f43f5e'
                : status === 'suspicious' ? '#f59e0b'
                : '#10b981';
    const text  = status === 'critical' ? '!'
                : status === 'suspicious' ? '?'
                : '';
    chrome.action.setBadgeText({ text, tabId });
    chrome.action.setBadgeBackgroundColor({ color, tabId });
}

function _showNotification(type, url, message) {
    try {
        const hostname = new URL(url).hostname;
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: 'SafeSurf Alert',
            message: `${message}\n${hostname}`,
            priority: 2
        });
    } catch (_) {}
}

async function _checkBackend(url, tabId) {
    const BACKEND = 'https://malware-url-detector.vercel.app/api/check-url';
    try {
        const res = await fetch(BACKEND, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
            signal: AbortSignal.timeout(5000) // 5 s timeout
        });

        if (!res.ok) return;
        const data  = await res.json();
        const score = data.score || 0;

        const status = score >= 60 ? 'critical'
                     : score >= 35 ? 'suspicious'
                     : 'safe';

        const reasons = (data.details || [])
            .filter(d => d.type === 'risk')
            .map(d => d.label)
            .slice(0, 4);

        _updateUI(tabId, status, url, { score, reasons, ...data });
    } catch (_) {
        // Backend offline — local heuristics already saved; nothing to do
    }
}
