/**
 * Advanced Detection Engine v2.0 — Weighted Structural Scoring
 *
 * Scoring philosophy:
 *  - HIGH RISK  (60–75 pts each): IP, homoglyph impersonation, known threat feed
 *  - MED RISK   (20–40 pts each): entropy, TLD, keywords, redirect params
 *  - LOW RISK   (10–15 pts each): structural quirks
 *  - MITIGATION (0 pts): HTTPS is NOT rewarded — 90%+ of phishing uses HTTPS (Let's Encrypt).
 *                         HTTP is slightly penalised (+15) because all legit sites use HTTPS.
 *
 * Thresholds:
 *  ≥ 60  → Malicious
 *  ≥ 35  → Suspicious
 *  < 35  → Safe
 */

'use strict';

module.exports = function detect(f) {
    let score = 0;
    const details = [];

    const add = (label, impact, type) => {
        score += impact;
        details.push({ label, impact, type });
    };

    // ── Short-circuit for verified official domains ──────────────────────────
    if (f.isTrustedOfficial) {
        add('Verified Official Domain (Whitelist)', -100, 'safety');
        score = 0;
        return { score: 0, label: 'Safe', details };
    }

    // ── CRITICAL RISK (instant high score) ───────────────────────────────────

    // Homoglyph brand impersonation (e.g. g00gle.com, аpple.com)
    if (f.isHomoglyphAttack) {
        add('Homoglyph brand impersonation (visual spoofing attack)', 75, 'risk');
    } else if (f.brandImpersonation) {
        add('Suspected brand impersonation / lookalike domain', 65, 'risk');
    }

    // Raw IP address
    if (f.hasIP) {
        add('Raw IP address used instead of domain name', 60, 'risk');
    }

    // Double file extension (malware delivery)
    if (f.hasDoubleExtension) {
        add('Dangerous double file extension (malware delivery vector)', 55, 'risk');
    }

    // ── MEDIUM RISK ───────────────────────────────────────────────────────────

    // Shannon Entropy — high = likely algorithmically generated domain (DGA)
    if (f.entropy >= 4.0) {
        add(`High domain entropy (${f.entropy.toFixed(2)}) — likely algorithmically generated`, 35, 'risk');
    } else if (f.entropy >= 3.5) {
        add(`Elevated domain entropy (${f.entropy.toFixed(2)}) — possible DGA pattern`, 20, 'risk');
    }

    // Consonant Ratio — no vowels = human-unreadable = machine-generated (DGA)
    // e.g. "xk9f2rp4mz" has ~100% consonants; "google" has 50%
    if (f.consonants >= 0.9) {
        add(`No-vowel domain pattern (${(f.consonants * 100).toFixed(0)}% consonants) — DGA/machine-generated`, 35, 'risk');
    } else if (f.consonants >= 0.75) {
        add(`Very low vowel density in domain (${(f.consonants * 100).toFixed(0)}% consonants)`, 20, 'risk');
    }

    // Sensitive keywords in URL
    if (f.foundKeywords && f.foundKeywords.length > 0) {
        const impact = Math.min(f.foundKeywords.length * 15, 40);
        add(`Phishing keywords detected: ${f.foundKeywords.slice(0, 3).join(', ')}`, impact, 'risk');
    }

    // Suspicious / free TLD
    if (f.hasSuspiciousTLD) {
        add('Non-standard / free-registration domain suffix (TLD)', 25, 'risk');
    }

    // URL shortener
    if (f.hasUrlShortener) {
        add('URL shortener used — destination hidden from user', 25, 'risk');
    }

    // Open redirect parameter
    if (f.has_redirect_param) {
        add('Open redirect parameter detected (redirect/url/next/goto)', 25, 'risk');
    }

    // Obfuscation characters
    if (f.hasSpecialChars) {
        add('URL contains obfuscation characters (@ or %)', 20, 'risk');
    }

    // Encoded characters in path
    if (f.hasEncodedChars) {
        add('Excessive URL encoding — possible payload obfuscation', 15, 'risk');
    }

    // ── LOW / STRUCTURAL RISK ─────────────────────────────────────────────────

    // Deep subdomain nesting (e.g. login.verify.account.evil.tk)
    if (f.subdomain_depth >= 3) {
        add(`Deeply nested subdomains (${f.subdomain_depth} levels)`, 20, 'risk');
    } else if (f.subdomain_depth === 2) {
        add('Multiple subdomain levels', 10, 'risk');
    }

    // Abnormally long second-level domain
    if (f.sld_length > 30) {
        add(`Extremely long domain name (${f.sld_length} chars)`, 15, 'risk');
    } else if (f.sld_length > 20) {
        add(`Long domain name (${f.sld_length} chars)`, 8, 'risk');
    }

    // Numeric-only SLD (not an IP, but looks machine-generated)
    if (f.sld_is_numeric) {
        add('Numeric-only second-level domain (machine-generated pattern)', 20, 'risk');
    }

    // Long encoded path segment (possible payload)
    if (f.has_long_path_segment) {
        add('Abnormally long URL path segment (possible encoded payload)', 20, 'risk');
    }

    // Very deep URL path
    if (f.path_depth > 6) {
        add(`Very deep URL path (${f.path_depth} segments)`, 10, 'risk');
    }

    // Many query parameters
    if (f.param_count > 8) {
        add(`Excessive query parameters (${f.param_count})`, 12, 'risk');
    }

    // Excessive dashes in domain
    if (f.dashCount > 3) {
        add(`Abnormal dash count in domain (${f.dashCount})`, 12, 'risk');
    }

    // Excessive digits in hostname
    if (f.digitCount > 5) {
        add(`High digit density in domain name (${f.digitCount} digits)`, 12, 'risk');
    }

    // Excessively long URL
    if (f.length > 150) {
        add('Excessively long URL structure', 10, 'risk');
    }

    // ── HTTP (no HTTPS) penalty — note: HTTPS no longer rewarded ─────────────
    // Rationale: 90%+ of phishing sites now use HTTPS (free certificates).
    // We no longer give -15 for HTTPS. HTTP is slightly more suspicious
    // because every legitimate site in 2024+ uses HTTPS.
    if (!f.hasHttps) {
        add('Unencrypted HTTP connection (all legitimate sites use HTTPS)', 15, 'risk');
    }

    // ── Normalise score ───────────────────────────────────────────────────────
    if (score < 0)   score = 0;
    if (score > 100) score = 100;
    score = Math.round(score);

    // ── Label assignment ──────────────────────────────────────────────────────
    let label = 'Safe';
    if      (score >= 60) label = 'Malicious';
    else if (score >= 35) label = 'Suspicious';

    return { score, label, details };
};
