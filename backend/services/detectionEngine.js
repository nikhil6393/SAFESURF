/**
 * Advanced Hybrid Detection Engine v3.5 (Precision Calibrated)
 *
 * Fuses:
 *  1. Verified Official Whitelist (0% False Positive Guarantee on all brand ccTLDs & official domains)
 *  2. High-Accuracy Machine Learning Ensemble (Random Forest + Probability Calibration)
 *  3. Explainable Threat Vector Attribution
 */

'use strict';

const mlEngine = require('./mlEngine');

module.exports = function detect(f) {
    const details = [];

    const addDetail = (label, impact, type) => {
        details.push({ label, impact, type });
    };

    // ── Layer 1: Whitelist Short-Circuit ─────────────────────────────────────
    if (f.isTrustedOfficial) {
        addDetail('Verified Official Domain (Trusted Whitelist)', 0, 'safety');
        return {
            score: 0,
            label: 'Safe',
            threatProbability: 0,
            probabilities: { safe: 1.0, malicious: 0.0, suspicious: 0.0 },
            details,
            mlConfidence: 0.999
        };
    }

    // ── Layer 2: Machine Learning Prediction ─────────────────────────────────
    let mlResult = {
        label: 'Safe',
        score: 0,
        threatProbability: 0,
        probabilities: { safe: 1, malicious: 0, suspicious: 0 }
    };

    if (f.vector && mlEngine.isLoaded) {
        mlResult = mlEngine.predictVector(f.vector);
    }

    // ── Layer 3: Explainable Signal Attribution ──────────────────────────────

    // Brand Impersonation & Homoglyphs
    if (f.isHomoglyphAttack) {
        addDetail('Homoglyph visual spoofing attack (lookalike brand spoofing)', 75, 'risk');
    } else if (f.brand_impersonation_score > 0) {
        addDetail('Suspected brand impersonation in unofficial domain', 65, 'risk');
    }

    // IP Address
    if (f.is_ip_address) {
        addDetail('Direct IP address used instead of reputable hostname', 60, 'risk');
    }

    // Double extension
    if (f.has_double_extension) {
        addDetail('Dangerous double executable file extension (malware delivery vector)', 60, 'risk');
    }

    // DGA patterns (calibrated for length and entropy)
    if (f.entropy_host >= 3.85 && f.host_length >= 10) {
        addDetail(`High domain entropy (${f.entropy_host.toFixed(2)}) — algorithmically generated / DGA domain`, 35, 'risk');
    } else if (f.entropy_host >= 3.6 && f.host_length >= 12) {
        addDetail(`Elevated domain randomness (${f.entropy_host.toFixed(2)}) — possible DGA pattern`, 20, 'risk');
    }

    if (f.consonant_ratio_host >= 0.88 && f.sld_length >= 8) {
        addDetail(`Extreme consonant ratio (${(f.consonant_ratio_host * 100).toFixed(0)}%) — non-human vowel-free domain`, 35, 'risk');
    }

    // Phishing keywords
    if (f.foundKeywords && f.foundKeywords.length > 0) {
        const kwImpact = Math.min(f.foundKeywords.length * 15, 40);
        addDetail(`Phishing keywords detected: ${f.foundKeywords.slice(0, 3).join(', ')}`, kwImpact, 'risk');
    }

    // Suspicious TLD
    if (f.has_suspicious_tld) {
        addDetail('Non-standard / high-risk domain suffix (TLD)', 25, 'risk');
    }

    // URL Shortener
    if (f.has_url_shortener) {
        addDetail('URL shortener masking actual target destination', 25, 'risk');
    }

    // Obfuscation & Authority Spoofing with @
    if (f.num_at_symbols > 0) {
        addDetail('URL contains "@" character — possible credential authority spoofing', 35, 'risk');
    }

    // Redirect parameter
    if (f.has_redirect_param) {
        addDetail('Open redirect parameter detected (?redirect= / ?dest=)', 25, 'risk');
    }

    // Punycode
    if (f.has_punycode) {
        addDetail('Internationalized domain name (Punycode xn--) detected', 30, 'risk');
    }

    // Deep Subdomains
    if (f.subdomain_depth >= 3) {
        addDetail(`Deep subdomain nesting chain (${f.subdomain_depth} levels)`, 20, 'risk');
    }

    // Unencrypted HTTP
    if (!f.is_https) {
        addDetail('Unencrypted plain HTTP connection', 10, 'risk');
    }

    // ── Final Score Fusion & Calibration ─────────────────────────────────────
    let finalScore = mlResult.score;

    // Hard safeguards for verified threat signatures
    if (f.isHomoglyphAttack || f.has_double_extension) {
        finalScore = Math.max(finalScore, 85);
    } else if (f.is_ip_address && (f.num_sensitive_keywords > 0 || f.has_port)) {
        finalScore = Math.max(finalScore, 85);
    } else if (f.brand_impersonation_score > 0 && f.num_sensitive_keywords > 0) {
        finalScore = Math.max(finalScore, 80);
    } else if (f.num_at_symbols > 0 && f.num_sensitive_keywords > 0) {
        finalScore = Math.max(finalScore, 75);
    }

    finalScore = Math.max(0, Math.min(100, Math.round(finalScore)));

    let finalLabel = 'Safe';
    if (finalScore >= 65 || mlResult.probabilities.malicious >= 0.45) {
        finalLabel = 'Malicious';
    } else if (finalScore >= 35 || mlResult.probabilities.suspicious >= 0.35) {
        finalLabel = 'Suspicious';
    }

    const maxProb = Math.max(mlResult.probabilities.safe, mlResult.probabilities.malicious, mlResult.probabilities.suspicious);
    const mlConfidence = Number(maxProb.toFixed(4));

    if (details.length === 0 && finalLabel === 'Safe') {
        addDetail('Clean URL structure, no threat signatures or anomalous entropy detected', 0, 'safety');
    }

    return {
        score: finalScore,
        label: finalLabel,
        threatProbability: mlResult.threatProbability,
        probabilities: mlResult.probabilities,
        mlConfidence,
        details
    };
};
