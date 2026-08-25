'use strict';

const express        = require('express');
const cors           = require('cors');
const extractFeatures = require('./services/featureExtractor');
const detect         = require('./services/detectionEngine');
const datasetLoader  = require('./services/DatasetLoader');
const threatFeed     = require('./services/ThreatFeedService');
const connectDB      = require('./services/db');
const historyService = require('./services/HistoryService');
require('dotenv').config();

// ── Initialise services ───────────────────────────────────────────────────────
connectDB();
datasetLoader.init();
threatFeed.startAutoRefresh(); // pulls OpenPhish, URLhaus, MalwareDomains every 6 h

// ── Express setup ─────────────────────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 5000;

// CORS: allow chrome-extension:// and explicitly listed origins.
// Set ALLOWED_ORIGINS in your .env (comma-separated); use "*" to disable allowlist.
const allowedOrigins = (
    process.env.ALLOWED_ORIGINS ||
    'http://localhost:5000,http://localhost:3000,http://127.0.0.1:5500'
).split(',').map(o => o.trim()).filter(Boolean);

app.use(cors({
    origin: (origin, callback) => {
        if (!origin)                              return callback(null, true);
        if (allowedOrigins.includes('*'))         return callback(null, true);
        if (origin.startsWith('chrome-extension://')) return callback(null, true);
        if (allowedOrigins.includes(origin))      return callback(null, true);
        return callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
}));

// Cap body size to prevent memory-exhaustion payloads.
app.use(express.json({ limit: '16kb' }));

// ── In-process rate limiter (per IP, per minute) ──────────────────────────────
const RATE_WINDOW_MS = 60_000;
const RATE_MAX       = 60;
const rateHits       = new Map();

app.use((req, res, next) => {
    const now  = Date.now();
    const ip   = req.ip || req.socket?.remoteAddress || 'unknown';
    let   entry = rateHits.get(ip);

    if (!entry || now > entry.reset) entry = { count: 0, reset: now + RATE_WINDOW_MS };
    entry.count++;
    rateHits.set(ip, entry);

    if (rateHits.size > 10_000) {
        for (const [k, v] of rateHits) if (now > v.reset) rateHits.delete(k);
    }

    if (entry.count > RATE_MAX) return res.status(429).json({ error: 'Too many requests, slow down.' });
    next();
});

// ── Core URL Analysis Pipeline ────────────────────────────────────────────────

/**
 * Analyse a URL through 3 layers:
 *  1. Static dataset  (CSV — exact/hostname match)
 *  2. Live threat feed (OpenPhish + URLhaus + MalwareDomains)
 *  3. Heuristic engine (entropy, anatomy, brand impersonation, keywords, etc.)
 *
 * @param {string} url
 * @returns {{ url, score, label, details, source }}
 */
const analyzeURL = (url) => {
    // Layer 1: Static dataset lookup
    const knownMatch = datasetLoader.check(url);
    if (knownMatch) {
        const score = knownMatch.label === 'malicious' ? 95
                    : knownMatch.label === 'suspicious' ? 50
                    : 0;
        return {
            url,
            score,
            label: knownMatch.label.charAt(0).toUpperCase() + knownMatch.label.slice(1),
            details: [{
                label: `Known ${knownMatch.type} pattern (static intelligence database)`,
                impact: score,
                type:   score > 0 ? 'risk' : 'safety'
            }],
            source: 'dataset'
        };
    }

    // Layer 2: Live threat-feed lookup
    try {
        const { hostname } = new URL(url.startsWith('http') ? url : 'https://' + url);
        if (threatFeed.check(hostname)) {
            return {
                url,
                score: 92,
                label: 'Malicious',
                details: [{
                    label: 'Confirmed in live threat intelligence feed (OpenPhish / URLhaus)',
                    impact: 92,
                    type:  'risk'
                }],
                source: 'threat_feed'
            };
        }
    } catch (_) { /* malformed URL — fall through to heuristics */ }

    // Layer 3: Heuristic engine
    const features = extractFeatures(url);
    const result   = detect(features);

    return {
        url,
        score:   result.score,
        label:   result.label,
        details: result.details,
        source:  'heuristics'
    };
};

// ── API Routes ────────────────────────────────────────────────────────────────

const path = require('path');

// Serve frontend static web app
app.use(express.static(path.join(__dirname, '../frontend')));

app.get('/api/status', (_req, res) =>
    res.json({ status: 'Online', message: 'SafeSurf Security Backend v2.0' })
);

app.post('/api/check-url', async (req, res) => {
    try {
        const { url } = req.body || {};

        if (typeof url !== 'string' || url.trim() === '') {
            return res.status(400).json({ error: 'A non-empty "url" string is required' });
        }
        if (url.length > 2048) {
            return res.status(413).json({ error: 'URL exceeds maximum allowed length (2048)' });
        }

        const result = analyzeURL(url.trim());
        console.log(`[SCAN] ${result.label.padEnd(10)} score=${String(result.score).padStart(3)} src=${result.source} — ${url}`);

        historyService.save({
            url:    result.url,
            label:  result.label,
            score:  result.score,
            source: result.source
        });

        res.json(result);
    } catch (err) {
        console.error('[check-url]', err.message);
        res.status(500).json({ error: 'Internal error during URL analysis' });
    }
});

app.get('/api/history', async (_req, res) => {
    res.json(await historyService.getRecent());
});

app.get('/api/dataset', (_req, res) => {
    res.json(datasetLoader.getAll());
});

app.get('/api/dataset-stats', (_req, res) => {
    res.json(datasetLoader.getStats());
});

app.get('/api/stats', async (_req, res) => {
    const [history, datasetStats] = await Promise.all([
        historyService.getRecent(),
        Promise.resolve(datasetLoader.getStats())
    ]);

    res.json({
        totalScanned:    history.length,
        threatsBlocked:  history.filter(h => h.label !== 'Safe').length,
        intelligenceSize: datasetStats.totalItems,
        threatFeedSize:  threatFeed.size,
        threatFeedLastRefresh: threatFeed.lastRefresh
    });
});

// ── Boot ──────────────────────────────────────────────────────────────────────
if (require.main === module) {
    app.listen(PORT, () =>
        console.log(`🛡️  SafeSurf backend running at http://localhost:${PORT}`)
    );
}

module.exports = app;
