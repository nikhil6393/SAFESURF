const express = require('express');
const cors = require('cors');
const extractFeatures = require('./services/featureExtractor');
const detect = require('./services/detectionEngine');
const datasetLoader = require('./services/DatasetLoader');
const connectDB = require('./services/db');
const historyService = require('./services/HistoryService');
require('dotenv').config();

// Initialize Cloud Database
connectDB();

// Initialize Dataset
datasetLoader.init();

const app = express();
const PORT = process.env.PORT || 5000;

// CORS: restrict to explicitly allowed origins (comma-separated in ALLOWED_ORIGINS).
// Browser extensions (chrome-extension://) and non-browser clients (no Origin) are allowed.
// Set ALLOWED_ORIGINS to your deployed frontend origin in production; use "*" to disable the allowlist.
const allowedOrigins = (process.env.ALLOWED_ORIGINS ||
    'http://localhost:5000,http://localhost:3000,http://127.0.0.1:5500')
    .split(',').map(o => o.trim()).filter(Boolean);

app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);                       // curl / same-origin / server-to-server
        if (allowedOrigins.includes('*')) return callback(null, true);  // explicit opt-out of allowlist
        if (origin.startsWith('chrome-extension://')) return callback(null, true);
        if (allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
}));

// Cap request body size to blunt memory-exhaustion payloads.
app.use(express.json({ limit: '16kb' }));

// Best-effort in-memory rate limiter (per process). NOTE: on serverless/multi-instance
// deployments each instance keeps its own counter, so use a shared store or the
// platform's rate limiting for real protection there.
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX = 60;
const rateHits = new Map();
app.use((req, res, next) => {
    const now = Date.now();
    const ip = req.ip || req.socket?.remoteAddress || 'unknown';
    let entry = rateHits.get(ip);
    if (!entry || now > entry.reset) {
        entry = { count: 0, reset: now + RATE_WINDOW_MS };
    }
    entry.count++;
    rateHits.set(ip, entry);

    // Prune expired entries occasionally so the map can't grow unbounded.
    if (rateHits.size > 10000) {
        for (const [k, v] of rateHits) if (now > v.reset) rateHits.delete(k);
    }

    if (entry.count > RATE_MAX) {
        return res.status(429).json({ error: 'Too many requests, slow down.' });
    }
    next();
});

// IMPROVED HEURISTIC ENGINE: Weighted Scoring with Whitelist
const analyzeURL = (url) => {
    // 1. Check known dataset first (Direct Recognition)
    const knownMatch = datasetLoader.check(url);
    if (knownMatch) {
        return {
            url,
            score: knownMatch.label === 'malicious' ? 95 : (knownMatch.label === 'suspicious' ? 45 : 0),
            label: knownMatch.label.charAt(0).toUpperCase() + knownMatch.label.slice(1),
            details: [{ label: `Known ${knownMatch.type} pattern from local intelligence`, impact: knownMatch.label === 'malicious' ? 95 : 45, type: knownMatch.label === 'safe' ? 'safety' : 'risk' }],
            source: 'dataset'
        };
    }

    // 2. Extract features from URL
    const features = extractFeatures(url);

    // 3. Run detection engine with weighted scoring
    const result = detect(features);

    return {
        url,
        score: result.score,
        label: result.label,
        details: result.details,
        source: 'heuristics'
    };
};

// API Endpoints
app.get('/', (req, res) => {
    res.json({ status: 'Online', message: 'SafeSurf Security Backend is running' });
});

app.post('/api/check-url', async (req, res) => {
    try {
        const { url } = req.body || {};

        // Input validation: reject non-strings (prevents NoSQL-style objects and
        // TypeErrors deep in the analyzer) and enforce a sane length cap.
        if (typeof url !== 'string' || url.trim() === '') {
            return res.status(400).json({ error: 'A non-empty "url" string is required' });
        }
        if (url.length > 2048) {
            return res.status(413).json({ error: 'URL exceeds maximum allowed length (2048)' });
        }

        const result = analyzeURL(url);
        console.log(`[SCAN] ${url} -> ${result.label} (${result.score}) [Source: ${result.source}]`);

        // Persist to History (Cloud with Local Fallback)
        historyService.save({
            url: result.url,
            label: result.label,
            score: result.score,
            source: result.source
        });

        res.json(result);
    } catch (err) {
        console.error('check-url error:', err.message);
        res.status(500).json({ error: 'Internal error during URL analysis' });
    }
});

app.get('/api/history', async (req, res) => {
    const history = await historyService.getRecent();
    res.json(history);
});

app.get('/api/dataset', (req, res) => {
    res.json(datasetLoader.getAll());
});

app.get('/api/dataset-stats', (req, res) => {
    res.json(datasetLoader.getStats());
});

app.get('/api/stats', async (req, res) => {
    const history = await historyService.getRecent();
    const datasetStats = datasetLoader.getStats();

    // Calculate dashboard stats
    const totalScanned = history.length;
    const threatsBlocked = history.filter(h => h.label !== 'Safe').length;

    res.json({
        totalScanned,
        threatsBlocked,
        intelligenceSize: datasetStats.totalItems
    });
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Security Backend running at http://localhost:${PORT}`);
    });
}

// Export for Vercel and other serverless environments
module.exports = app;
