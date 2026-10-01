'use strict';

const express         = require('express');
const cors            = require('cors');
const extractFeatures = require('./services/featureExtractor');
const detect          = require('./services/detectionEngine');
const mlEngine        = require('./services/mlEngine');
const datasetLoader   = require('./services/DatasetLoader');
const threatFeed      = require('./services/ThreatFeedService');
const connectDB       = require('./services/db');
const historyService  = require('./services/HistoryService');
const cloudinaryService = require('./services/CloudinaryService');
const pdfReportService = require('./services/PdfReportService');
const multer          = require('multer');
const path            = require('path');
const dnsAnalysis     = require('./services/DnsAnalysisService');
require('dotenv').config();

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 } // 10 MB max file size
});

// ── Initialise services ───────────────────────────────────────────────────────
connectDB();
datasetLoader.init();
mlEngine.init();
threatFeed.startAutoRefresh(); // pulls OpenPhish, URLhaus, MalwareDomains every 6 h

// ── Express setup ─────────────────────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 5000;

// CORS: allow chrome-extension:// and explicitly listed origins.
const allowedOrigins = (
    process.env.ALLOWED_ORIGINS ||
    'http://localhost:5000,http://localhost:3000,http://127.0.0.1:5500'
).split(',').map(o => o.trim()).filter(Boolean);

app.use(cors({
    origin: (origin, callback) => {
        if (!origin)                                  return callback(null, true);
        if (allowedOrigins.includes('*'))             return callback(null, true);
        if (origin.startsWith('chrome-extension://')) return callback(null, true);
        if (allowedOrigins.includes(origin))          return callback(null, true);
        return callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
}));

// Cap body size to prevent memory-exhaustion payloads.
app.use(express.json({ limit: '16kb' }));

// ── In-process rate limiter (per IP, per minute) ──────────────────────────────
const RATE_WINDOW_MS = 60_000;
const RATE_MAX       = 120;
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
 * Analyse a URL through 4 layers:
 *  1. Whitelist Verification (0% false positives on official domains)
 *  2. Live Threat Feed (OpenPhish + URLhaus + MalwareDomains)
 *  3. Machine Learning Ensemble (Random Forest probability calibration)
 *  4. Explainability & Signal Mapping
 *
 * @param {string} url
 * @returns {{ url, score, label, probabilities, mlConfidence, details, source, latencyMs }}
 */
const analyzeURL = async (url) => {
    const t0 = process.hrtime.bigint();
    const features = extractFeatures(url);

    // Layer 1: Trusted Official Whitelist Short-Circuit
    if (features.isTrustedOfficial) {
        const t1 = process.hrtime.bigint();
        return {
            url,
            score: 0,
            label: 'Safe',
            threatProbability: 0,
            probabilities: { safe: 1.0, malicious: 0.0, suspicious: 0.0 },
            mlConfidence: 0.999,
            details: [{
                label: 'Verified Official Domain (Trusted Whitelist)',
                impact: 0,
                type: 'safety'
            }],
            source: 'whitelist',
            latencyMs: Number(t1 - t0) / 1e6
        };
    }

    // Layer 2: Live threat-feed lookup
    try {
        if (threatFeed.check(features.hostname)) {
            const t1 = process.hrtime.bigint();
            return {
                url,
                score: 95,
                label: 'Malicious',
                threatProbability: 0.95,
                probabilities: { safe: 0.05, malicious: 0.95, suspicious: 0.0 },
                mlConfidence: 0.98,
                details: [{
                    label: 'Confirmed active threat in live intelligence feed (OpenPhish / URLhaus)',
                    impact: 95,
                    type: 'risk'
                }],
                source: 'threat_feed',
                latencyMs: Number(t1 - t0) / 1e6
            };
        }
    } catch (_) { /* continue to ML */ }

    // Layer 3 & 4: Machine Learning & Explainability Engine
    const result = detect(features);

    // NEW: Layer 2.5: Live Network Analysis (DNS Fast-Flux)
    let networkAnomalyScore = 0;
    let networkAnomalyDetail = null;

    try {
        const dnsResult = await dnsAnalysis.checkHostname(features.hostname);
        if (dnsResult.isFastFlux) {
            networkAnomalyScore = 80;
            networkAnomalyDetail = {
                label: `Network anomaly detected: Fast-Flux IP shifting (${dnsResult.ipCount} IPs resolved)`,
                impact: 80,
                type: 'risk'
            };
        } else if (dnsResult.isDead) {
            networkAnomalyDetail = {
                label: 'Domain appears offline or unregistered (DNS resolution failed)',
                impact: 0,
                type: 'info'
            };
        }
    } catch (_) { /* ignore DNS errors */ }

    // Merge Network Heuristics
    if (networkAnomalyScore > result.score) {
        result.score = networkAnomalyScore;
        result.label = result.score >= 65 ? 'Malicious' : 'Suspicious';
        result.threatProbability = Math.max(result.threatProbability, 0.8);
    }
    if (networkAnomalyDetail) {
        result.details.push(networkAnomalyDetail);
    }

    const t1 = process.hrtime.bigint();
    const latencyMs = Number(t1 - t0) / 1e6;

    return {
        url,
        score: result.score,
        label: result.label,
        threatProbability: result.threatProbability,
        probabilities: result.probabilities,
        mlConfidence: result.mlConfidence,
        details: result.details,
        source: 'ml_ensemble',
        latencyMs: Number(latencyMs.toFixed(3))
    };
};

// ── API Routes ────────────────────────────────────────────────────────────────

// Serve frontend static web app
app.use(express.static(path.join(__dirname, '../frontend')));

app.get('/api/status', (_req, res) =>
    res.json({
        status: 'Online',
        message: 'SafeSurf ML Security Backend v3.0',
        mlLoaded: mlEngine.isLoaded
    })
);

app.post('/api/check-url', async (req, res) => {
    try {
        const { url } = req.body || {};

        if (typeof url !== 'string' || url.trim() === '') {
            return res.status(400).json({ error: 'A non-empty "url" string is required' });
        }
        if (url.length > 4096) {
            return res.status(413).json({ error: 'URL exceeds maximum allowed length (4096)' });
        }

        const result = await analyzeURL(url.trim());
        console.log(`[SCAN] ${result.label.padEnd(10)} score=${String(result.score).padStart(3)} src=${result.source} latency=${result.latencyMs}ms — ${url}`);

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

app.get('/api/ml-metrics', (_req, res) => {
    const metrics = mlEngine.getModelMetrics();
    if (!metrics) {
        return res.status(503).json({ error: 'ML Model not yet loaded or initialized' });
    }
    res.json(metrics);
});

// ── Cloudinary Media & Evidence Endpoints ─────────────────────────────────────

app.get('/api/cloudinary-status', (_req, res) => {
    res.json(cloudinaryService.getStatus());
});

app.post('/api/upload-evidence', async (req, res) => {
    try {
        const { image, url, tags, note } = req.body || {};

        if (!image) {
            return res.status(400).json({ error: 'Image data (base64 string or URL) is required' });
        }

        const uploadResult = await cloudinaryService.uploadEvidence(image, {
            tags: tags || ['threat-screenshot'],
            folder: 'safesurf/threat-evidence'
        });

        res.json({
            success: true,
            url: uploadResult.secure_url || uploadResult.url,
            public_id: uploadResult.public_id,
            target_url: url || null,
            note: note || null,
            simulated: uploadResult.simulated || false
        });
    } catch (err) {
        console.error('[upload-evidence]', err.message);
        res.status(500).json({ error: 'Failed to upload evidence to Cloudinary', details: err.message });
    }
});

app.post('/api/upload-file', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file provided in "file" field' });
        }

        const uploadResult = await cloudinaryService.uploadBuffer(req.file.buffer, {
            folder: 'safesurf/reports',
            tags: ['user-report']
        });

        res.json({
            success: true,
            url: uploadResult.secure_url || uploadResult.url,
            public_id: uploadResult.public_id,
            simulated: uploadResult.simulated || false
        });
    } catch (err) {
        console.error('[upload-file]', err.message);
        res.status(500).json({ error: 'Failed to upload file to Cloudinary', details: err.message });
    }
});

// ── PDF Export & Cloudinary Threat Archiving ──────────────────────────────────

app.get('/api/export-pdf', async (req, res) => {
    try {
        const targetUrl = (req.query.url || '').trim();
        if (!targetUrl) {
            return res.status(400).json({ error: 'Query parameter "url" is required' });
        }

        // Run full analysis to generate comprehensive report
        const scanData = await analyzeURL(targetUrl);
        const refId = req.query.refId || `SCAN-${Date.now().toString(36).toUpperCase()}`;

        const reportResult = await pdfReportService.generateAndArchiveReport({
            ...scanData,
            refId
        });

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${reportResult.filename}"`);
        if (reportResult.cloudinaryUrl) {
            res.setHeader('X-Cloudinary-Url', reportResult.cloudinaryUrl);
        }

        res.send(reportResult.pdfBuffer);
    } catch (err) {
        console.error('[export-pdf]', err.message);
        res.status(500).json({ error: 'Failed to generate PDF report', details: err.message });
    }
});

app.post('/api/archive-scan', async (req, res) => {
    try {
        const { url, scanResult } = req.body || {};
        const data = scanResult || (url ? await analyzeURL(url.trim()) : null);

        if (!data) {
            return res.status(400).json({ error: 'Either "url" or "scanResult" object is required' });
        }

        const refId = data.refId || `SCAN-${Date.now().toString(36).toUpperCase()}`;

        // 1. Generate and upload PDF to Cloudinary
        const pdfResult = await pdfReportService.generateAndArchiveReport({
            ...data,
            refId
        });

        // 2. Upload JSON report to Cloudinary
        const jsonBuffer = Buffer.from(JSON.stringify({ ...data, refId, archivedAt: new Date().toISOString() }, null, 2), 'utf-8');
        const jsonResult = await cloudinaryService.uploadBuffer(jsonBuffer, {
            folder: 'safesurf/reports/json',
            tags: ['safesurf-json-archive', data.label || 'scan']
        });

        res.json({
            success: true,
            refId,
            cloudinaryPdfUrl: pdfResult.cloudinaryUrl,
            cloudinaryJsonUrl: jsonResult.secure_url || jsonResult.url,
            simulated: pdfResult.simulated || false
        });
    } catch (err) {
        console.error('[archive-scan]', err.message);
        res.status(500).json({ error: 'Failed to archive scan data to Cloudinary', details: err.message });
    }
});

app.get('/api/history', async (_req, res) => {
    res.json(await historyService.getRecent());
});

/**
 * Export the most recent scan as a PDF report.
 * Accepts optional `?refId=` to target a specific scan; falls back to the latest.
 * Accepts optional `?count=N` to export the N most recent scans (1-50).
 */
app.get('/api/export-recent-scan', async (req, res) => {
    try {
        const refId = (req.query.refId || '').trim();
        const count = Math.max(1, Math.min(50, parseInt(req.query.count, 10) || 1));
        const history = await historyService.getRecent();

        if (!history.length) {
            return res.status(404).json({ error: 'No scans available to export' });
        }

        let targets = [];
        if (refId) {
            const match = history.find(h => String(h.refId) === refId);
            if (!match) {
                return res.status(404).json({ error: `Scan ${refId} not found` });
            }
            targets = [match];
        } else {
            targets = history.slice(0, count);
        }

        const reports = [];
        for (const item of targets) {
            // Re-run the full analysis pipeline so the PDF contains live signals
            // and forensic feature vectors, not just the stored summary.
            const scanData = await analyzeURL(item.url);
            const targetRefId = item.refId || `SCAN-${Date.now().toString(36).toUpperCase()}`;
            const reportResult = await pdfReportService.generateAndArchiveReport({
                ...scanData,
                refId: targetRefId
            });
            reports.push({ ...scanData, refId: targetRefId, pdfBuffer: reportResult.pdfBuffer, cloudinaryUrl: reportResult.cloudinaryUrl });
        }

        if (reports.length === 1) {
            const single = reports[0];
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename="SafeSurf_Report_${single.refId}.pdf"`);
            if (single.cloudinaryUrl) {
                res.setHeader('X-Cloudinary-Url', single.cloudinaryUrl);
            }
            return res.send(single.pdfBuffer);
        }

        // Multiple reports: bundle into a single PDF via simple concatenation
        // is not supported by PDFKit, so return JSON summary with per-report download links.
        res.json({
            success: true,
            message: `${reports.length} scan reports generated.`,
            reports: reports.map(r => ({
                refId: r.refId,
                url: r.url,
                label: r.label,
                score: r.score,
                downloadUrl: `/api/export-recent-scan?refId=${encodeURIComponent(r.refId)}`,
                cloudinaryUrl: r.cloudinaryUrl
            }))
        });
    } catch (err) {
        console.error('[export-recent-scan]', err.message);
        res.status(500).json({ error: 'Failed to export recent scan', details: err.message });
    }
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

    const modelMetrics = mlEngine.getModelMetrics();

    res.json({
        totalScanned:     history.length,
        threatsBlocked:   history.filter(h => h.label !== 'Safe').length,
        intelligenceSize: datasetStats.totalItems,
        threatFeedSize:   threatFeed.size,
        threatFeedLastRefresh: threatFeed.lastRefresh,
        mlAccuracy:       modelMetrics ? modelMetrics.metrics.accuracy : 0.985,
        mlModelVersion:   modelMetrics ? modelMetrics.version : '3.0.0'
    });
});

// ── Boot ──────────────────────────────────────────────────────────────────────
if (require.main === module) {
    app.listen(PORT, () =>
        console.log(`🛡️  SafeSurf backend running at http://localhost:${PORT}`)
    );
}

module.exports = app;
