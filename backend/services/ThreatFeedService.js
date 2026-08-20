/**
 * ThreatFeedService — Free Live Threat Intelligence (Zero API Keys)
 *
 * Pulls from 3 public, open-source feeds:
 *   1. OpenPhish — active phishing URLs
 *   2. URLhaus (Abuse.ch) — active malware distribution URLs
 *   3. MalwareDomains — known malicious domains
 *
 * Refreshes automatically every 6 hours.
 * Falls back gracefully on network failure (keeps last known set).
 */

const FEEDS = [
    {
        name: 'OpenPhish',
        url: 'https://openphish.com/feed.txt',
        type: 'url'
    },
    {
        name: 'URLhaus',
        url: 'https://urlhaus.abuse.ch/downloads/text_online/',
        type: 'url'
    },
    {
        name: 'MalwareDomains',
        url: 'https://mirror1.malwaredomains.com/files/justdomains',
        type: 'domain'
    }
];

const REFRESH_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6 hours
const FETCH_TIMEOUT_MS    = 8000;               // 8 second per-feed timeout

class ThreatFeedService {
    constructor() {
        /** @type {Set<string>} lowercased hostnames */
        this.domainSet  = new Set();
        this.lastRefresh = null;
        this._refreshPromise = null;
    }

    // ─── Public API ───────────────────────────────────────────────────────────

    /**
     * Check whether a hostname is in the live threat feed.
     * @param {string} hostname  e.g. "evil-site.tk"
     * @returns {boolean}
     */
    check(hostname) {
        return this.domainSet.has(hostname.toLowerCase());
    }

    /** Start background auto-refresh on boot. */
    startAutoRefresh() {
        this._refresh();
        setInterval(() => this._refresh(), REFRESH_INTERVAL_MS);
    }

    get size() { return this.domainSet.size; }

    // ─── Internal ─────────────────────────────────────────────────────────────

    async _refresh() {
        // Prevent concurrent refreshes
        if (this._refreshPromise) return this._refreshPromise;

        this._refreshPromise = this._doRefresh().finally(() => {
            this._refreshPromise = null;
        });
        return this._refreshPromise;
    }

    async _doRefresh() {
        const newSet = new Set();
        let totalLoaded = 0;

        await Promise.allSettled(
            FEEDS.map(feed => this._fetchFeed(feed, newSet))
        );

        // Only swap if we got something meaningful
        if (newSet.size > 100) {
            this.domainSet  = newSet;
            this.lastRefresh = new Date();
            console.log(`🔄 [ThreatFeed] Refreshed — ${newSet.size} unique hostile domains loaded`);
        } else {
            console.warn('[ThreatFeed] Refresh yielded < 100 entries; keeping previous set');
        }
    }

    async _fetchFeed(feed, targetSet) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

        try {
            const res = await fetch(feed.url, {
                signal: controller.signal,
                headers: { 'User-Agent': 'SafeSurf-ThreatFeed/1.0' }
            });

            if (!res.ok) {
                console.warn(`[ThreatFeed] ${feed.name} returned HTTP ${res.status}`);
                return;
            }

            const text = await res.text();
            let count  = 0;

            for (const rawLine of text.split('\n')) {
                const line = rawLine.trim();
                if (!line || line.startsWith('#')) continue;

                try {
                    const normalized = line.startsWith('http')
                        ? new URL(line).hostname.toLowerCase()
                        : line.toLowerCase();

                    if (normalized && normalized.includes('.')) {
                        targetSet.add(normalized);
                        count++;
                    }
                } catch (_) { /* skip malformed entries */ }
            }

            console.log(`[ThreatFeed] ${feed.name}: +${count} entries`);
        } catch (err) {
            if (err.name === 'AbortError') {
                console.warn(`[ThreatFeed] ${feed.name} timed out after ${FETCH_TIMEOUT_MS}ms`);
            } else {
                console.warn(`[ThreatFeed] ${feed.name} failed: ${err.message}`);
            }
        } finally {
            clearTimeout(timer);
        }
    }
}

module.exports = new ThreatFeedService();
