const fs = require('fs');
const path = require('path');
require('dotenv').config();

class DatasetLoader {
    constructor() {
        this.dataset = [];
        this.urlMap = new Map();
        // External datasets are opt-in via the EXTERNAL_DATASETS env var
        // (comma-separated absolute paths). When unset, the bundled sample in
        // ./data/dataset.csv is used, so the project is portable across machines.
        this.datasetPaths = (process.env.EXTERNAL_DATASETS || '')
            .split(',')
            .map(p => p.trim())
            .filter(Boolean);
    }

    init() {
        this.datasetPaths.forEach(filePath => {
            if (!fs.existsSync(filePath)) {
                console.warn(`Dataset not found at ${filePath}, skipping...`);
                return;
            }
            this.loadDataset(filePath);
        });

        // Final fallback if nothing loaded
        if (this.urlMap.size === 0) {
            console.warn("No external datasets loaded, using local sample.");
            this.loadDataset(path.join(__dirname, '../data/dataset.csv'));
        }

        console.log(`Initialization complete. Total unique signatures indexed: ${this.urlMap.size}`);
    }

    loadDataset(filePath) {
        try {
            const data = fs.readFileSync(filePath, 'utf8');
            const lines = data.split('\n');
            if (lines.length < 2) return;

            const filename = path.basename(filePath).toLowerCase();
            const header = lines[0].split(',').map(h => h.trim().toLowerCase());

            console.log(`Crunching ${filename}...`);

            if (filename === 'spam.csv') {
                this.parseSpamDataset(lines);
            } else {
                this.parseStandardDataset(lines, header);
            }
        } catch (err) {
            console.error(`Error loading ${filePath}:`, err);
        }
    }

    parseStandardDataset(lines, header) {
        const urlIdx = header.indexOf('url');
        const typeIdx = header.indexOf('type');
        const labelIdx = header.indexOf('label');

        if (urlIdx === -1) {
            console.warn("No 'url' column found in this dataset. Skipping signature indexing.");
            return;
        }

        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;

            const parts = line.split(',');
            let url = parts[urlIdx] ? parts[urlIdx].trim() : '';
            let type = (typeIdx !== -1 && parts[typeIdx]) ? parts[typeIdx].trim() : 'unknown';
            
            if (!url) continue;

            let label;
            if (labelIdx !== -1 && parts[labelIdx]) {
                label = parts[labelIdx].trim();
            } else {
                label = (type === 'benign' || type === 'safe') ? 'safe' : (type === 'defacement' ? 'suspicious' : 'malicious');
            }

            this.addToIndex(url, label, type);
        }
    }

    parseSpamDataset(lines) {
        // v1 = label (ham/spam), v2 = text
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;

            const parts = line.split(',');
            const type = parts[0] ? parts[0].trim().toLowerCase() : '';
            const text = parts.slice(1).join(',');

            // Extract URLs from text (allowing for common spam obfuscation like spaces)
            const urlRegex = /(https?:\/\/[\w. \-\/?=&%]+)/gi;
            const matches = text.match(urlRegex);

            if (matches) {
                matches.forEach(url => {
                    // Strip trailing punctuation often found in CSV text
                    const cleanUrl = url.replace(/[.,!?;:)]+$/, '').trim();
                    if (!cleanUrl) return;

                    this.addToIndex(cleanUrl, type === 'spam' ? 'malicious' : 'safe', `spam_sms_${type}`);

                    // Also indexing the protocol-stripped version for more flexible lookups
                    const stripped = cleanUrl.replace(/^https?:\/\//, '');
                    if (stripped && stripped !== cleanUrl) {
                        this.addToIndex(stripped, type === 'spam' ? 'malicious' : 'safe', `spam_sms_${type}`);
                    }
                });
            }
        }
    }

    addToIndex(url, label, type) {
        if (!this.urlMap.has(url)) {
            const item = { url, label, type };
            this.urlMap.set(url, item);
            if (this.dataset.length < 1000) {
                this.dataset.push(item);
            }
        }
    }

    check(url) {
        // 1. Try exact match from input
        let match = this.urlMap.get(url);
        if (match) return match;

        // 2. Try cleaning URL for match
        let cleanUrl = url.replace(/^https?:\/\//, '').replace(/\/$/, '');
        match = this.urlMap.get(cleanUrl);
        if (match) return match;

        // 3. Try hostname match
        try {
            const parsed = new URL(url.startsWith('http') ? url : 'http://' + url);
            const hostname = parsed.hostname.toLowerCase();
            match = this.urlMap.get(hostname);
            if (match) return match;
        } catch (e) { }

        return null;
    }

    getAll() {
        // Return only the preview subset to prevent frontend crash
        return this.dataset;
    }

    getStats() {
        return {
            totalItems: this.urlMap.size,
            previewItems: this.dataset.length
        };
    }
}

module.exports = new DatasetLoader();
