/**
 * Comprehensive Test Suite for SafeSurf ML Engine & Detection Pipeline v3.0
 * Run: node backend/test.js
 */

const extract = require('./services/featureExtractor');
const detect  = require('./services/detectionEngine');
const mlEngine = require('./services/mlEngine');

// Initialize ML Engine
mlEngine.init();

const tests = [
    { url: 'https://google.com',                                  expected: 'Safe',      note: 'Official Google domain (whitelist)' },
    { url: 'https://github.com/torvalds/linux',                   expected: 'Safe',      note: 'Official GitHub repository' },
    { url: 'https://en.wikipedia.org/wiki/Machine_learning',      expected: 'Safe',      note: 'Official Wikipedia article' },
    { url: 'https://microsoft.com/en-us/products',                expected: 'Safe',      note: 'Official Microsoft products page' },
    { url: 'https://paypal.com/signin',                           expected: 'Safe',      note: 'Official PayPal login' },
    { url: 'https://nytimes.com/section/technology',              expected: 'Safe',      note: 'Legitimate news article' },
    { url: 'http://192.168.1.5/login',                            expected: 'Malicious', note: 'Raw IP address + login keyword' },
    { url: 'http://185.220.101.5:8080/dropper/payload.exe',       expected: 'Malicious', note: 'Raw IP + port + executable payload' },
    { url: 'http://g00gle-secure.xyz',                            expected: 'Malicious', note: 'Homoglyph visual spoofing + TLD' },
    { url: 'https://apple-id-support-verify.com',                 expected: 'Malicious', note: 'Brand impersonation + phishing keywords' },
    { url: 'http://paypal.com.account-verify.checkpoint.xyz',     expected: 'Malicious', note: 'Subdomain chain spoofing PayPal' },
    { url: 'https://xk9f2rp4mz.tk/payload.zip.exe',               expected: 'Malicious', note: 'High entropy DGA domain + double extension' },
    { url: 'http://secure-login.com/@verify/account',             expected: 'Malicious', note: 'Obfuscation character @ + sensitive keywords' },
    { url: 'https://login.verify.account.evil.xyz',               expected: 'Malicious', note: 'Deep nested subdomain phishing chain' },
    { url: 'https://free-gift-card.xyz',                          expected: 'Suspicious',note: 'Suspicious spam/phishing offer TLD' },
    { url: 'http://vulnerable-site-42.com/search?q=<script>alert(1)</script>', expected: 'Suspicious', note: 'XSS / Injection payload URL' }
];

const PASS = '\x1b[32m✅\x1b[0m';
const WARN = '\x1b[33m⚠️ \x1b[0m';
const FAIL = '\x1b[31m❌\x1b[0m';

console.log('\n🧪 SafeSurf Machine Learning & Security Engine v3.0 — Self Test\n' + '═'.repeat(70));

let passed = 0, failed = 0;
const startBench = process.hrtime.bigint();

for (const t of tests) {
    const t0 = process.hrtime.bigint();
    const features = extract(t.url);
    const result   = detect(features);
    const t1 = process.hrtime.bigint();
    const latencyUs = Number(t1 - t0) / 1000; // in microseconds

    const ok = (result.label === t.expected) ||
               (t.expected === 'Suspicious' && (result.label === 'Suspicious' || result.label === 'Malicious')) ||
               (t.expected === 'Malicious' && (result.label === 'Malicious' || result.label === 'Suspicious'));

    const icon = ok ? PASS : FAIL;
    console.log(`\n${icon} ${t.note}`);
    console.log(`   URL:      ${t.url}`);
    console.log(`   Expected: ${t.expected.padEnd(10)} Got: ${result.label.padEnd(10)} Score: ${String(result.score).padStart(3)} | ThreatProb: ${(result.threatProbability * 100).toFixed(1)}% | Latency: ${latencyUs.toFixed(1)} µs`);
    
    if (result.details && result.details.length > 0) {
        console.log(`   Signals:  ${result.details.map(d => d.label).slice(0, 2).join(' | ')}`);
    }

    if (!ok) {
        failed++;
    } else {
        passed++;
    }
}

const totalBenchMs = Number(process.hrtime.bigint() - startBench) / 1e6;
const avgLatencyUs = (totalBenchMs * 1000) / tests.length;

console.log('\n' + '═'.repeat(70));
console.log(`\nResults: ${passed} passed, ${failed} failed out of ${tests.length} test cases`);
console.log(`⚡ Average Evaluation Latency: ${avgLatencyUs.toFixed(2)} µs (${(avgLatencyUs / 1000).toFixed(4)} ms) per URL\n`);

if (failed > 0) process.exit(1);
