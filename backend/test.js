/**
 * Quick self-test for featureExtractor v2 + detectionEngine v2
 * Run: node backend/test.js
 */
const extract = require('./services/featureExtractor');
const detect  = require('./services/detectionEngine');

const tests = [
    { url: 'https://google.com',                      expected: 'Safe',      note: 'Official whitelist' },
    { url: 'https://github.com/torvalds/linux',       expected: 'Safe',      note: 'Official with path' },
    { url: 'https://microsoft.com/en-us/products',    expected: 'Safe',      note: 'Official with path' },
    { url: 'http://192.168.1.5/login',                expected: 'Malicious', note: 'IP + HTTP + keyword' },
    { url: 'http://g00gle-secure.xyz',                expected: 'Malicious', note: 'Homoglyph + TLD + HTTP' },
    { url: 'https://apple-id-support-verify.com',     expected: 'Malicious', note: 'Brand + keywords' },
    { url: 'https://secure-bank-login.net',           expected: 'Malicious', note: 'Keywords + entropy (conservatively flagged Malicious — correct)' },
    { url: 'http://bit.ly/abc123',                    expected: 'Malicious', note: 'Shortener + HTTP + no vowels' },
    { url: 'https://free-gift-card.xyz',              expected: 'Suspicious',note: 'Suspicious TLD' },
    { url: 'https://xk9f2rp4mz.tk',                  expected: 'Malicious', note: 'High entropy + TLD' },
    { url: 'http://secure-login.com/@verify/account', expected: 'Malicious', note: 'Obfusc + keywords' },
    { url: 'https://login.verify.account.evil.xyz',   expected: 'Malicious', note: 'Deep subdomain + keywords + TLD' },
    { url: 'https://paypal.com/signin',               expected: 'Safe',      note: 'Official + keyword path OK' },
];

const PASS = '\x1b[32m✅\x1b[0m';
const WARN = '\x1b[33m⚠️ \x1b[0m';
const FAIL = '\x1b[31m❌\x1b[0m';

console.log('\n🧪 SafeSurf Detection Engine v2.0 — Self Test\n' + '═'.repeat(70));

let passed = 0, failed = 0;

for (const t of tests) {
    const features = extract(t.url);
    const result   = detect(features);
    const ok       = result.label === t.expected;

    const icon = ok ? PASS : (result.label === 'Safe' && t.expected !== 'Safe' ? FAIL : WARN);
    console.log(`\n${icon} ${t.note}`);
    console.log(`   URL:      ${t.url}`);
    console.log(`   Expected: ${t.expected.padEnd(10)} Got: ${result.label} (score=${result.score})`);
    if (!ok) {
        console.log(`   Signals: ${result.details.map(d => d.label).join(' | ')}`);
        failed++;
    } else {
        passed++;
    }
}

console.log('\n' + '═'.repeat(70));
console.log(`\nResults: ${passed} passed, ${failed} failed out of ${tests.length} tests\n`);
if (failed > 0) process.exit(1);
