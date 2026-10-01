const { performance } = require('perf_hooks');
const extract = require('./services/featureExtractor');
const detect = require('./services/detectionEngine');
const mlEngine = require('./services/mlEngine');

mlEngine.init();

function benchmarkMLDetection() {
    const urls = [
        'https://google.com/search?q=cybersecurity+defense+frameworks',
        'https://en.wikipedia.org/wiki/Artificial_intelligence',
        'http://paypal.com.account-verify.security-checkpoint.xyz/login.php',
        'http://g00gle-secure.xyz/auth?user=test',
        'http://185.220.101.5:8080/dropper/payload.exe',
        'https://apple-id-support-verify.com/signin',
        'https://xk9f2rp4mz.tk/payload.zip.exe',
        'https://free-gift-card.xyz'
    ];

    const iterations = 5000;
    console.log(`\n🚀 Running End-to-End Machine Learning + Feature Extraction Benchmark for ${iterations} scans...`);

    // Warm up V8 JIT
    for (let i = 0; i < 500; i++) {
        const u = urls[i % urls.length];
        detect(extract(u));
    }

    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
        const u = urls[i % urls.length];
        const f = extract(u);
        detect(f);
    }
    const end = performance.now();

    const totalTimeMs = end - start;
    const avgLatencyMs = totalTimeMs / iterations;

    console.log(`\n📊 END-TO-END ML BENCHMARK RESULTS:`);
    console.log(`  Total Iterations: ${iterations} scans`);
    console.log(`  Total Time:       ${totalTimeMs.toFixed(2)} ms`);
    console.log(`  Avg Latency:      ${avgLatencyMs.toFixed(4)} ms (${(avgLatencyMs * 1000).toFixed(1)} µs) per URL`);
    console.log(`  Throughput:       ${Math.round(iterations / (totalTimeMs / 1000))} scans / second`);
    
    if (avgLatencyMs < 0.5) {
        console.log(`\n✅ ULTRA-LOW LATENCY CONFIRMED: End-to-end ML inference runs at < 0.5ms!`);
    }
}

benchmarkMLDetection();
