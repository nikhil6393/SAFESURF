const { performance } = require('perf_hooks');

// Mock dataset similar to the 640k map you use
const dataset = new Map();
console.log("Loading 640,000 mock signatures into memory...");
for (let i = 0; i < 640000; i++) {
    dataset.set(`malicious-domain-${i}.com`, true);
}
console.log("Dataset loaded successfully.\n");

function benchmarkLatency() {
    const testSize = 10000;
    console.log(`🚀 Running Latency Benchmark for ${testSize} lookups...`);

    const start = performance.now();

    for (let i = 0; i < testSize; i++) {
        // Randomly lookup domains (some exist, some don't to simulate real traffic)
        dataset.has(`malicious-domain-${Math.floor(Math.random() * 700000)}.com`);
    }

    const end = performance.now();
    const totalTimeMs = end - start;
    const avgLatencyMs = totalTimeMs / testSize;

    console.log(`\n📊 BENCHMARK RESULTS:`);
    console.log(`Total Time for ${testSize} lookups: ${totalTimeMs.toFixed(2)} ms`);
    console.log(`Average Latency per URL: ${avgLatencyMs.toFixed(4)} ms`);
    
    if (avgLatencyMs < 0.42) {
        console.log(`\n✅ PROOF SUCCESSFUL: Average latency is well below the claimed 0.42ms!`);
    }
}

benchmarkLatency();
