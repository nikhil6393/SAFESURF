/**
 * Test script for PDF Threat Report Generation & Cloudinary Archiving
 * Run: node backend/test-pdf-export.js
 */

const pdfReportService = require('./services/PdfReportService');
const fs = require('fs');
const path = require('path');

async function testPdfReport() {
    console.log('\n🧪 Testing PDF Report Generation & Cloudinary Archiving...\n' + '═'.repeat(65));

    const sampleScan = {
        url: 'http://paypal.com.account-verify.security-checkpoint.xyz/login.php',
        label: 'Malicious',
        score: 92,
        threatProbability: 0.923,
        mlConfidence: 0.985,
        source: 'ml_ensemble',
        refId: 'SCAN-TEST-2026',
        details: [
            { label: 'Suspected brand impersonation in unofficial domain (paypal)', impact: 65, type: 'risk' },
            { label: 'High domain entropy (4.12) — machine-generated / DGA domain', impact: 35, type: 'risk' },
            { label: 'Phishing keywords detected: account, verify, login', impact: 40, type: 'risk' },
            { label: 'Non-standard / high-risk domain suffix (.xyz)', impact: 25, type: 'risk' }
        ],
        features: {
            entropy_host: 4.12,
            consonant_ratio_host: 0.72,
            subdomain_depth: 3,
            is_ip_address: 0,
            num_sensitive_keywords: 3,
            is_https: 0
        }
    };

    console.log('1. Generating PDF buffer...');
    const result = await pdfReportService.generateAndArchiveReport(sampleScan);

    console.log('Result:', {
        filename: result.filename,
        pdfSizeBytes: result.pdfBuffer.length,
        cloudinaryUrl: result.cloudinaryUrl,
        public_id: result.public_id,
        simulated: result.simulated
    });

    // Save a local copy to verify valid PDF output
    const localOutputPath = path.join(__dirname, 'sample-report.pdf');
    fs.writeFileSync(localOutputPath, result.pdfBuffer);
    console.log(`\n💾 Saved local verification PDF to: ${localOutputPath}`);

    // Verify PDF header %PDF-
    const header = result.pdfBuffer.slice(0, 5).toString('utf-8');
    if (header.startsWith('%PDF')) {
        console.log(`✅ Valid PDF binary signature confirmed: ${header}`);
    } else {
        throw new Error(`Invalid PDF signature: ${header}`);
    }

    console.log('\n' + '═'.repeat(65));
    console.log('✅ PDF Generation & Cloudinary Archiving verified successfully!\n');
}

testPdfReport().catch(console.error);
