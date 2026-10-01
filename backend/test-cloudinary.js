/**
 * Test script for Cloudinary Integration
 * Run: node backend/test-cloudinary.js
 */

const cloudinaryService = require('./services/CloudinaryService');

async function testCloudinary() {
    console.log('\n🧪 Testing Cloudinary Service...\n' + '═'.repeat(60));

    const status = cloudinaryService.getStatus();
    console.log('Status:', status);

    // Test 1: Upload a base64 sample screenshot / evidence
    const sampleBase64 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
    console.log('\nUploading sample screenshot payload...');
    const result = await cloudinaryService.uploadEvidence(sampleBase64, {
        tags: ['test-threat-evidence'],
        folder: 'safesurf/test'
    });

    console.log('Upload Result:', {
        url: result.secure_url || result.url,
        public_id: result.public_id,
        simulated: result.simulated || false
    });

    // Test 2: Upload a buffer
    console.log('\nUploading buffer payload...');
    const buffer = Buffer.from('SafeSurf Report Evidence File Content', 'utf-8');
    const bufferResult = await cloudinaryService.uploadBuffer(buffer, {
        folder: 'safesurf/test-reports'
    });

    console.log('Buffer Upload Result:', {
        url: bufferResult.secure_url || bufferResult.url,
        public_id: bufferResult.public_id,
        simulated: bufferResult.simulated || false
    });

    console.log('\n' + '═'.repeat(60));
    console.log('✅ Cloudinary Service tests executed successfully!\n');
}

testCloudinary().catch(console.error);
