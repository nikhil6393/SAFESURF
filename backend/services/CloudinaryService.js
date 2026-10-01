/**
 * Cloudinary Media & Threat Evidence Service
 * Handles uploading, archiving, and managing threat screenshots,
 * phishing page captures, and report attachments via Cloudinary SDK v2.
 */

'use strict';

const cloudinary = require('cloudinary').v2;
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env'), override: true });

class CloudinaryService {
    constructor() {
        this.isConfigured = false;
        this.init();
    }

    init() {
        const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
        const apiKey = process.env.CLOUDINARY_API_KEY;
        const apiSecret = process.env.CLOUDINARY_API_SECRET;
        const cloudinaryUrl = process.env.CLOUDINARY_URL;

        if (cloudinaryUrl) {
            cloudinary.config({ cloudinary_url: cloudinaryUrl });
            this.isConfigured = true;
            console.log('☁️  [Cloudinary] Initialized using CLOUDINARY_URL');
        } else if (cloudName && apiKey && apiSecret) {
            cloudinary.config({
                cloud_name: cloudName,
                api_key: apiKey,
                api_secret: apiSecret,
                secure: true
            });
            this.isConfigured = true;
            console.log(`☁️  [Cloudinary] Initialized with cloud_name: ${cloudName}`);
        } else {
            console.warn('⚠️  [Cloudinary] Credentials not set in .env. Uploads will use local simulated storage.');
        }
    }

    /**
     * Upload an image/screenshot (base64 string or remote URL) to Cloudinary.
     * @param {string} fileInput - Base64 data URI or remote image URL
     * @param {object} options - Optional folder, tags, public_id
     * @returns {Promise<object>}
     */
    async uploadEvidence(fileInput, options = {}) {
        const defaultOptions = {
            folder: options.folder || 'safesurf/threat-evidence',
            resource_type: 'auto',
            tags: ['safesurf', 'threat-evidence', ...(options.tags || [])],
            transformation: options.transformation || [
                { quality: 'auto', fetch_format: 'auto' }
            ]
        };

        if (options.public_id) {
            defaultOptions.public_id = options.public_id;
        }

        if (!this.isConfigured) {
            console.warn('[Cloudinary] Offline / unconfigured mode: returning simulated upload payload.');
            return {
                url: fileInput.startsWith('data:') ? 'https://res.cloudinary.com/demo/image/upload/sample.jpg' : fileInput,
                secure_url: fileInput.startsWith('data:') ? 'https://res.cloudinary.com/demo/image/upload/sample.jpg' : fileInput,
                public_id: `simulated_${Date.now()}`,
                format: 'jpg',
                bytes: fileInput.length,
                simulated: true,
                message: 'Cloudinary credentials missing in .env (add CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET)'
            };
        }

        try {
            const result = await cloudinary.uploader.upload(fileInput, defaultOptions);
            return {
                url: result.url,
                secure_url: result.secure_url,
                public_id: result.public_id,
                format: result.format,
                width: result.width,
                height: result.height,
                bytes: result.bytes,
                created_at: result.created_at
            };
        } catch (error) {
            console.error('[Cloudinary] Upload failed:', error.message);
            throw error;
        }
    }

    /**
     * Upload a raw file Buffer (from Multer memory storage).
     * @param {Buffer} buffer - File buffer
     * @param {object} options - Upload options
     * @returns {Promise<object>}
     */
    async uploadBuffer(buffer, options = {}) {
        if (!this.isConfigured) {
            return {
                secure_url: 'https://res.cloudinary.com/demo/image/upload/sample.jpg',
                public_id: `simulated_buffer_${Date.now()}`,
                bytes: buffer.length,
                simulated: true
            };
        }

        const folder = options.folder || 'safesurf/attachments';
        return new Promise((resolve, reject) => {
            const uploadStream = cloudinary.uploader.upload_stream(
                { folder, resource_type: 'auto', tags: ['safesurf', ...(options.tags || [])] },
                (error, result) => {
                    if (error) return reject(error);
                    resolve({
                        url: result.url,
                        secure_url: result.secure_url,
                        public_id: result.public_id,
                        format: result.format,
                        bytes: result.bytes
                    });
                }
            );
            uploadStream.end(buffer);
        });
    }

    /**
     * Delete an asset from Cloudinary by public ID.
     * @param {string} publicId
     * @returns {Promise<object>}
     */
    async deleteAsset(publicId) {
        if (!this.isConfigured) {
            return { result: 'ok (simulated)' };
        }
        return await cloudinary.uploader.destroy(publicId);
    }

    getStatus() {
        return {
            configured: this.isConfigured,
            cloud_name: process.env.CLOUDINARY_CLOUD_NAME || (this.isConfigured ? 'configured' : null)
        };
    }
}

module.exports = new CloudinaryService();
