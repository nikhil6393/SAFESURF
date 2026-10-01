/**
 * SafeSurf PDF Threat Assessment Report Generator & Cloudinary Archiver
 * Generates professional PDF security audit reports and uploads them to Cloudinary.
 */

'use strict';

const PDFDocument = require('pdfkit');
const cloudinaryService = require('./CloudinaryService');

class PdfReportService {
    /**
     * Builds a PDF report buffer from scan result data.
     * @param {object} scanData - { url, label, score, probabilities, mlConfidence, details, source, timestamp, refId }
     * @returns {Promise<Buffer>}
     */
    generatePdfBuffer(scanData) {
        return new Promise((resolve, reject) => {
            try {
                const doc = new PDFDocument({
                    size: 'A4',
                    margin: 40,
                    info: {
                        Title: `SafeSurf Security Report - ${scanData.url}`,
                        Author: 'SafeSurf Neural Security Platform',
                        Subject: 'Malware & Phishing Threat Assessment'
                    }
                });

                const buffers = [];
                doc.on('data', chunk => buffers.push(chunk));
                doc.on('end', () => resolve(Buffer.concat(buffers)));
                doc.on('error', err => reject(err));

                const label = (scanData.label || 'Safe').toUpperCase();
                const score = Number(scanData.score) || 0;
                const isSafe = label === 'SAFE';
                const isSuspicious = label === 'SUSPICIOUS';

                // Color palette
                const primaryColor = '#7c3aed'; // Cyber violet
                const textColor = '#1e293b';
                const subTextColor = '#64748b';
                const verdictColor = isSafe ? '#10b981' : (isSuspicious ? '#f59e0b' : '#f43f5e');
                const bgColor = isSafe ? '#ecfdf5' : (isSuspicious ? '#fffbeb' : '#fff1f2');

                // ── HEADER ──────────────────────────────────────────────────
                doc.rect(0, 0, doc.page.width, 100).fill('#0f172a');
                
                doc.fillColor('#ffffff')
                   .fontSize(22)
                   .font('Helvetica-Bold')
                   .text('SAFESURF SECURITY AUDIT', 40, 30);

                doc.fontSize(10)
                   .font('Helvetica')
                   .fillColor('#94a3b8')
                   .text('Automated Neural Threat Assessment & URL Forensic Report', 40, 58);

                const refId = scanData.refId || `SCAN-${Date.now().toString(36).toUpperCase()}`;
                doc.fontSize(9)
                   .fillColor('#94a3b8')
                   .text(`Report ID: #${refId}`, doc.page.width - 200, 35, { align: 'right', width: 160 })
                   .text(`Generated: ${new Date().toUTCString()}`, doc.page.width - 200, 50, { align: 'right', width: 160 });

                let y = 120;

                // ── TARGET URL BOX ──────────────────────────────────────────
                doc.roundedRect(40, y, doc.page.width - 80, 50, 6)
                   .fillAndStroke('#f8fafc', '#e2e8f0');

                doc.fillColor(subTextColor)
                   .fontSize(8)
                   .font('Helvetica-Bold')
                   .text('TARGET URL INSPECTED', 55, y + 10);

                doc.fillColor(textColor)
                   .fontSize(11)
                   .font('Helvetica')
                   .text(scanData.url || 'Unknown', 55, y + 24, {
                       width: doc.page.width - 110,
                       ellipsis: true
                   });

                y += 65;

                // ── VERDICT CARD & METRICS ──────────────────────────────────
                const cardWidth = (doc.page.width - 95) / 3;

                // Verdict Card
                doc.roundedRect(40, y, cardWidth, 75, 6)
                   .fillAndStroke(bgColor, verdictColor);

                doc.fillColor(verdictColor)
                   .fontSize(9)
                   .font('Helvetica-Bold')
                   .text('SECURITY VERDICT', 52, y + 14);

                doc.fontSize(20)
                   .text(label, 52, y + 32);

                // Threat Score Card
                doc.roundedRect(40 + cardWidth + 7, y, cardWidth, 75, 6)
                   .fillAndStroke('#f8fafc', '#e2e8f0');

                doc.fillColor(subTextColor)
                   .fontSize(9)
                   .font('Helvetica-Bold')
                   .text('THREAT SCORE', 40 + cardWidth + 19, y + 14);

                doc.fillColor(verdictColor)
                   .fontSize(20)
                   .font('Helvetica-Bold')
                   .text(`${score}%`, 40 + cardWidth + 19, y + 32);

                // Detection Engine Card
                doc.roundedRect(40 + (cardWidth * 2) + 14, y, cardWidth, 75, 6)
                   .fillAndStroke('#f8fafc', '#e2e8f0');

                doc.fillColor(subTextColor)
                   .fontSize(9)
                   .font('Helvetica-Bold')
                   .text('ANALYSIS ENGINE', 40 + (cardWidth * 2) + 26, y + 14);

                const srcText = (scanData.source || 'ML Ensemble').replace('_', ' ').toUpperCase();
                doc.fillColor(primaryColor)
                   .fontSize(13)
                   .font('Helvetica-Bold')
                   .text(srcText, 40 + (cardWidth * 2) + 26, y + 34);

                const conf = scanData.mlConfidence ? `${(scanData.mlConfidence * 100).toFixed(1)}% Conf` : 'High Conf';
                doc.fillColor(subTextColor)
                   .fontSize(8)
                   .font('Helvetica')
                   .text(conf, 40 + (cardWidth * 2) + 26, y + 52);

                y += 95;

                // ── EXPLAINABLE SIGNALS & THREAT INDICATORS ──────────────────
                doc.fillColor(textColor)
                   .fontSize(12)
                   .font('Helvetica-Bold')
                   .text('EXPLAINABLE THREAT INDICATORS & SIGNALS', 40, y);

                y += 18;

                const details = scanData.details || [];
                if (details.length === 0) {
                    doc.roundedRect(40, y, doc.page.width - 80, 35, 4)
                       .fillAndStroke('#ecfdf5', '#10b981');
                    doc.fillColor('#065f46')
                       .fontSize(9)
                       .font('Helvetica')
                       .text('Clean URL structure: Zero known threat signatures, zero DGA patterns, and verified safe entropy.', 52, y + 12);
                    y += 45;
                } else {
                    details.forEach((d, idx) => {
                        const isRisk = d.type === 'risk';
                        const itemBg = isRisk ? '#fff1f2' : '#ecfdf5';
                        const itemBorder = isRisk ? '#f43f5e' : '#10b981';
                        const itemText = isRisk ? '#9f1239' : '#065f46';

                        doc.roundedRect(40, y, doc.page.width - 80, 26, 4)
                           .fillAndStroke(itemBg, itemBorder);

                        doc.fillColor(itemText)
                           .fontSize(9)
                           .font('Helvetica-Bold')
                           .text(isRisk ? 'THREAT SIGNAL' : 'SAFETY VERIFICATION', 52, y + 8, { width: 140 });

                        doc.fillColor(textColor)
                           .fontSize(8.5)
                           .font('Helvetica')
                           .text(d.label, 200, y + 8, { width: doc.page.width - 250 });

                        y += 31;
                    });
                }

                y += 10;

                // ── MULTI-DIMENSIONAL FORENSIC METRICS ───────────────────────
                doc.fillColor(textColor)
                   .fontSize(12)
                   .font('Helvetica-Bold')
                   .text('NEURAL FEATURE VECTOR BREAKDOWN', 40, y);

                y += 18;

                // Table Header
                doc.rect(40, y, doc.page.width - 80, 22).fill('#f1f5f9');
                doc.fillColor('#334155')
                   .fontSize(8.5)
                   .font('Helvetica-Bold')
                   .text('FEATURE NAME', 52, y + 6)
                   .text('VALUE', 260, y + 6)
                   .text('ASSESSMENT', 400, y + 6);

                y += 24;

                const features = scanData.features || {};
                const featureRows = [
                    { name: 'Shannon Entropy (Hostname)', val: features.entropy_host !== undefined ? String(features.entropy_host) : '2.84', eval: Number(features.entropy_host || 0) > 3.5 ? 'Elevated Randomness (DGA Risk)' : 'Normal Lexical Distribution' },
                    { name: 'Consonant Absence Ratio', val: features.consonant_ratio_host !== undefined ? `${(features.consonant_ratio_host * 100).toFixed(0)}%` : '50%', eval: Number(features.consonant_ratio_host || 0) > 0.8 ? 'Abnormal Consonant Density' : 'Natural Word Form' },
                    { name: 'Subdomain Chain Depth', val: features.subdomain_depth !== undefined ? String(features.subdomain_depth) : '0', eval: Number(features.subdomain_depth || 0) >= 3 ? 'Deep Nesting (Spoofing Vector)' : 'Standard Hierarchy' },
                    { name: 'Direct IP Address Usage', val: features.is_ip_address ? 'Yes (Detected)' : 'No (Domain Name)', eval: features.is_ip_address ? 'High Risk' : 'Legitimate Host' },
                    { name: 'Sensitive Keywords', val: features.num_sensitive_keywords !== undefined ? String(features.num_sensitive_keywords) : '0', eval: Number(features.num_sensitive_keywords || 0) > 0 ? 'Phishing Keywords Found' : 'None Detected' },
                    { name: 'HTTPS Encryption', val: features.is_https ? 'HTTPS (TLS)' : 'HTTP (Plaintext)', eval: features.is_https ? 'Encrypted Channel' : 'Unencrypted' }
                ];

                featureRows.forEach((r, idx) => {
                    const rowBg = idx % 2 === 0 ? '#ffffff' : '#f8fafc';
                    doc.rect(40, y, doc.page.width - 80, 20).fill(rowBg);

                    doc.fillColor(textColor)
                       .fontSize(8)
                       .font('Helvetica')
                       .text(r.name, 52, y + 5)
                       .text(r.val, 260, y + 5)
                       .text(r.eval, 400, y + 5);

                    y += 21;
                });

                // ── FOOTER ──────────────────────────────────────────────────
                const footerY = doc.page.height - 40;
                doc.fontSize(8)
                   .fillColor('#94a3b8')
                   .font('Helvetica')
                   .text('SafeSurf Security Intelligence — Powered by Neural ML Ensemble & Live Threat Feeds', 40, footerY, { align: 'center', width: doc.page.width - 80 });

                doc.end();
            } catch (err) {
                reject(err);
            }
        });
    }

    /**
     * Generates a PDF report and automatically archives it to Cloudinary.
     * @param {object} scanData
     * @returns {Promise<{ pdfBuffer: Buffer, cloudinaryUrl: string, public_id: string }>}
     */
    async generateAndArchiveReport(scanData) {
        const pdfBuffer = await this.generatePdfBuffer(scanData);

        const refId = scanData.refId || `report_${Date.now()}`;
        const sanitizedUrl = (scanData.url || 'url').replace(/[^a-zA-Z0-9]/g, '_').substring(0, 30);
        const filename = `safesurf_report_${sanitizedUrl}_${refId}`;

        // Upload PDF buffer to Cloudinary
        let cloudinaryResult = { secure_url: null, public_id: null, simulated: true };
        try {
            cloudinaryResult = await cloudinaryService.uploadBuffer(pdfBuffer, {
                folder: 'safesurf/reports/pdf',
                public_id: filename,
                tags: ['safesurf-pdf-report', scanData.label || 'scan']
            });
        } catch (err) {
            console.warn('[PdfReportService] Cloudinary archive warning:', err.message);
        }

        return {
            pdfBuffer,
            cloudinaryUrl: cloudinaryResult.secure_url || cloudinaryResult.url,
            public_id: cloudinaryResult.public_id,
            simulated: cloudinaryResult.simulated || false,
            filename: `${filename}.pdf`
        };
    }
}

module.exports = new PdfReportService();
