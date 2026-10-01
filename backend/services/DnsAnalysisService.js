'use strict';

const dns = require('dns').promises;

/**
 * Live Network Heuristics Service
 * Uses native DNS lookups to detect Fast-Flux botnets and dead domains.
 */
class DnsAnalysisService {
    /**
     * Analyze a hostname for network-level threats.
     * @param {string} hostname
     * @returns {Promise<{ isDead: boolean, isFastFlux: boolean, ipCount: number, error: string|null }>}
     */
    static async checkHostname(hostname) {
        if (!hostname || typeof hostname !== 'string') {
            return { isDead: false, isFastFlux: false, ipCount: 0, error: null };
        }

        try {
            // Resolve A records (IPv4 addresses)
            const addresses = await dns.resolve4(hostname);
            const ipCount = addresses.length;

            // Fast-Flux heuristic: > 3 distinct IPs rapidly shifting behind a single domain
            // is highly suspicious and common in botnets.
            const isFastFlux = ipCount > 3;

            return {
                isDead: false,
                isFastFlux,
                ipCount,
                error: null
            };
        } catch (err) {
            if (err.code === 'ENOTFOUND' || err.code === 'SERVFAIL') {
                return {
                    isDead: true,
                    isFastFlux: false,
                    ipCount: 0,
                    error: err.code
                };
            }
            return { isDead: false, isFastFlux: false, ipCount: 0, error: err.code };
        }
    }
}

module.exports = DnsAnalysisService;
