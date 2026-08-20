// Background Service Worker
let blacklistSet = new Set();
let cache = {};

// Load Optimized Dataset
fetch(chrome.runtime.getURL("dataset.json"))
    .then(res => res.json())
    .then(data => {
        blacklistSet = new Set(data.blacklist);
        console.log(`🛡️ SafeSurf: Loaded Intel Dataset v${data.version} (${data.blacklist.length} domains)`);
    })
    .catch(err => console.error("Failed to load dataset:", err));

// 1. Real-Time URL Scanner Logic
function normalizeURL(url) {
    try {
        const parsed = new URL(url);
        return parsed.hostname.toLowerCase();
    } catch (err) {
        return null;
    }
}

function checkBlacklist(url) {
    const domain = normalizeURL(url);
    if (!domain) return { safe: false, reason: "Invalid URL" };

    if (cache[domain]) {
        return cache[domain];
    }

    if (blacklistSet.has(domain)) {
        cache[domain] = { safe: false, reason: "Blacklisted domain" };
        return cache[domain];
    }

    cache[domain] = { safe: true };
    return cache[domain];
}

// 2. Heuristic Phishing Detection (Enhanced Local Engine)
const trustedDomains = ["google.com", "github.com", "microsoft.com", "amazon.com", "facebook.com", "youtube.com", "twitter.com", "linkedin.com", "wikipedia.org", "reddit.com", "apple.com", "paypal.com"];
const suspiciousKeywords = ['login', 'verify', 'account', 'secure', 'update', 'bank', 'wallet', 'signin'];
const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.link', '.online'];

function evaluateURL(url) {
    let score = 0;
    let reasons = [];

    try {
        const parsed = new URL(url.startsWith('http') ? url : 'http://' + url);
        const hostname = parsed.hostname.toLowerCase();
        const fullURL = url.toLowerCase();

        // 🟢 Whitelist Check
        if (trustedDomains.some(d => hostname === d || hostname.endsWith("." + d))) {
            return { block: false, score: 0, reasons: ["Verified Official Domain"] };
        }

        // 🔴 HIGH RISK
        // Brand Impersonation check
        const brands = ['google', 'apple', 'icloud', 'microsoft', 'paypal', 'amazon', 'facebook', 'instagram', 'binance'];
        const isImpersonation = brands.some(brand => hostname.includes(brand) && !hostname.endsWith(brand + '.com') && !hostname.endsWith(brand + '.net'));
        if (isImpersonation) {
            score += 65;
            reasons.push("Potential Brand Impersonation");
        }

        if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
            score += 60;
            reasons.push("Raw IP address used");
        }

        // 🟠 MEDIUM RISK
        if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
            score += 30;
            reasons.push("Low-reputation domain suffix (TLD)");
        }

        const foundKws = suspiciousKeywords.filter(kw => fullURL.includes(kw));
        if (foundKws.length > 0) {
            score += Math.min(foundKws.length * 20, 40);
            reasons.push(`Suspicious keywords: ${foundKws.join(", ")}`);
        }

        if (hostname.split('.').length > 4) {
            score += 15;
            reasons.push("Excessive subdomains");
        }

        if (hostname.includes('-') && hostname.length > 20) {
            score += 10;
            reasons.push("Abnormal use of dashes in domain");
        }

        // 🟢 SAFETY
        if (url.startsWith('https')) {
            score -= 15;
        } else {
            score += 20;
            reasons.push("Unsecured connection");
        }

    } catch (e) {
        return { block: false, score: 0, reasons: [] };
    }

    // Blacklist check (Static)
    const blacklistResult = checkBlacklist(url);
    if (!blacklistResult.safe) {
        score = Math.max(score, 85);
        reasons.unshift("Known Malicious Domain (Local Intel)");
    }

    // Clamp score
    if (score < 0) score = 0;
    if (score > 100) score = 100;

    if (reasons.length === 0 && score === 0) {
        reasons.push("Verified Safe Domain Structure");
    }

    return {
        block: score >= 60,
        score,
        reasons: reasons.slice(0, 3) // Top 3 reasons
    };
}

// 4. Redirect Chain Tracking
chrome.webRequest.onBeforeRedirect.addListener(
    function (details) {
        console.log("Redirect detected to:", details.redirectUrl);
        const result = evaluateURL(details.redirectUrl);

        if (result.block) {
            console.warn("Blocked due to redirect risk:", result.reasons.join(", "));
            // Notify user about redirect risk
            showNotification('critical', details.redirectUrl, `Dangerous Redirect Blocked: ${result.reasons[0]}`);
        }
    },
    { urls: ["<all_urls>"] }
);

// Handle messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "evaluateURL") {
        const result = evaluateURL(request.url);
        sendResponse(result);
    }
    return true; // Keep channel open for async response
});


// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only check when loading is complete and we have a valid HTTP/HTTPS URL
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        // Run local evaluation first
        const localResult = evaluateURL(tab.url);
        let status = 'safe';
        if (localResult.score >= 60) {
            status = 'critical';
        } else if (localResult.score >= 35) {
            status = 'suspicious';
        }

        // Always store initial local evaluation immediately
        updateUI(tabId, status, tab.url, localResult);

        // Perform backend check asynchronously for deeper intelligence
        checkBackendURL(tab.url, tabId);
    }
});

// Helper to update UI based on assessment
function updateUI(tabId, status, url, data) {
    updateIcon(tabId, status);
    if (status !== 'safe') {
        const message = status === 'critical' ? 'CRITICAL THREAT DETECTED! ⚠️' : 'Suspicious Activity Detected ⚠️';
        showNotification(status, url, message);
    }

    // Standardize reasons array for extension popup & content overlay
    let reasons = data.reasons;
    if (!reasons || reasons.length === 0) {
        if (data.details && data.details.length > 0) {
            reasons = data.details.filter(d => d.type === 'risk').map(d => d.label);
        }
    }
    if (!reasons || reasons.length === 0) {
        reasons = status === 'safe' ? ["Verified Secure Domain"] : ["Suspicious Structural Vector"];
    }

    const payload = { ...data, url, status, reasons };

    // Trigger in-page overlay for critical AND suspicious threats (Active Intervention)
    if (status === 'critical' || status === 'suspicious') {
        chrome.tabs.sendMessage(tabId, {
            action: 'SHOW_WARNING',
            data: {
                reasons: reasons,
                score: data.score
            }
        }).catch(err => console.log("Overlay injection failed (content script not ready):", err));
    }

    chrome.storage.local.set({ [tabId.toString()]: payload });
}

// Function to check URL against backend API
async function checkBackendURL(url, tabId) {
    try {
        const response = await fetch('http://localhost:5000/api/check-url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            console.warn('Backend check failed with status:', response.status);
            return;
        }

        const data = await response.json();
        const score = data.score || 0;

        let status = 'safe';
        if (score >= 60) {
            status = 'critical';
        } else if (score >= 35) {
            status = 'suspicious';
        }

        const reasons = (data.details && data.details.length > 0)
            ? data.details.filter(d => d.type === 'risk').map(d => d.label)
            : (data.reasons || ["Verified Secure Domain"]);

        updateUI(tabId, status, url, { ...data, score, reasons });

    } catch (error) {
        console.warn('Backend connection error - relying on local heuristics');
    }
}

// Update Extension Icon Badge/Color
function updateIcon(tabId, status) {
    let color = '#00d9ff'; // Safe blue
    let text = '';

    if (status === 'critical') {
        color = '#ff3b3b';
        text = '!';
    } else if (status === 'suspicious') {
        color = '#ffa500'; // Orange
        text = '?';
    }

    // Set badge text
    chrome.action.setBadgeText({ text: text, tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
}

// Show Desktop Notification
function showNotification(type, url, message) {
    const iconUrl = type === 'critical' ? 'icons/icon128.png' : 'icons/icon48.png';

    chrome.notifications.create({
        type: 'basic',
        iconUrl: iconUrl, // Ensure these icons exist in your extension folder!
        title: 'SafeSurf Alert',
        message: `${message}\n${new URL(url).hostname}`,
        priority: 2,
        buttons: [
            { title: 'Scan Details' },
            { title: 'Close' }
        ]
    });
}

// Handle Notification Button Clicks
chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    if (buttonIndex === 0) {
        // User clicked "Scan Details" - Open Popup... wait, we cannot programmatic open popup.
        // We can open a full dashboard page instead.
        // chrome.tabs.create({ url: 'popup.html' }); // Use full page version if available
    }
});
