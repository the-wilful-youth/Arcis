// Arcis Phishing Shield Background Service Worker

// Active tab analysis cache to avoid redundant hits
const scanCache = {};

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only trigger when URL is updated and fully loaded
    if (changeInfo.url && (changeInfo.url.startsWith('http://') || changeInfo.url.startsWith('https://'))) {
        const url = changeInfo.url;
        
        // Skip if already in cache
        if (scanCache[url]) {
            updateBadge(tabId, scanCache[url]);
            return;
        }

        // Run background scan
        fetch('http://127.0.0.1:5001/api/analyze/url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        })
        .then(response => {
            if (!response.ok) throw new Error('API Error');
            return response.json();
        })
        .then(data => {
            const risk = data.risk_score_pct;
            scanCache[url] = risk;
            updateBadge(tabId, risk);
        })
        .catch(err => {
            console.error('Background Scan failed:', err);
            // On error, clear badge
            chrome.action.setBadgeText({ tabId: tabId, text: '' });
        });
    }
});

function updateBadge(tabId, riskScore) {
    if (riskScore < 30) {
        // Safe: clear badge
        chrome.action.setBadgeText({ tabId: tabId, text: '' });
    } else if (riskScore < 70) {
        // Suspicious
        chrome.action.setBadgeText({ tabId: tabId, text: 'WARN' });
        chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: '#f59e0b' });
    } else {
        // Dangerous
        chrome.action.setBadgeText({ tabId: tabId, text: 'BAD' });
        chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: '#ef4444' });
    }
}

// Message listener to handle privileged fetch requests bypassing Gmail CSP
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'analyze_email') {
        // 1. Analyze the email sender/headers
        const emailPromise = fetch('http://127.0.0.1:5001/api/analyze/email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request.data)
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => {
                    throw new Error(err.detail || 'API Error');
                });
            }
            return response.json();
        });

        // 2. Scan all extracted embedded links in parallel
        const linkPromises = (request.links || []).map(url => {
            return fetch('http://127.0.0.1:5001/api/analyze/url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            })
            .then(res => {
                if (!res.ok) throw new Error('URL API Error');
                return res.json();
            })
            .then(data => ({ url: url, data: data }))
            .catch(err => ({ url: url, error: err.message }));
        });

        Promise.all([emailPromise, Promise.all(linkPromises)])
        .then(([emailResult, linkResults]) => {
            let highestLinkRisk = 0;
            const flaggedLinks = [];

            linkResults.forEach(res => {
                if (res.data) {
                    const risk = res.data.risk_score_pct || 0;
                    if (risk > highestLinkRisk) {
                        highestLinkRisk = risk;
                    }
                    if (res.data.is_phishing || risk >= 50) {
                        flaggedLinks.push({ url: res.url, risk: risk, brand: res.data.brand_alert });
                    }
                }
            });

            // If a link in the email is more dangerous than the sender, elevate the overall threat level
            if (highestLinkRisk > emailResult.risk_score_pct) {
                emailResult.risk_score_pct = highestLinkRisk;
                emailResult.is_phishing = emailResult.risk_score_pct >= 50;
            }

            // Append CC addresses to reasons list
            if (request.cc && request.cc.length > 0) {
                emailResult.details.reasons.push(`CC: ${request.cc.join(', ')}`);
            }

            // Append link results to findings
            if (flaggedLinks.length > 0) {
                flaggedLinks.forEach(fl => {
                    let msg = `🚨 Dangerous Link: ${fl.url.substring(0, 35)}... (Risk: ${fl.risk.toFixed(0)}%)`;
                    if (fl.brand && fl.brand.impersonated) {
                        msg += ` imitating ${fl.brand.brand.toUpperCase()}`;
                    }
                    emailResult.details.reasons.push(msg);
                });
            } else if (request.links && request.links.length > 0) {
                emailResult.details.reasons.push(`Checked ${request.links.length} embedded link(s) — all links are clean.`);
            }

            sendResponse({ success: true, data: emailResult });
        })
        .catch(err => {
            console.error('Background Email & Link Scan failed:', err);
            sendResponse({ success: false, error: err.message });
        });
        return true; // Keep message channel open for async response
    }
});

