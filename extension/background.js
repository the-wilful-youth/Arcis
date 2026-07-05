// Arcis Phishing Shield Background Service Worker

// Active tab analysis cache to avoid redundant hits
const scanCache = {};
const scanCacheKeys = [];

function setCache(url, risk) {
    if (scanCacheKeys.length >= 500) {
        const oldest = scanCacheKeys.shift();
        delete scanCache[oldest];
    }
    if (!(url in scanCache)) {
        scanCacheKeys.push(url);
    }
    scanCache[url] = risk;
}

async function getCredentials() {
    try {
        const stored = await chrome.storage.local.get(['backend_url', 'api_key']);
        return {
            backendUrl: stored.backend_url || 'https://arcis-dvgq.onrender.com',
            apiKey: stored.api_key || ''
        };
    } catch (e) {
        return {
            backendUrl: 'https://arcis-dvgq.onrender.com',
            apiKey: ''
        };
    }
}

function isValidUrl(string) {
    try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
        return false;
    }
}

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
    if (request.action === 'get_backend_url') {
        getCredentials().then(creds => sendResponse({ url: creds.backendUrl }));
        return true;
    }

    if (request.action === 'analyze_email') {
        getCredentials().then(async (creds) => {
            if (!isValidUrl(creds.backendUrl)) {
                sendResponse({ error: 'Invalid API Endpoint URL configured.' });
                return;
            }

            // 1. Analyze the email sender/headers
            const emailPromise = fetch(`${creds.backendUrl}/api/analyze/email`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': creds.apiKey
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
                return fetch(`${creds.backendUrl}/api/analyze/url`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-API-Key': creds.apiKey
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

                // Map link results to a list for the report page
                const scannedLinksList = linkResults.map(res => {
                    return {
                        url: res.url,
                        resolved_url: res.data ? (res.data.resolved_url || res.url) : res.url,
                        risk: res.data ? (res.data.risk_score_pct || 0) : 0,
                        is_phishing: res.data ? (res.data.is_phishing || false) : false
                    };
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

                emailResult.scanned_links = scannedLinksList;

                // Build report payload to POST to the database
                const reportPayload = {
                    subject: request.data.subject || '',
                    sender: request.data.email || '',
                    body: request.data.body || '',
                    cc: request.cc || [],
                    risk_score_pct: emailResult.risk_score_pct,
                    reasons: emailResult.details.reasons || [],
                    links: scannedLinksList
                };

                return fetch(`${creds.backendUrl}/api/report`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-API-Key': creds.apiKey
                    },
                    body: JSON.stringify(reportPayload)
                })
                .then(res => {
                    if (!res.ok) throw new Error('Report API Error');
                    return res.json();
                })
                .then(repData => {
                    emailResult.report_id = repData.report_id;
                    sendResponse({ success: true, data: emailResult });
                })
                .catch(err => {
                    console.error('Report submission failed:', err);
                    sendResponse({ success: true, data: emailResult });
                });
            })
            .catch(err => {
                console.error('Background Email & Link Scan failed:', err);
                sendResponse({ success: false, error: err.message });
            });
        });
        return true; // Keep message channel open for async response
    }
});

