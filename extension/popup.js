document.addEventListener('DOMContentLoaded', async () => {
    // Tab switching elements
    const tabButtons = document.querySelectorAll('.p-tab');
    const tabPanes = document.querySelectorAll('.p-pane');

    // Load backend URL configuration and API Key
    let backendUrl = 'https://arcis-dvgq.onrender.com';
    let apiKey = '';
    const settingsUrlInput = document.getElementById('settings-backend-url');
    const settingsKeyInput = document.getElementById('settings-api-key');
    const settingsSaveBtn = document.getElementById('settings-save-btn');
    const settingsStatus = document.getElementById('settings-status');
    const launchDashboardLink = document.getElementById('launch-dashboard-link');

    function isValidUrl(string) {
        try {
            const url = new URL(string);
            return url.protocol === 'http:' || url.protocol === 'https:';
        } catch (_) {
            return false;
        }
    }

    function showSettingsStatus(msg, color) {
        if (settingsStatus) {
            settingsStatus.textContent = msg;
            settingsStatus.style.color = color;
            settingsStatus.style.display = 'block';
            setTimeout(() => {
                settingsStatus.style.display = 'none';
            }, 3000);
        }
    }

    try {
        const stored = await chrome.storage.local.get(['backend_url', 'api_key']);
        if (stored.backend_url) {
            backendUrl = stored.backend_url;
        }
        if (stored.api_key) {
            apiKey = stored.api_key;
        }
    } catch (e) {
        console.error(e);
    }

    if (settingsUrlInput) {
        settingsUrlInput.value = backendUrl;
    }
    if (settingsKeyInput) {
        settingsKeyInput.value = apiKey;
    }
    if (launchDashboardLink) {
        launchDashboardLink.href = backendUrl;
    }

    if (settingsSaveBtn && settingsUrlInput && settingsKeyInput) {
        settingsSaveBtn.addEventListener('click', async () => {
            const urlVal = settingsUrlInput.value.trim().replace(/\/$/, '');
            const keyVal = settingsKeyInput.value.trim();
            
            if (!isValidUrl(urlVal)) {
                showSettingsStatus('Error: Invalid API Endpoint URL. Must be http:// or https://', '#ef4444');
                return;
            }
            
            backendUrl = urlVal;
            apiKey = keyVal;
            await chrome.storage.local.set({ backend_url: urlVal, api_key: keyVal });
            if (launchDashboardLink) {
                launchDashboardLink.href = urlVal;
            }
            showSettingsStatus('Settings saved successfully!', '#ABD1C6');
        });
    }

    // URL Scanner elements
    const activeUrlEl = document.getElementById('active-url');
    const scanBtn = document.getElementById('scan-btn');
    const loadingState = document.getElementById('loading-state');
    const resultState = document.getElementById('result-state');
    const riskScoreEl = document.getElementById('risk-score');
    const statusAlertEl = document.getElementById('status-alert');
    const findingsList = document.getElementById('findings-list');

    // Email Scanner elements
    const emailForm = document.getElementById('email-form');
    const emailScanBtn = document.getElementById('email-scan-btn');
    const emailLoadingState = document.getElementById('email-loading-state');
    const emailResultState = document.getElementById('email-result-state');
    const emailRiskScoreEl = document.getElementById('email-risk-score');
    const emailStatusAlertEl = document.getElementById('email-status-alert');
    const emailFindingsList = document.getElementById('email-findings-list');

    let currentTabUrl = '';

    // --- 1. Tab Switching Logic ---
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            tabButtons.forEach(b => b.classList.remove('p-tab--active'));
            tabPanes.forEach(p => p.classList.add('hidden'));

            btn.classList.add('p-tab--active');
            const targetPane = document.getElementById(btn.dataset.tab);
            if (targetPane) {
                targetPane.classList.remove('hidden');
            }
        });
    });

    // --- 2. URL Scanner: Get active tab URL ---
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
            currentTabUrl = tab.url;
            activeUrlEl.textContent = currentTabUrl;
            
            // Pre-populate email sender input if visiting a mailto link
            if (currentTabUrl.startsWith('mailto:')) {
                const mailAddr = currentTabUrl.replace('mailto:', '').split('?')[0];
                document.getElementById('email-sender').value = mailAddr;
            }
        } else {
            activeUrlEl.textContent = "Unable to read active tab URL.";
            scanBtn.disabled = true;
        }
    } catch (e) {
        console.error(e);
        activeUrlEl.textContent = "Error reading active URL.";
        scanBtn.disabled = true;
    }

    // --- 3. URL Scanner: Run Scan ---
    scanBtn.addEventListener('click', async () => {
        if (!currentTabUrl) return;

        if (!apiKey) {
            findingsList.innerHTML = `<li style="color: #ef4444; font-weight: 600;">Configuration Required: Please set your API Key in the Settings tab to authenticate requests.</li>`;
            riskScoreEl.textContent = 'N/A';
            statusAlertEl.textContent = 'CONFIG ERROR';
            statusAlertEl.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
            statusAlertEl.style.color = '#ef4444';
            resultState.classList.remove('hidden');
            return;
        }

        scanBtn.disabled = true;
        loadingState.classList.remove('hidden');
        resultState.classList.add('hidden');

        try {
            const response = await fetch(`${backendUrl}/api/analyze/url`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': apiKey
                },
                body: JSON.stringify({ url: currentTabUrl })
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || 'Scan failed.');
            }

            const data = await response.json();
            
            // Render Result
            const riskVal = data.risk_score_pct;
            riskScoreEl.textContent = `${riskVal}%`;

            if (riskVal < 30) {
                statusAlertEl.textContent = 'SAFE LINK';
                statusAlertEl.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
                statusAlertEl.style.color = '#10b981';
                riskScoreEl.style.color = '#10b981';
            } else if (riskVal < 50) {
                statusAlertEl.textContent = 'SUSPICIOUS LINK';
                statusAlertEl.style.backgroundColor = 'rgba(245, 158, 11, 0.15)';
                statusAlertEl.style.color = '#f59e0b';
                riskScoreEl.style.color = '#f59e0b';
            } else {
                statusAlertEl.textContent = 'DANGEROUS LINK';
                statusAlertEl.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
                statusAlertEl.style.color = '#ef4444';
                riskScoreEl.style.color = '#ef4444';
            }

            findingsList.innerHTML = '';
            
            if (data.brand_alert && data.brand_alert.impersonated) {
                const brandLi = document.createElement('li');
                brandLi.style.color = '#ef4444';
                brandLi.style.fontWeight = '700';
                brandLi.textContent = `🚨 Brand Impersonation: Imitating "${data.brand_alert.brand.toUpperCase()}" (${data.brand_alert.type})`;
                findingsList.appendChild(brandLi);
            }

            /* Friendly feature name helper */
            function getFriendlyFeatureName(key) {
                const customNames = {
                    time_domain_activation: 'Domain Registration Age',
                    time_domain_expiration: 'Domain Expiry Window',
                    qty_ip_resolved:        'Resolved IP Addresses',
                    time_response:          'Server Response Time',
                    length_url:             'URL Length',
                    domain_length:          'Domain Name Length',
                    directory_length:       'Directory Path Length',
                    file_length:            'File Name Length',
                    params_length:          'Query Parameters Length',
                    ttl_hostname:           'DNS Time-to-Live (TTL)',
                    asn_ip:                 'Network Provider (ASN)',
                    qty_nameservers:        'Nameservers Count',
                    qty_mx_servers:         'Mail Servers Count',
                    qty_vowels_domain:      'Vowel Count in Domain',
                    tld_present_params:     'Domain Extensions in Parameters'
                };

                if (customNames[key]) {
                    return customNames[key];
                }

                if (key.startsWith('qty_')) {
                    const parts = key.split('_');
                    if (parts.length >= 3) {
                        const charMap = {
                            dot: 'dot (.)',
                            slash: 'slash (/)',
                            hyphen: 'hyphen (-)',
                            underline: 'underscore (_)',
                            at: 'at symbol (@)',
                            questionmark: 'question mark (?)',
                            equal: 'equal sign (=)',
                            and: 'ampersand (&)',
                            exclamation: 'exclamation mark (!)',
                            space: 'space',
                            tilde: 'tilde (~)',
                            comma: 'comma (,)',
                            plus: 'plus sign (+)',
                            asterisk: 'asterisk (*)',
                            hashtag: 'hashtag (#)',
                            dollar: 'dollar sign ($)',
                            percent: 'percent sign (%)'
                        };

                        const locMap = {
                            directory: 'directory path',
                            file: 'file name',
                            url: 'URL',
                            domain: 'domain name',
                            params: 'query parameters'
                        };

                        const charName = charMap[parts[1]] || parts[1];
                        const locName = locMap[parts[2]] || parts[2];
                        return `Count of "${charName}" in ${locName}`;
                    }
                }

                return key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
            }

            data.top_features.forEach(indicator => {
                const li = document.createElement('li');
                const val = indicator.value;
                const feat = indicator.feature;
                
                let desc = '';
                if (feat === 'time_domain_activation') {
                    desc = val < 0 ? 'Domain registration age cannot be verified.' : `Domain registered ${Math.round(val)} days ago.`;
                } else if (feat === 'qty_ip_resolved') {
                    desc = val <= 0 ? 'Fails to resolve to any IP address.' : `Resolves to ${Math.round(val)} active IP(s).`;
                } else if (feat === 'time_response') {
                    desc = val < 0 ? 'Web server connection timed out.' : `Server connection is responsive.`;
                } else if (feat === 'length_url') {
                    desc = `URL length is ${Math.round(val)} characters.`;
                } else if (feat.startsWith('qty_slash_')) {
                    desc = `Contains ${Math.round(val)} slash character(s).`;
                } else {
                    const friendlyName = getFriendlyFeatureName(feat);
                    desc = `${friendlyName}: ${val} (${indicator.direction === 'increases' ? 'increases' : 'decreases'} risk)`;
                }

                li.textContent = desc;
                findingsList.appendChild(li);
            });

            resultState.classList.remove('hidden');

        } catch (error) {
            console.error(error);
            findingsList.innerHTML = `<li style="color: #ef4444; font-weight: 600;">Error: Unable to contact scan backend at ${backendUrl}. Ensure API node is running and configured correctly.</li>`;
            riskScoreEl.textContent = 'N/A';
            statusAlertEl.textContent = 'SCAN FAILED';
            statusAlertEl.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
            statusAlertEl.style.color = '#ef4444';
            resultState.classList.remove('hidden');
        } finally {
            loadingState.classList.add('hidden');
            scanBtn.disabled = false;
        }
    });

    // --- 4. Email Scanner: Run Scan ---
    emailForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (!apiKey) {
            emailFindingsList.innerHTML = `<li style="color: #ef4444; font-weight: 600;">Configuration Required: Please set your API Key in the Settings tab to authenticate requests.</li>`;
            emailRiskScoreEl.textContent = 'N/A';
            emailStatusAlertEl.textContent = 'CONFIG ERROR';
            emailStatusAlertEl.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
            emailStatusAlertEl.style.color = '#ef4444';
            emailResultState.classList.remove('hidden');
            return;
        }

        const sender = document.getElementById('email-sender').value.trim();
        const subject = document.getElementById('email-subject').value.trim();
        const body = document.getElementById('email-body').value.trim();
        const spf = document.getElementById('email-spf').value;
        const dkim = document.getElementById('email-dkim').value;
        const dmarc = document.getElementById('email-dmarc').value;

        emailScanBtn.disabled = true;
        emailLoadingState.classList.remove('hidden');
        emailResultState.classList.add('hidden');

        try {
            const response = await fetch(`${backendUrl}/api/analyze/email`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': apiKey
                },
                body: JSON.stringify({
                    email: sender,
                    subject: subject,
                    body: body,
                    spf: spf,
                    dkim: dkim,
                    dmarc: dmarc
                })
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || 'Email scan failed.');
            }

            const data = await response.json();
            
            // Render Result
            const riskVal = data.risk_score_pct;
            emailRiskScoreEl.textContent = `${riskVal}%`;

            if (riskVal < 30) {
                emailStatusAlertEl.textContent = 'SAFE SENDER';
                emailStatusAlertEl.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
                emailStatusAlertEl.style.color = '#10b981';
                emailRiskScoreEl.style.color = '#10b981';
            } else if (riskVal < 50) {
                emailStatusAlertEl.textContent = 'SUSPICIOUS SENDER';
                emailStatusAlertEl.style.backgroundColor = 'rgba(245, 158, 11, 0.15)';
                emailStatusAlertEl.style.color = '#f59e0b';
                emailRiskScoreEl.style.color = '#f59e0b';
            } else {
                emailStatusAlertEl.textContent = 'DANGEROUS SENDER';
                emailStatusAlertEl.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
                emailStatusAlertEl.style.color = '#ef4444';
                emailRiskScoreEl.style.color = '#ef4444';
            }

            emailFindingsList.innerHTML = '';
            
            // List reasons/signals
            const reasons = data.details.reasons || [];
            reasons.forEach(reason => {
                const li = document.createElement('li');
                li.textContent = reason;
                emailFindingsList.appendChild(li);
            });

            emailResultState.classList.remove('hidden');

        } catch (error) {
            console.error(error);
            emailFindingsList.innerHTML = `<li style="color: #ef4444; font-weight: 600;">Error: Unable to contact scan backend at ${backendUrl}. Ensure API node is running and configured correctly.</li>`;
            emailRiskScoreEl.textContent = 'N/A';
            emailStatusAlertEl.textContent = 'SCAN FAILED';
            emailStatusAlertEl.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
            emailStatusAlertEl.style.color = '#ef4444';
            emailResultState.classList.remove('hidden');
        } finally {
            emailLoadingState.classList.add('hidden');
            emailScanBtn.disabled = false;
        }
    });
});
